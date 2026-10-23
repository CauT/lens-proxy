"""RequestData persistence semantics which a displayed HAR URL cannot carry."""
import base64
import copy
import unittest
from unittest.mock import patch

from mitmproxy import http

from bounds import METADATA_BYTES, metadata_size
from har_request import export_request_facts, request_facts_metadata_size, restore_legacy_request, restore_request_facts
from http_method import request_method
from http_urls import request_url
from outgoing import request_fingerprint


def captured(**changes):
    fields = dict(host='127.0.0.1', port=8123, method=b'GET', scheme=b'http',
                  authority=b'', path=b'/path?q=1', http_version=b'HTTP/1.1',
                  headers=http.Headers([(b'Host', b'shown.test:8443'), (b'X-Raw', b'\xff'),
                                        (b'X-Duplicate', b'one'), (b'X-Duplicate', b'two')]),
                  content=b'', trailers=None, timestamp_start=1.25, timestamp_end=None)
    fields.update(changes)
    return http.Request(**fields)


def standard(request):
    return {'method': request_method(request), 'url': request_url(request, pretty=True),
            'httpVersion': request.http_version}


class HARRequestFacts(unittest.TestCase):
    def assert_roundtrip(self, request):
        facts = export_request_facts(request)
        headers = http.Headers(request.headers.fields)
        restored = restore_request_facts(facts, standard(request), headers, request.timestamp_start)
        self.assertEqual(restored.get_state(), request.get_state())
        self.assertEqual(request_fingerprint(restored), request_fingerprint(request))
        self.assertEqual(export_request_facts(restored), facts)
        self.assertIs(restored.headers, headers)
        self.assertEqual(restored.metadata if hasattr(restored, 'metadata') else None, None)
        return restored

    def test_non_utf8_and_case_sensitive_method_path_scheme_and_version_are_observed_bytes(self):
        for changes in ({'method': b'gEt', 'path': b'/raw\xff?q=\xfe'},
                        {'method': b'G\xffT', 'scheme': b'h\xfftp', 'http_version': b'HTTP/\xff'},
                        {'method': b'', 'scheme': b'', 'authority': b'', 'path': b''}):
            with self.subTest(changes=changes):
                self.assert_roundtrip(captured(**changes))

    def test_route_and_port_stay_separate_from_displayed_host(self):
        request = captured()
        self.assertEqual(standard(request)['url'], 'http://shown.test:8443/path?q=1')
        restored = self.assert_roundtrip(request)
        self.assertEqual((restored.host, restored.port), ('127.0.0.1', 8123))
        self.assertEqual(request_url(restored), 'http://127.0.0.1:8123/path?q=1')

    def test_asterisk_origin_and_absolute_forms_keep_sdk_representation(self):
        for changes in ({'method': b'OPTIONS', 'path': b'*'},
                        {'authority': b'absolute.test:8090'}, {'path': b'/'},
                        {'path': b''}):
            with self.subTest(changes=changes):
                restored = self.assert_roundtrip(captured(**changes))
                self.assertEqual(restored.data.path, changes.get('path', b'/path?q=1'))

    def test_connect_authority_and_zero_unknown_port_are_inspectable(self):
        request = captured(method=b'CONNECT', scheme=b'', authority=b'tunnel.test:443', path=b'')
        self.assertEqual(standard(request)['url'], 'tunnel.test:443')
        self.assert_roundtrip(request)
        self.assert_roundtrip(captured(host='', port=0, headers=http.Headers()))

    def test_http2_idna_and_raw_authority_keep_routed_host_and_pseudo_header_distinct(self):
        for authority in (b'xn--bcher-kva.test:8443', b'raw\xff.test:8443'):
            with self.subTest(authority=authority):
                request = captured(http_version=b'HTTP/2.0', scheme=b'https', authority=authority,
                                   headers=http.Headers([(b'x-source', b'value')]))
                restored = self.assert_roundtrip(request)
                self.assertEqual(restored.data.authority, authority)
                self.assertEqual((restored.host, restored.port), ('127.0.0.1', 8123))

    def test_large_source_path_bypasses_editing_limit_within_metadata_budget(self):
        request = captured(path=b'/' + b'\xff' * (64 * 1024 + 7))
        self.assertGreater(len(request.data.path), 64 * 1024)
        self.assertLess(metadata_size(export_request_facts(request), METADATA_BYTES), METADATA_BYTES)
        self.assert_roundtrip(request)

    def test_optional_http_version_omission_does_not_invent_a_default(self):
        request = captured(http_version=b'HTTP/2.0', authority=b'shown.test:8443')
        source = standard(request)
        del source['httpVersion']
        restored = restore_request_facts(export_request_facts(request), source, request.headers, 1.25)
        self.assertEqual(restored.data.http_version, b'HTTP/2.0')

    def test_invalid_shape_version_route_and_base64_reject_before_decode(self):
        facts = export_request_facts(captured())
        invalid = [None, [], {**facts, 'unknown': 1}, {k: v for k, v in facts.items() if k != 'path_base64'}]
        for key, values in (('version', (True, 0, 2, '1')), ('host', (None, b'host', 1)),
                            ('port', (True, False, -1, 65536, 80.0, '80')),
                            ('http_version_base64', ('/x==', '//9=', '@@@@', 'AAA', None, 4))):
            invalid.extend({**facts, key: value} for value in values)
        for value in invalid:
            with self.subTest(value=value), patch('har_request.decode_base64', side_effect=AssertionError('must preflight')):
                with self.assertRaises(ValueError):
                    restore_request_facts(value, standard(captured()), http.Headers(), 1.25)

    def test_complete_metadata_expansion_is_admitted_before_any_decode(self):
        facts = export_request_facts(captured())
        facts['path_base64'] = base64.b64encode(b'/' + b'x' * 700).decode('ascii')
        with patch('har_request.METADATA_BYTES', 1024), patch('har_request.decode_base64', side_effect=AssertionError('must preflight')):
            with self.assertRaisesRegex(ValueError, 'budget'):
                restore_request_facts(facts, standard(captured()), http.Headers(), 1.25)
        facts = export_request_facts(captured())
        facts['host'] = '\u754c' * 400
        with patch('har_request.METADATA_BYTES', 1024), patch('har_request.decode_base64', side_effect=AssertionError('must preflight')):
            with self.assertRaisesRegex(ValueError, 'budget'):
                restore_request_facts(facts, standard(captured()), http.Headers(), 1.25)

    def test_export_measures_base64_expansion_before_any_encoding(self):
        request = captured(path=b'/' + b'x' * 700)
        with patch('har_request.METADATA_BYTES', 1024), patch('har_request.base64.b64encode', side_effect=AssertionError('must preflight')):
            with self.assertRaisesRegex(ValueError, 'budget'):
                export_request_facts(request)

    def test_retention_measurement_equals_archive_logical_size_without_base64_allocation(self):
        request = captured(path=b'/' + b'\xff' * 70000)
        expected = metadata_size(export_request_facts(request), METADATA_BYTES)
        with patch('har_request.base64.b64encode', side_effect=AssertionError('measurement must not encode')):
            self.assertEqual(request_facts_metadata_size(request), expected)

    def test_standard_contradictions_and_invalid_types_do_not_mutate_source_headers(self):
        request = captured()
        facts = export_request_facts(request)
        source_facts = copy.deepcopy(facts)
        headers_before = request.headers.fields
        for key, values in (('method', ('POST', None)), ('url', ('http://different.test/', None)),
                            ('httpVersion', ('HTTP/2.0', None, ''))):
            for value in values:
                with self.subTest(key=key, value=value):
                    source = {**standard(request), key: value}
                    with self.assertRaises(ValueError):
                        restore_request_facts(facts, source, request.headers, 1.25)
                    self.assertEqual(request.headers.fields, headers_before)
                    self.assertEqual(facts, source_facts)
        for missing in ('method', 'url'):
            source = standard(request)
            del source[missing]
            with self.assertRaises(ValueError):
                restore_request_facts(facts, source, request.headers, 1.25)


class LegacyHARRequest(unittest.TestCase):
    def test_ordinary_ascii_urls_match_sdk_make_without_mutating_passed_headers(self):
        for source in ('HTTP://EXAMPLE.TEST:80/a;b?x=1#frag', 'https://xn--bcher-kva.test:443/path',
                       'http://[::1]:8080/path', 'http://host:0', 'http://user:pass@host:123/x',
                       'http://host:/x', 'http://host?x=1', 'http://host/%FF?x=%FE'):
            with self.subTest(source=source):
                expected = http.Request.make('gEt', source)
                headers = http.Headers([(b'Host', b'source-header.test'), (b'X-Raw', b'\xff')])
                before = headers.fields
                request = restore_legacy_request({'method': 'gEt', 'url': source}, headers, 1.25)
                for name in ('method', 'scheme', 'authority', 'path', 'host', 'port', 'http_version'):
                    self.assertEqual(getattr(request.data, name), getattr(expected.data, name))
                self.assertEqual(headers.fields, before)
                self.assertIs(request.headers, headers)
                self.assertEqual(request.timestamp_start, 1.25)
                self.assertIsNone(request.timestamp_end)

    def test_non_utf8_and_utf8_suffix_bytes_are_preserved_without_quoting(self):
        for suffix in ('/raw\udcff?a=\udcfe&a=2', '/é?q=\u503c#\u7247', '/semi;p=1?x=1&x=2#fragment',
                       '/path?', '/path#', '/path?#', '?', '#', '/%FF?x=%FE'):
            with self.subTest(suffix=suffix):
                source = {'method': 'G\udcffT', 'url': 'https://bücher.test:8443' + suffix,
                          'httpVersion': 'HTTP/2.0'}
                request = restore_legacy_request(source, http.Headers(), 1.25)
                self.assertEqual(request.host, 'bücher.test')
                self.assertEqual(request.port, 8443)
                self.assertEqual(request.data.method, b'G\xffT')
                self.assertEqual(request.data.authority, b'', 'legacy HAR has no observed :authority bytes')
                self.assertEqual(request.data.path, (suffix if suffix.startswith('/') else '/' + suffix).encode('utf-8', 'surrogateescape'))
                self.assertEqual(request.data.http_version, b'HTTP/2.0')

    def test_legacy_asterisk_and_connect_facts_are_not_invented(self):
        request = restore_legacy_request({'method': 'OPTIONS', 'url': 'http://shown.test'}, http.Headers(), 1.25)
        self.assertEqual(request.data.path, b'/')
        self.assertEqual(request.data.authority, b'')
        for source in ('tunnel.test:443', '*', '/relative', 'ftp://host/path', '//host/path'):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'absolute HTTP'):
                restore_legacy_request({'method': 'CONNECT', 'url': source}, http.Headers(), 1.25)

    def test_invalid_legacy_authority_text_and_metadata_fail_without_header_mutation(self):
        headers = http.Headers([(b'Host', b'kept.test')])
        for source in ('http:///path', 'http://invalid host/path', 'http://host:65536/path',
                       'http://host:abc/path', 'http://[broken/path', 'http://host\x00/path',
                       'http://\udcff.test/path', 'http://host/\ud800'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                restore_legacy_request({'method': 'GET', 'url': source}, headers, 1.25)
            self.assertEqual(headers.fields, ((b'Host', b'kept.test'),))
        for source in (None, {}, {'method': None, 'url': 'http://host/'},
                       {'method': 'GET', 'url': 'http://host/', 'httpVersion': None}):
            with self.subTest(source=source), self.assertRaises(ValueError):
                restore_legacy_request(source, headers, 1.25)
        with patch('har_request.METADATA_BYTES', 1024), patch('har_request.http.Request', side_effect=AssertionError('must preflight')):
            with self.assertRaisesRegex(ValueError, 'budget'):
                restore_legacy_request({'method': 'GET', 'url': 'http://host/' + '\u754c' * 400}, headers, 1.25)


if __name__ == '__main__':
    unittest.main()
