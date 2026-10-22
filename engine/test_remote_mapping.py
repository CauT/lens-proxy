"""SDK boundary cases that cannot be inferred from successful ASCII wire requests."""
import unittest
from mitmproxy import http
from http_urls import URL_BYTES
from remote_mapping import RemoteMapping


class RemoteMappingBoundaries(unittest.TestCase):
    def test_opaque_target_and_ipv6_authority_in_both_sdk_protocol_shapes(self):
        for version in ("HTTP/1.1", "HTTP/2.0"):
            with self.subTest(version=version):
                request = http.Request.make("GET", "http://source.test/api/x")
                request.http_version = version
                request.data.path = b"/api/raw\xff%2f?x=&x=%ff&"
                selected = RemoteMapping.prepare("https://[::1]:8443/dev/", "http://source.test/api/*", "relative")
                selected.apply(request)
                self.assertEqual(request.data.path, b"/dev/raw\xff%2f?x=&x=%ff&")
                self.assertEqual(request.host, "::1")
                self.assertEqual(request.port, 8443)
                self.assertEqual(request.host_header, "[::1]:8443")
                if version == "HTTP/2.0":
                    self.assertEqual(request.authority, "[::1]:8443")

    def test_asterisk_remains_server_target(self):
        request = http.Request.make("OPTIONS", "http://source.test/")
        request.data.path = b"*"
        RemoteMapping.prepare("https://mapped.test/dev/?q=1", "*", "relative").apply(request)
        self.assertEqual(request.data.path, b"*")
        self.assertEqual(request.host_header, "mapped.test")

    def test_target_budget_and_later_inapplicable_mapping_do_not_partially_mutate(self):
        request = http.Request.make("GET", "http://source.test/api/a")
        original = request.get_state()
        with self.assertRaisesRegex(ValueError, "source directory"):
            RemoteMapping.prepare("https://mapped.test/dev/", "http://source.test/other/*", "relative").apply(request)
        self.assertEqual(request.get_state(), original)
        request.data.path = b"/" + b"a" * (URL_BYTES - 1)
        original = request.get_state()
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            RemoteMapping.prepare("https://mapped.test/base", "*", "append").apply(request)
        self.assertEqual(request.get_state(), original)

    def test_input_admission_rejects_ambiguous_destinations_and_modes(self):
        for source in ("http://host:abc/", "http://host:65536/", "http://host:0/", "http://host:/",
                       "http://host\n.evil/", "http://host/#fragment", "http://@host/", "http://user:pass@host/",
                       "http://host/space here", "http://host/\\bad", "http://host/" + "x" * URL_BYTES):
            with self.subTest(source=source[:80]), self.assertRaises(ValueError):
                RemoteMapping.prepare(source, "*")
        for mode in (None, True, "unknown", []):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                RemoteMapping.prepare("https://host/", "*", mode)

class IndividualDestinationBoundaries(unittest.TestCase):
    def test_blank_fields_and_path_only_preserve_exact_authority_and_opaque_bytes(self):
        request = http.Request.make('GET', 'http://source.test:8123/api/old')
        request.host_header = 'Source.TEST:8123'
        request.data.path = b'/api/raw\xff%2f?k=&k=%ff&'
        before = request.get_state()
        RemoteMapping.prepare_parts({}, '*', 'relative').apply(request)
        self.assertEqual(request.get_state(), before)
        RemoteMapping.prepare_parts({'path': '/dev/'}, 'http://source.test:8123/api/*', 'relative').apply(request)
        self.assertEqual(request.data.path, b'/dev/raw\xff%2f?k=&k=%ff&')
        self.assertEqual(request.host_header, 'Source.TEST:8123')
        self.assertEqual((request.scheme, request.host, request.port), ('http', 'source.test', 8123))

    def test_only_selected_authority_facts_change_and_idna_ipv6_use_endpoint_owner(self):
        for selected, expected in (({'scheme': 'https'}, ('https', 'source.test', 8123)),
                                   ({'host': 'LOCALHOST.'}, ('http', 'localhost', 8123)),
                                   ({'port': '8443'}, ('http', 'source.test', 8443)),
                                   ({'host': 'faß.test'}, ('http', 'xn--fa-hia.test', 8123)),
                                   ({'host': '::1', 'port': 8443}, ('http', '::1', 8443))):
            with self.subTest(selected=selected):
                request = http.Request.make('GET', 'http://source.test:8123/api/x')
                request.data.path = b'/api/x?'
                RemoteMapping.prepare_parts(selected, '*', 'relative').apply(request)
                self.assertEqual((request.scheme, request.host, request.port), expected)
                self.assertEqual(request.data.path, b'/api/x?')
                self.assertEqual(request.host_header, ('[::1]' if expected[1] == '::1' else expected[1]) + ':' + str(expected[2]))

    def test_query_preserve_replace_and_explicit_empty_are_separate(self):
        for selected, expected in (({}, b'/api/x?x=%2f&&'), ({'query_mode': 'replace', 'query': 'k=%2F&k='}, b'/api/x?k=%2F&k='),
                                   ({'query_mode': 'replace'}, b'/api/x?')):
            request = http.Request.make('GET', 'http://source.test/api/x?x=%2f&&')
            RemoteMapping.prepare_parts(selected, '*', 'relative').apply(request)
            self.assertEqual(request.data.path, expected)

    def test_invalid_selected_fields_fail_at_configuration_without_partial_edits(self):
        for selected in ([], {'unknown': 'x'}, {'scheme': 'ftp'}, {'host': 'http://bad'}, {'host': '[::1]'},
                         {'port': True}, {'port': '0'}, {'port': 65536}, {'port': '8x'}, {'port': '１'},
                         {'path': 'relative'}, {'path': '/path?query'}, {'path': '/path#fragment'}, {'path': '/中文'},
                         {'query_mode': 'future'}, {'query_mode': 'replace', 'query': 'bad#fragment'}, {'host': None}):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                RemoteMapping.prepare_parts(selected, '*', 'relative')

    def test_asterisk_and_h2_authority_follow_selected_destination_without_target_conversion(self):
        request = http.Request.make('OPTIONS', 'http://source.test:8123/')
        request.http_version = 'HTTP/2.0'; request.data.path = b'*'
        RemoteMapping.prepare_parts({'host': '::1'}, '*', 'relative').apply(request)
        self.assertEqual(request.data.path, b'*'); self.assertEqual(request.authority, '[::1]:8123')


class IndividualConfigurationOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_selected_fields_are_detached_and_immutable_after_configuration(self):
        from pathlib import Path
        from unittest.mock import Mock, patch
        import engine
        master = Mock(); master.addons.get.return_value = None
        lens = engine.Lens(master, Path('/tmp/unused-map-parts-owner'), 8890)
        selected = {'host': 'localhost', 'port': '8123', 'path': '/admitted'}
        try:
            with patch.object(engine, 'emit'):
                await lens.command({'command': 'configure', 'rules': [{'kind': 'map_remote', 'match': '*', 'path_mode': 'relative', 'map_destination': selected}]})
                selected['host'] = 'changed.test'; selected['path'] = '/changed'
                self.assertEqual(lens.rules[0].parameters['map_destination']['host'], 'localhost')
                with self.assertRaises(TypeError): lens.rules[0].parameters['map_destination']['host'] = 'mutated.test'
                request = http.Request.make('GET', 'http://source.test/original')
                lens.rules[0].remote.apply(request)
                self.assertEqual((request.host, request.port, request.data.path), ('localhost', 8123, b'/admitted'))
        finally:
            await lens.close()


if __name__ == "__main__":
    unittest.main()
