import unittest
from mitmproxy import http
from http_urls import request_url, prepare_url, prepare_destination


class HTTPURLRendering(unittest.TestCase):
    def test_ipv6_default_and_explicit_ports_keep_authority_brackets(self):
        for source in ('http://[::1]/a?x=1&x=2', 'https://[2001:db8::1]:8443/a%2Fb?x=%2F'):
            request = http.Request.make('GET', source)
            self.assertEqual(request_url(request), source)
            self.assertEqual(request_url(request, pretty=True), source)

    def test_display_authority_is_distinct_from_actual_routed_host(self):
        request = http.Request.make('POST', 'http://127.0.0.1:8000/a')
        request.host_header = '[::1]:9000'
        self.assertEqual(request_url(request), 'http://127.0.0.1:8000/a')
        self.assertEqual(request_url(request, pretty=True), 'http://[::1]:9000/a')
        request.host_header = 'virtual.test'
        self.assertEqual(request_url(request, pretty=True), 'http://virtual.test/a')

    def test_non_ipv6_source_and_path_facts_match_sdk_without_reparsing(self):
        for source in ('http://example.test:8080/a%2Fb?x=1&x=2', 'https://example.test/empty?', 'https://xn--fiq228c.test/a'):
            request = http.Request.make('GET', source)
            self.assertEqual(request_url(request), request.url)
            self.assertEqual(request_url(request, pretty=True), request.pretty_url)

    def test_malformed_host_header_is_not_reclassified_as_ipv6(self):
        request = http.Request.make('GET', 'http://example.test/a')
        request.host_header = 'bad:unknown'
        self.assertEqual(request_url(request, pretty=True), request.pretty_url)

    def test_asterisk_and_connect_keep_existing_source_semantics(self):
        request = http.Request.make('OPTIONS', 'http://example.test/')
        request.path = '*'
        self.assertEqual(request_url(request), request.url)
        request.method = 'CONNECT'; request.authority = 'example.test:443'; request.path = ''
        self.assertEqual(request_url(request), request.url)
        self.assertEqual(request_url(request, pretty=True), request.pretty_url)

    def test_prepared_url_keeps_source_normalized_value_and_authority_as_distinct_facts(self):
        source = 'HTTP://[::1]:8080/path?x=1'
        prepared = prepare_url(source)
        self.assertEqual((prepared.source, prepared.value, prepared.authority),
                         (source, 'http://[::1]:8080/path?x=1', '[::1]:8080'))
        unicode_url = prepare_url('https://中文.test/a')
        self.assertEqual(unicode_url.source, 'https://中文.test/a')
        self.assertEqual(unicode_url.authority, 'xn--fiq228c.test')

    def test_prepared_target_owns_empty_query_and_default_path_without_sdk_reparse(self):
        for source, target in (("http://example.test", b"/"), ("http://example.test?", b"/?"),
                               ("http://example.test/empty?", b"/empty?"),
                               ("https://[::1]/a;b?x=%2f&x=", b"/a;b?x=%2f&x=")):
            with self.subTest(source=source):
                self.assertEqual(prepare_url(source).target, target)

    def test_destination_admits_only_host_facts_not_embedded_url_components(self):
        for host in ('valid.test/path', 'valid.test?query', 'user@valid.test', '[::1]', '', 'bad\udcff.test', '::1%' + 'a.' * 150 + 'a'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                prepare_destination('http', host, 8080)
        for port in (True, 0, 65536, '80'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                prepare_destination('https', 'valid.test', port)
        for host, expected in (('::1', '[::1]:8080'), ('中文.test', 'xn--fiq228c.test:8080'), ('xn--fa-hia.test', 'xn--fa-hia.test:8080'), ('source_name.test', 'source_name.test:8080')):
            destination = prepare_destination('https', host, 8080)
            self.assertEqual(destination.authority, expected)
            self.assertEqual(destination.port, 8080)
