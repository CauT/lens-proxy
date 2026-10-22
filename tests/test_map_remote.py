"""Map Remote acceptance through real JSONL control and owned HTTP/TLS sockets.

No external requests, host proxy changes, or trust-store changes are made.
LENS_TEST_ENGINE can select a separately packaged engine and runtime.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

import httpx

from test_e2e import EngineHarness
from test_network_features import certificates


class MappingOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_OPTIONS(self):
        self.respond()

    def respond(self):
        record = {'method': self.command,
                  'target_base64': base64.b64encode(self.raw_requestline.split(b' ', 2)[1]).decode(),
                  'host': self.headers.get('Host'),
                  'sni': getattr(self.connection, 'mapping_sni', None)}
        with self.server.history_lock:
            self.server.history.append(record)
        target = base64.b64decode(record['target_base64'])
        status, location = 200, None
        if target.startswith(b'/redirect/'):
            status = int(target.split(b'/')[2].split(b'?')[0])
            location = (self.server.absolute_location if status in (301, 307)
                        else '../final?item=1&item=&')
        payload = json.dumps(record).encode()
        self.send_response(status)
        if location is not None:
            self.send_header('Location', location)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class IPv6MappingOrigin(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class MapRemoteFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-map-remote-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, leaves = certificates(cls.directory)
        cls.origins = []
        for identity in (None, leaves[0], leaves[1]):
            cls.origins.append(cls.start_origin(identity=identity))
        cls.origin, cls.secure, cls.wrong_san = cls.origins
        cls.http = f'http://127.0.0.1:{cls.origin.server_port}'
        cls.https = f'https://localhost:{cls.secure.server_port}'
        for origin in cls.origins:
            origin.absolute_location = cls.http + '/final?item=1&item=&'
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready['ca_cert'])

    @classmethod
    def start_origin(cls, *, identity=None, ipv6=False):
        server_type = IPv6MappingOrigin if ipv6 else ThreadingHTTPServer
        server = server_type(('::1' if ipv6 else '127.0.0.1', 0), MappingOrigin)
        cls.addClassCleanup(server.server_close)
        server.history, server.history_lock = [], threading.Lock()
        if identity is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*identity)

            def observe_sni(connection, server_name, _context):
                connection.mapping_sni = server_name

            context.set_servername_callback(observe_sni)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, name='map-remote-origin')
        worker.start()
        cls.addClassCleanup(cls.close_origin, server, worker)
        return server

    @staticmethod
    def close_origin(server, worker):
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError('Owned Map Remote origin did not stop')

    def setUp(self):
        self.engine.configure([])
        self.engine.command('clear')

    @staticmethod
    def mapping(destination, match='*', mode='relative'):
        rule = {'kind': 'map_remote', 'match': match, 'value': destination}
        if mode is not None:
            rule['path_mode'] = mode
        return rule

    def client(self, *, http2=False):
        return httpx.Client(proxy=self.engine.proxy, verify=self.context,
                            trust_env=False, timeout=8, http2=http2, follow_redirects=False)

    def captured(self, original, *, after=0):
        return self.engine.wait(lambda event: event.get('event') == 'flow'
            and event['flow'].get('original_url') == original
            and event['flow']['state'] == 'complete', after=after)['flow']

    def raw_request(self, target, *, method=b'GET', host=b'original.invalid'):
        with socket.create_connection(('127.0.0.1', self.engine.port), timeout=8) as connection:
            connection.sendall(method + b' ' + target + b' HTTP/1.1\r\nHost: '
                               + host + b'\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(connection)
            response.begin()
            try:
                payload = response.read()
                self.assertEqual(response.status, 200, payload)
                return json.loads(payload)
            finally:
                response.close()

    def assert_target(self, record, expected):
        self.assertEqual(base64.b64decode(record['target_base64']), expected)


class MapRemoteAcceptance(MapRemoteFixture):
    def test_relative_directory_file_and_empty_destination_path(self):
        cases = [
            ('/api/*', '/dev/', '/api/nested/x?one=1', b'/dev/nested/x?one=1'),
            ('/api/*.css', '/dev/', '/api/nested/x.css', b'/dev/nested/x.css'),
            ('/api/old.txt', '/new.txt', '/api/old.txt', b'/new.txt'),
            ('/api/old.txt', '/dev/', '/api/old.txt', b'/dev/old.txt'),
            ('/api/*', '', '/api/x?x=1', b'/api/x?x=1'),
            ('/api/*', '/', '/api/x?x=1', b'/x?x=1'),
        ]
        for scope, destination, source, expected in cases:
            with self.subTest(scope=scope, destination=destination, source=source):
                self.engine.configure([self.mapping(self.http + destination, 'http://original.invalid' + scope)])
                original = 'http://original.invalid' + source
                with self.client() as client:
                    response = client.get(original)
                self.assertEqual(response.status_code, 200, response.text)
                self.assert_target(response.json(), expected)
                self.assertEqual(response.json()['host'], f'127.0.0.1:{self.origin.server_port}')

    def test_absent_path_mode_retains_legacy_append_and_query_override(self):
        for mode in (None, 'append'):
            with self.subTest(mode=mode):
                self.engine.configure([self.mapping(self.http + '/base?replacement=2', mode=mode)])
                with self.client() as client:
                    response = client.get('http://original.invalid/api/x?original=1')
                self.assertEqual(response.status_code, 200, response.text)
                self.assert_target(response.json(), b'/base/api/x?replacement=2')

    def test_raw_targets_preserve_empty_query_percent_spelling_and_opaque_bytes(self):
        targets = [b'/api/raw?', b'/api/%2f%FF?x=%FF&x=&',
                   b'/api/raw\xff?q=1', b'/api/raw??duplicate?&']
        for source in targets:
            with self.subTest(source=source):
                self.engine.configure([self.mapping(self.http + '/dev/', 'http://original.invalid/api/*')])
                # Origin-form ingress retains opaque SDK path bytes; the
                # pinned proxy's absolute-form parser rejects non-UTF8 URLs.
                target = source if b'\xff' in source else b'http://original.invalid' + source
                record = self.raw_request(target)
                self.assert_target(record, b'/dev/' + source[len(b'/api/'):])
                entry = self.engine.command('export_har')[1]['log']['entries'][-1]
                self.assertEqual(base64.b64decode(entry['_lensRequestFacts']['path_base64']),
                                 b'/dev/' + source[len(b'/api/'):])
        self.engine.configure([self.mapping(self.http + '/dev/?', 'http://original.invalid/api/*')])
        record = self.raw_request(b'http://original.invalid/api/x?remove=1&')
        self.assert_target(record, b'/dev/x?')
        self.engine.configure([self.mapping(self.http + '/dev/?new=2&new=', 'http://original.invalid/api/*')])
        record = self.raw_request(b'http://original.invalid/api/x?remove=1')
        self.assert_target(record, b'/dev/x?new=2&new=')
        har = self.engine.command('export_har')[1]
        path = self.directory / 'raw-targets.har'
        self.engine.command('save_har', path=str(path))
        self.engine.command('clear')
        self.engine.command('load_har', path=str(path))
        self.assertEqual(self.engine.command('export_har')[1], har)

    def test_options_asterisk_remains_asterisk_after_destination_change(self):
        self.engine.configure([self.mapping(self.http + '/dev/')])
        record = self.raw_request(b'*', method=b'OPTIONS')
        self.assert_target(record, b'*')
        self.assertEqual(record['method'], 'OPTIONS')
        self.assertEqual(record['host'], f'127.0.0.1:{self.origin.server_port}')

    def test_http_to_https_uses_mapped_host_sni_and_strict_san_verification(self):
        original = 'http://original.invalid/api/tls?kept=1'
        self.engine.configure([self.mapping(self.https + '/dev/', 'http://original.invalid/api/*')])
        with self.client() as client:
            response = client.get(original)
        self.assertEqual(response.status_code, 200, response.text)
        self.assert_target(response.json(), b'/dev/tls?kept=1')
        self.assertEqual(response.json()['host'], f'localhost:{self.secure.server_port}')
        self.assertEqual(response.json()['sni'], 'localhost')
        flow = self.captured(original)
        self.assertEqual(flow['effective_url'], self.https + '/dev/tls?kept=1')
        self.engine.configure([self.mapping(f'https://localhost:{self.wrong_san.server_port}/dev/',
                                             'http://original.invalid/api/*')])
        before = len(self.wrong_san.history)
        with self.client() as client:
            rejected = client.get(original)
        self.assertEqual(rejected.status_code, 502)
        self.assertIn('certificate', rejected.text.lower())
        self.assertEqual(len(self.wrong_san.history), before)

    def test_https_to_http_keeps_frontend_h2_and_effective_http_destination(self):
        original = self.https + '/api/front-h2?kept=1'
        self.engine.configure([self.mapping(self.http + '/dev/', self.https + '/api/*')])
        with self.client(http2=True) as client:
            response = client.get(original)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.http_version, 'HTTP/2')
        self.assert_target(response.json(), b'/dev/front-h2?kept=1')
        self.assertEqual(response.json()['host'], f'127.0.0.1:{self.origin.server_port}')
        self.assertIsNone(response.json()['sni'])
        flow = self.captured(original)
        self.assertEqual(flow['effective_url'], self.http + '/dev/front-h2?kept=1')

    def test_ipv6_mapped_host_is_bracketed_for_http1_and_frontend_h2(self):
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(('::1', 0))
        except OSError as exc:
            self.skipTest(f'IPv6 loopback is unavailable: {exc}')
        origin = self.start_origin(ipv6=True)
        destination = f'http://[::1]:{origin.server_port}/dev/'
        for secure in (False, True):
            original = (self.https if secure else 'http://original.invalid') + '/api/ipv6'
            with self.subTest(frontend_https_h2=secure):
                self.engine.configure([self.mapping(destination, (self.https if secure else 'http://original.invalid') + '/api/*')])
                with self.client(http2=secure) as client:
                    response = client.get(original)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()['host'], f'[::1]:{origin.server_port}')
                self.assert_target(response.json(), b'/dev/ipv6')
                if secure:
                    self.assertEqual(response.http_version, 'HTTP/2')
                flow = self.captured(original)
                self.assertEqual(flow['routed_url'], destination + 'ipv6')

    def test_redirects_remain_original_responses_and_har_roundtrip_is_exact(self):
        for status in (301, 302, 307, 308):
            with self.subTest(status=status):
                self.engine.command('clear')
                self.engine.configure([self.mapping(self.http + '/redirect/', 'http://original.invalid/api/*')])
                original = f'http://original.invalid/api/{status}?kept=1'
                before = len(self.origin.history)
                with self.client() as client:
                    response = client.get(original)
                self.assertEqual(response.status_code, status)
                expected = (self.origin.absolute_location if status in (301, 307)
                            else '../final?item=1&item=&')
                self.assertEqual(response.headers['Location'], expected)
                self.assertEqual(len(self.origin.history), before + 1)
                flow = self.captured(original)
                effective = self.http + f'/redirect/{status}?kept=1'
                self.assertEqual(flow['effective_url'], effective)
                har = self.engine.command('export_har')[1]
                entry = har['log']['entries'][0]
                self.assertEqual(entry['_lensOriginalUrl'], original)
                self.assertEqual(entry['request']['url'], effective)
                self.assertIn({'name': 'Location', 'value': expected}, entry['response']['headers'])
                path = self.directory / f'redirect-{status}.har'
                self.engine.command('save_har', path=str(path))
                self.engine.command('clear')
                self.engine.command('load_har', path=str(path))
                self.assertEqual(self.engine.command('export_har')[1], har)
                self.assertEqual(self.captured(original)['effective_url'], effective)

    def test_invalid_destinations_and_modes_reject_atomically(self):
        retained = self.mapping(self.http + '/retained/', 'http://original.invalid/api/*')
        self.engine.configure([retained])
        invalid = ['http://mapped.invalid:abc/', 'http://mapped.invalid:65536/',
                   'http://mapped.invalid:0/', 'http://mapped.invalid:/',
                   'http://mapped.invalid\n.evil/', 'http://mapped.invalid/#fragment',
                   'http://@mapped.invalid/', 'http://user:password@mapped.invalid/',
                   'http://mapped.invalid/with space', 'http://mapped.invalid/\\escape']
        for index, target in enumerate(invalid):
            with self.subTest(target=target):
                with self.assertRaises(AssertionError):
                    self.engine.configure([self.mapping(self.http + '/wrong/'), self.mapping(target)])
                with self.client() as client:
                    response = client.get(f'http://original.invalid/api/valid-{index}')
                self.assertEqual(response.status_code, 200, response.text)
                self.assert_target(response.json(), f'/retained/valid-{index}'.encode())
        for mode in ('unknown', '', 1, None):
            with self.subTest(path_mode=mode):
                malformed = self.mapping(self.http + '/wrong/')
                malformed['path_mode'] = mode
                with self.assertRaises(AssertionError):
                    self.engine.configure([malformed])
        with self.client() as client:
            response = client.get('http://original.invalid/api/still-retained')
        self.assert_target(response.json(), b'/retained/still-retained')

    def test_chained_source_prefix_mismatch_and_expansion_fail_before_dial(self):
        scope = 'http://original.invalid/api/*'
        self.engine.configure([self.mapping(self.http + '/moved/', scope),
                               self.mapping(self.http + '/dev/', scope)])
        before = len(self.origin.history)
        with self.client() as client:
            response = client.get('http://original.invalid/api/chained')
        self.assertEqual(response.status_code, 502)
        self.assertIn('source directory', response.text)
        self.assertEqual(len(self.origin.history), before)
        # Each selected input fits the URL bound. Their assembled target does
        # not, so mapping must fail before any upstream request is emitted.
        self.engine.configure([self.mapping(self.http + '/' + 'p' * 40000,
                                             scope, mode='append')])
        with self.client() as client:
            response = client.get('http://original.invalid/api/' + 'x' * 30000)
        self.assertEqual(response.status_code, 502)
        self.assertIn('64 KiB', response.text)
        self.assertEqual(len(self.origin.history), before)

    def test_paused_request_retains_compiled_mapping_across_configuration_change(self):
        scope = 'http://original.invalid/api/*'
        original = 'http://original.invalid/api/generation?kept=1'
        self.engine.configure([
            {'kind': 'breakpoint_request', 'match': scope, 'timeout_seconds': 30},
            self.mapping(self.http + '/retained/', scope),
        ])

        def request():
            with self.client() as client:
                return client.get(original)

        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(request)
            paused = self.engine.flow(original, 'paused')
            self.engine.configure([self.mapping(self.https + '/replacement', scope, mode='append')])
            self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'],
                                stage='request', action='continue')
            first = pending.result(timeout=8)
        self.assertEqual(first.status_code, 200, first.text)
        self.assert_target(first.json(), b'/retained/generation?kept=1')
        self.assertEqual(first.json()['host'], f'127.0.0.1:{self.origin.server_port}')
        self.assertIsNone(first.json()['sni'])
        first_flow = self.captured(original)
        self.assertEqual(first_flow['id'], paused['id'])
        self.assertEqual(first_flow['effective_url'], self.http + '/retained/generation?kept=1')
        after = len(self.engine.events)
        second = request()
        self.assertEqual(second.status_code, 200, second.text)
        self.assert_target(second.json(), b'/replacement/api/generation?kept=1')
        self.assertEqual(second.json()['host'], f'localhost:{self.secure.server_port}')
        self.assertEqual(second.json()['sni'], 'localhost')
        second_flow = self.captured(original, after=after)
        self.assertNotEqual(second_flow['id'], first_flow['id'])
        self.assertEqual(second_flow['effective_url'], self.https + '/replacement/api/generation?kept=1')


if __name__ == '__main__':
    unittest.main()
