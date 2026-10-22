"""Actual proxy cache/cookie controls, source-bound rule plans and client state."""
from concurrent.futures import ThreadPoolExecutor
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
import uuid

import httpx
from test_e2e import EngineHarness
from test_protocols import protocol_certificates

BODY = bytes(range(256)) + b'\x00\xffcache fixture'
WIRE = gzip.compress(BODY, mtime=123)
INPUT = [('Cookie', 'old=1'), ('cOOkie', 'second=2'),
         ('If-None-Match', '"fixture"'), ('if-none-match', '"other"'),
         ('If-Modified-Since', 'Wed, 01 Jan 2020 00:00:00 GMT'),
         ('Cache-Control', 'max-age=3600'), ('cache-control', 'public'),
         ('Pragma', 'cache'), ('pragma', 'other'), ('X-Keep', 'one'), ('X-Keep', 'two')]


class ControlOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def do_GET(self): self.respond()
    def do_HEAD(self): self.respond()
    def respond(self):
        with self.server.condition:
            self.server.history.append({'path': self.path, 'headers': list(self.headers.raw_items())})
            self.server.condition.notify_all()
        if self.path.startswith('/held-'):
            if not self.server.release.wait(10): raise TimeoutError('held fixture not released')
        status = 304 if self.headers.get_all('If-None-Match') else 200
        if self.path.startswith('/failure-'): status = 500
        self.send_response(status)
        for name, value in [('Content-Type', 'application/octet-stream'), ('Content-Encoding', 'gzip'),
                ('ETag', '"fixture"'), ('etag', '"duplicate"'),
                ('Last-Modified', 'Wed, 01 Jan 2020 00:00:00 GMT'),
                ('Expires', 'Wed, 01 Jan 2040 00:00:00 GMT'), ('expires', 'other'),
                ('Cache-Control', 'public, max-age=3600'), ('cache-control', 'immutable'),
                ('Set-Cookie', 'new=1; Path=/; HttpOnly'), ('set-cookie', 'another=2; Path=/'),
                ('X-Keep', 'one'), ('X-Keep', 'two')]:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(WIRE)))
        self.end_headers()
        if status != 304 and self.command != 'HEAD': self.wfile.write(WIRE)


def values(fields, name):
    return [value for key, value in fields if key.lower() == name.lower()]


class HTTPControlAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-http-controls-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.ca, cert, key = protocol_certificates(cls.directory)
        cls.plain = ThreadingHTTPServer(('127.0.0.1', 0), ControlOrigin)
        cls.secure = ThreadingHTTPServer(('127.0.0.1', 0), ControlOrigin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.secure.socket = context.wrap_socket(cls.secure.socket, server_side=True)
        for server in (cls.plain, cls.secure):
            server.daemon_threads = True
            server.history, server.condition, server.release = [], threading.Condition(), threading.Event()
            cls.addClassCleanup(server.server_close); cls.addClassCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.http = f'http://127.0.0.1:{cls.plain.server_port}'
        cls.https = f'https://localhost:{cls.secure.server_port}'
        cls.engine = EngineHarness(cls.directory, cls.ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready['ca_cert'])

    def setUp(self):
        self.engine.configure([]); self.engine.command('clear')

    def client(self, *, h2=False, context=None):
        return httpx.Client(proxy=self.engine.proxy, verify=context or self.context,
                            trust_env=False, timeout=10, http2=h2)

    def url(self, path, secure=False):
        return (self.https if secure else self.http) + '/' + path + '-' + uuid.uuid4().hex

    def controls(self, match='*', **extra):
        return [{'kind': kind, 'match': match, **extra} for kind in ('no_cache', 'block_cookies')]

    def observed(self, url):
        server = self.secure if url.startswith('https:') else self.plain
        with server.condition:
            return next(row['headers'] for row in reversed(server.history) if row['path'] == httpx.URL(url).raw_path.decode())

    def assert_request_controlled(self, fields):
        for name in ('Cookie', 'If-None-Match', 'If-Modified-Since'): self.assertEqual(values(fields, name), [])
        self.assertEqual(values(fields, 'Pragma'), ['no-cache'])
        self.assertEqual(values(fields, 'Cache-Control'), ['no-cache'])
        self.assertEqual(values(fields, 'X-Keep'), ['one', 'two'])

    def assert_response_controlled(self, response):
        for name in ('Set-Cookie', 'ETag', 'Last-Modified'): self.assertNotIn(name, response.headers)
        self.assertEqual(response.headers.get_list('Expires'), ['0'])
        self.assertEqual(response.headers.get_list('Cache-Control'), ['no-store'])
        self.assertEqual(response.headers.get_list('X-Keep'), ['one', 'two'])

    def test_exact_headers_binary_and_har_on_http_tls_h2_and_head(self):
        self.engine.configure(self.controls())
        for secure, h2, method in [(False, False, 'GET'), (True, False, 'GET'), (True, True, 'GET'), (True, True, 'HEAD')]:
            with self.subTest(secure=secure, h2=h2, method=method), self.client(h2=h2) as client:
                url = self.url('selected', secure)
                response = client.send(client.build_request(method, url, headers=INPUT), stream=True)
                try: wire = b''.join(response.iter_raw())
                finally: response.close()
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.http_version, 'HTTP/2' if h2 else 'HTTP/1.1')
                self.assertEqual(wire, b'' if method == 'HEAD' else WIRE)
                if method != 'HEAD': self.assertEqual(gzip.decompress(wire), BODY)
                self.assert_request_controlled(self.observed(url)); self.assert_response_controlled(response)
                row = self.engine.flow(url)
                detail = self.engine.command('detail', id=row['id'])[1]
                self.assert_request_controlled(detail['request_headers'])
                self.assertEqual(values(detail['response_headers'], 'Set-Cookie'), [])
        har = self.engine.command('export_har')[1]
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)

    def test_disabled_unmatched_and_live_off_restore_conditional_requests(self):
        selected, unmatched = self.url('selected'), self.url('unmatched')
        self.engine.configure(self.controls(self.http + '/selected-*'))
        with self.client() as client:
            self.assertEqual(client.get(selected, headers=INPUT).status_code, 200)
            for url, rules in [(unmatched, self.controls(selected)), (selected, self.controls(selected, enabled=False)), (selected, [])]:
                self.engine.configure(rules)
                response = client.get(url, headers=INPUT)
                self.assertEqual(response.status_code, 304)
                self.assertEqual(values(self.observed(url), 'If-None-Match'), ['"fixture"', '"other"'])
                self.assertEqual(values(self.observed(url), 'Cookie'), ['old=1', 'second=2'])
                self.assertEqual(response.headers.get_list('Set-Cookie'), ['new=1; Path=/; HttpOnly', 'another=2; Path=/'])
                self.assertEqual(response.headers.get_list('ETag'), ['"fixture"', '"duplicate"'])

    def test_cookie_jar_existing_state_remains_but_sending_and_receiving_are_blocked(self):
        self.engine.configure(self.controls())
        with self.client() as client:
            client.cookies.set('preexisting', 'retained')
            for _ in range(2):
                url = self.url('cookie-jar', secure=True)
                response = client.get(url)
                self.assertEqual(values(self.observed(url), 'Cookie'), [])
                self.assertNotIn('Set-Cookie', response.headers)
                self.assertEqual(dict(client.cookies), {'preexisting': 'retained'})

    def test_mapping_preserves_original_scope_on_both_sides_and_does_not_select_target_only_rules(self):
        url = self.url('mapped-source')
        mapping = {'kind': 'map_remote', 'match': url, 'value': self.http + '/destination'}
        self.engine.configure([mapping, *self.controls(url)])
        with self.client() as client:
            response = client.get(url, headers=INPUT)
        self.assertEqual(response.status_code, 200); self.assert_response_controlled(response)
        target = self.http + '/destination' + httpx.URL(url).path
        self.assert_request_controlled(self.observed(target))
        self.engine.configure([mapping, *self.controls(target)])
        with self.client() as client:
            response = client.get(url, headers=INPUT)
        self.assertEqual(response.status_code, 304)
        self.assertIn('Set-Cookie', response.headers); self.assertIn('ETag', response.headers)

    def test_inflight_config_and_clear_do_not_split_the_rule_plan(self):
        url = self.url('held')
        self.plain.release.clear()
        self.engine.configure(self.controls(url))
        def request():
            with self.client() as client: return client.get(url, headers=INPUT)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request)
            try:
                with self.plain.condition:
                    self.assertTrue(self.plain.condition.wait_for(lambda: any(row['path'] == httpx.URL(url).path for row in self.plain.history), timeout=5))
                self.engine.configure([]); self.engine.command('clear')
            finally: self.plain.release.set()
            response = pending.result(timeout=8)
        self.assert_response_controlled(response); self.assert_request_controlled(self.observed(url))
        self.assertEqual(self.engine.command('export_har')[1]['log']['entries'], [])
        with self.client() as client:
            new = client.get(self.url('after-config'), headers=INPUT)
        self.assertEqual(new.status_code, 304); self.assertIn('Set-Cookie', new.headers)

    def test_breakpoint_url_edit_and_config_change_keep_both_stage_rules(self):
        original, edited = self.url('before-edit'), self.url('after-edit', secure=True)
        self.engine.configure([{'kind': 'breakpoint_request', 'match': original},
            *self.controls(original), {'kind': 'breakpoint_response', 'match': edited}])
        def request():
            with self.client(h2=True) as client: return client.get(original, headers=INPUT)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request)
            first = self.engine.flow(original, 'paused')
            self.engine.configure([])
            after = len(self.engine.events)
            self.engine.command('resume', id=first['id'], pause_id=first['pause_id'], stage='request', action='continue', request_edit={'url': edited})
            second = self.engine.flow(edited, 'paused', after=after)
            self.assertEqual(second['pause_stage'], 'response')
            self.engine.command('resume', id=second['id'], pause_id=second['pause_id'], stage='response', action='continue')
            response = pending.result(timeout=8)
        self.assertEqual(response.status_code, 200)
        self.assert_request_controlled(self.observed(edited)); self.assert_response_controlled(response)

    def test_concurrent_h2_streams_keep_independent_configuration_generations(self):
        held, later = self.url('held', secure=True), self.url('later', secure=True)
        self.secure.release.clear()
        self.engine.configure(self.controls())
        with self.client(h2=True) as client, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.get, held, headers=INPUT)
            try:
                with self.secure.condition:
                    self.assertTrue(self.secure.condition.wait_for(lambda: any(row['path'] == httpx.URL(held).path for row in self.secure.history), timeout=5))
                self.engine.configure([])
                second = client.get(later, headers=INPUT)
                self.assertEqual(second.status_code, 304)
                self.assertIn('Set-Cookie', second.headers)
            finally: self.secure.release.set()
            first = pending.result(timeout=8)
            self.assertEqual((first.http_version, second.http_version), ('HTTP/2', 'HTTP/2'))
            self.assertEqual(first.extensions['network_stream'].get_extra_info('socket').getsockname(),
                             second.extensions['network_stream'].get_extra_info('socket').getsockname())
            self.assert_response_controlled(first); self.assert_request_controlled(self.observed(held))
            # H2->H1 permits joining Cookie fields with semicolon separators.
            self.assertEqual(values(self.observed(later), 'Cookie'), ['old=1; second=2'])

    def test_later_rewrites_can_override_and_earlier_rewrites_are_removed(self):
        rewrites = [{'kind': 'rewrite_request_header', 'match': '*', 'name': 'Cookie', 'value': 'restored=1'},
                    {'kind': 'rewrite_response_header', 'match': '*', 'name': 'Set-Cookie', 'value': 'restored=1'},
                    {'kind': 'rewrite_response_header', 'match': '*', 'name': 'ETag', 'value': '"restored"'}]
        for later in (True, False):
            self.engine.configure([*self.controls(), *rewrites] if later else [*rewrites, *self.controls()])
            url = self.url('ordered')
            with self.client() as client: response = client.get(url, headers=INPUT)
            self.assertEqual(values(self.observed(url), 'Cookie'), ['restored=1'] if later else [])
            self.assertEqual(response.headers.get_list('Set-Cookie'), ['restored=1'] if later else [])
            self.assertEqual(response.headers.get_list('ETag'), ['"restored"'] if later else [])

    def test_opaque_tls_is_not_modified_and_visible_error_response_is_controlled(self):
        self.engine.command('configure', rules=self.controls(), ssl_hosts='')
        url = self.url('opaque', secure=True)
        with self.client(context=ssl.create_default_context(cafile=self.ca)) as client:
            response = client.get(url, headers=INPUT)
        self.assertEqual(response.status_code, 304)
        self.assertIn('Set-Cookie', response.headers)
        self.assertEqual(values(self.observed(url), 'Cookie'), ['old=1', 'second=2'])
        self.assertFalse(any(row['url'] == url for row in self.engine.flows.values()))
        self.engine.configure(self.controls())
        with self.client() as client: response = client.get(self.url('failure'), headers=INPUT)
        self.assertEqual(response.status_code, 500); self.assert_response_controlled(response)
