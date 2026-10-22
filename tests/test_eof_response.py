"""Real close-delimited HTTP responses and incomplete advertised lengths.

The upstream writes literal HTTP/1.0 or HTTP/1.1 bytes without CL/TE. TLS uses
private scoped CAs. No host proxy/trust, GUI, provider or external host is used.
LENS_TEST_ENGINE selects a packaged engine with the same production boundary.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest

import httpx

from test_e2e import EngineHarness
from test_protocols import protocol_certificates


BINARY = bytes(range(256)) * 33 + b'\x00\xffEOF payload\r\n'
PARTS = [b'first\x00', b'\xffmiddle', b'final bytes']
SOURCE_HEADERS = [(b'Content-Type', b'application/octet-stream'),
                  (b'X-EOF', b'first'), (b'x-eof', b'second'),
                  (b'Connection', b'close')]


class EOFOrigin(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        line = self.rfile.readline(65537)
        if not line:
            return
        request_fields = []
        while True:
            header = self.rfile.readline(65537)
            if header == b'\r\n':
                break
            if not header:
                raise EOFError('Owned upstream request ended in headers')
            request_fields.append(header)
        path = line.split(b' ', 2)[1].decode('ascii')
        version = 'HTTP/1.0' if '/http10/' in path else 'HTTP/1.1'
        body = b'' if '/empty' in path else b''.join(PARTS) if '/held' in path else BINARY
        fields = list(SOURCE_HEADERS)
        if '/short-length' in path:
            fields.append((b'Content-Length', str(len(body) + 23).encode()))
        row = {'path': path, 'version': version, 'headers': fields, 'body': body,
               'request_line': line, 'request_headers': request_fields,
               'before_eof': threading.Event(), 'release': threading.Event(),
               'closed': threading.Event(), 'parts_sent': []}
        if '/held' not in path:
            row['release'].set()
        with self.server.condition:
            self.server.history.append(row)
            self.server.condition.notify_all()
        try:
            wire_headers = (version + ' 200 EOF source\r\n').encode() + b''.join(
                name + b': ' + value + b'\r\n' for name, value in fields) + b'\r\n'
            self.request.sendall(wire_headers)
            pieces = PARTS if '/held' in path else [body]
            for piece in pieces:
                self.request.sendall(piece)
                row['parts_sent'].append(piece)
                if '/held' in path:
                    time.sleep(.08)
            row['before_eof'].set()
            if not row['release'].wait(10):
                raise TimeoutError('Owned EOF fixture was not released')
            if isinstance(self.request, ssl.SSLSocket):
                # Initiate TLS close_notify, so a close-delimited body ends at
                # a real TLS EOF instead of relying on an abrupt TCP reset.
                try:
                    plain = self.request.unwrap()
                    plain.close()
                except (ssl.SSLError, OSError):
                    pass
            else:
                try:
                    self.request.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        finally:
            self.request.close()
            row['closed'].set()


class EOFServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class EOFResponseAcceptance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lens-eof-response-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(self.directory)
        self.origins = []
        for secure in (False, True):
            server = EOFServer(('127.0.0.1', 0), EOFOrigin)
            server.history, server.condition = [], threading.Condition()
            self.addCleanup(server.server_close)
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, name='owned-eof-origin')
            worker.start()
            self.addCleanup(self.close_origin, server, worker)
            self.origins.append(server)
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)
        self.engine.configure([])
        self.context = ssl.create_default_context(cafile=self.engine.ready['ca_cert'])

    @staticmethod
    def close_origin(server, worker):
        with server.condition:
            for row in server.history:
                row['release'].set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError('Owned EOF listener did not join')

    def url(self, path, secure=False):
        return f'{"https://localhost" if secure else "http://127.0.0.1"}:{self.origins[int(secure)].server_address[1]}{path}'

    def request(self, url):
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=8) as client:
            response = client.send(client.build_request('GET', url), stream=True)
            try:
                raw = b''.join(response.iter_raw())
            finally:
                response.close()
        return response, raw

    def held(self, path, secure):
        server = self.origins[int(secure)]
        with server.condition:
            self.assertTrue(server.condition.wait_for(
                lambda: any(row['path'] == path for row in server.history), timeout=5))
            row = next(row for row in server.history if row['path'] == path)
        self.assertTrue(row['before_eof'].wait(5))
        return row

    def entry(self, url):
        return next(entry for entry in self.engine.command('export_har')[1]['log']['entries']
                    if entry['request']['url'] == url)

    def assert_source(self, entry, body, version):
        self.assertEqual(entry['response']['httpVersion'], version)
        fields = [(item['name'].encode(), item['value'].encode())
                  for item in entry['response']['headers']]
        self.assertEqual(fields, SOURCE_HEADERS)
        self.assertFalse(any(name.lower() in (b'content-length', b'transfer-encoding') for name, _ in fields))
        self.assertEqual(base64.b64decode(entry['_lensRawResponseBody']), body)
        content = entry['response']['content']
        decoded = base64.b64decode(content['text']) if content.get('encoding') == 'base64' else content['text'].encode()
        self.assertEqual(decoded, body)

    def roundtrip(self, name):
        path = self.directory / f'{name}.har'
        self.engine.command('save_har', path=str(path))
        original = json.loads(path.read_text())
        self.engine.command('clear')
        self.engine.command('load_har', path=str(path))
        after = self.directory / f'{name}-reopened.har'
        self.engine.command('save_har', path=str(after))
        self.assertEqual(json.loads(after.read_text()), original)
        return original

    def test_http10_http11_binary_empty_eof_on_http_and_strict_tls(self):
        for secure in (False, True):
            for version in ('http10', 'http11'):
                for label, expected in [('binary', BINARY), ('empty', b'')]:
                    with self.subTest(secure=secure, version=version, label=label):
                        url = self.url(f'/{version}/{label}', secure)
                        response, raw = self.request(url)
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(raw, expected)
                        flow = self.engine.flow(url)
                        self.assertIsNone(flow['error'])
                        detail = self.engine.command('detail', id=flow['id'])[1]
                        self.assertIs(detail['response_body_available'], True)
                        self.assertEqual(base64.b64decode(detail['response_body_base64']), expected)
                        self.assertIs(detail['response_truncated'], False)
                        self.assert_source(self.entry(url), expected, 'HTTP/1.0' if version == 'http10' else 'HTTP/1.1')
        self.assertEqual(len(self.roundtrip('all-complete')['log']['entries']), 8)

    def test_delayed_eof_stays_pending_until_actual_connection_end(self):
        for secure in (False, True):
            path = '/http11/held-delayed'
            url = self.url(path, secure)
            with self.subTest(secure=secure), ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.request, url)
                row = self.held(path, secure)
                try:
                    self.assertFalse(pending.done())
                    flow = self.engine.flow(url, 'pending')
                    detail = self.engine.command('detail', id=flow['id'])[1]
                    self.assertEqual(detail['state'], 'pending')
                    snapshot = self.entry(url)
                    self.assertEqual(snapshot['time'], -1)
                    self.assertEqual(snapshot['_lensTiming']['state'], 'pending')
                    if snapshot['_lensTiming']['response'] is not None:
                        self.assertIsNone(snapshot['_lensTiming']['response']['end'])
                finally:
                    row['release'].set()
                response, raw = pending.result(timeout=5)
                self.assertEqual((response.status_code, raw), (200, b''.join(PARTS)))
                self.assertTrue(row['closed'].wait(5))
                final = self.engine.flow(url)
                self.assertEqual(final['state'], 'complete')
                entry = self.entry(url)
                self.assertGreaterEqual(entry['timings']['receive'], 200)
                self.assert_source(entry, b''.join(PARTS), 'HTTP/1.1')
        self.roundtrip('delayed-complete')

    def test_premature_advertised_length_is_error_not_complete(self):
        for secure in (False, True):
            with self.subTest(secure=secure):
                url = self.url('/http11/short-length', secure)
                try:
                    response, _ = self.request(url)
                except httpx.HTTPError as failure:
                    self.assertNotIsInstance(failure, httpx.TimeoutException)
                else:
                    self.assertGreaterEqual(response.status_code, 500)
                flow = self.engine.flow(url, 'error')
                self.assertTrue(flow['error'])
                detail = self.engine.command('detail', id=flow['id'])[1]
                self.assertEqual(detail['state'], 'error')
                entry = self.entry(url)
                self.assertEqual(entry['_lensTiming']['state'], 'error')
                self.assertIsNotNone(entry['_lensError'])
                self.assertIsNotNone(entry['_lensTiming']['error'])
                self.assertIsNone(entry['_lensTiming']['response']['end'])
                self.assertEqual([item['value'] for item in entry['response']['headers']
                                  if item['name'].lower() == 'content-length'], [str(len(BINARY) + 23)])
        self.roundtrip('premature-length')

    def test_stop_interrupts_unfinished_eof_body_without_complete_capture(self):
        path, secure = '/http11/held-stop', True
        url = self.url(path, secure)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, url)
            row = self.held(path, secure)
            try:
                flow = self.engine.flow(url, 'pending')
                self.assertFalse(pending.done())
                self.engine.command('stop_capture')
                with self.assertRaises(httpx.HTTPError):
                    pending.result(timeout=3)
            finally:
                row['release'].set()
            self.assertTrue(row['closed'].wait(5))
        detail = self.engine.command('detail', id=flow['id'])[1]
        self.assertEqual(detail['state'], 'error')
        # Nonpaused transport closure currently reports the SDK disconnect
        # observation; the paused-breakpoint owner's Lens-stop label differs.
        self.assertTrue(detail['error'])
        entry = self.entry(url)
        self.assertEqual(entry['_lensTiming']['state'], 'error')
        self.assertIsNone(entry['_lensTiming']['response']['end'])
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', self.engine.port), timeout=.5)
        self.assertIsNone(self.engine.process.poll(), 'Stopped session owner remains available for inspection')
        self.roundtrip('stopped-eof')
        self.engine.close()
        self.assertEqual(self.engine.process.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
