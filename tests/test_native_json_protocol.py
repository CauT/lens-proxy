"""Real JSONL producer, HTTP byte boundaries and opt-in native projections."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import uuid

from test_e2e import EngineHarness, certificate_fixture

BODY = b'whole native response\0\xff'


def original_message(envelope):
    message = copy.deepcopy(envelope['message'])
    for record in reversed(envelope['source_text']):
        source = base64.b64decode(record['utf8_surrogatepass_base64'], validate=True).decode('utf-8', 'surrogatepass')
        path = record['path']
        target = message
        for component in path[:-1]:
            target = target[component]
        if record['kind'] == 'key':
            target[source] = target.pop(path[-1])
        else:
            target[path[-1]] = source
    return message


class NativeHarness(EngineHarness):
    def __init__(self, *args, **kwargs):
        self.envelopes = []
        super().__init__(*args, extra_args=['--native-json'], **kwargs)

    def read_events(self):
        try:
            for line in self.process.stdout:
                envelope = json.loads(line)
                if set(envelope) != {'native_json', 'message', 'source_text'} or envelope['native_json'] != 1:
                    raise ValueError('Engine did not emit its opt-in native envelope')
                event = original_message(envelope)
                with self.condition:
                    self.envelopes.append(envelope)
                    self.events.append(event)
                    if event.get('event') == 'flow':
                        self.flows[event['flow']['id']] = event['flow']
                    if event.get('event') == 'removed':
                        self.flows.pop(event['id'], None)
                    if event.get('event') == 'fatal':
                        self.failure = 'fatal: ' + event.get('message', 'Proxy failed')
                    self.condition.notify_all()
        except Exception as exc:
            with self.condition:
                self.failure = str(exc)
                self.condition.notify_all()
        finally:
            with self.condition:
                if self.failure is None:
                    self.failure = 'Control stream closed'
                self.condition.notify_all()


class ByteOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def do_GET(self):
        self.respond()
    def do_POST(self):
        self.respond()
    def respond(self):
        data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with self.server.history_lock:
            self.server.history.append({'line': self.raw_requestline,
                'headers': [(k.encode('latin1'), v.encode('latin1')) for k, v in self.headers.raw_items()], 'body': data})
        self.send_response(200, 'Originÿ')
        for name, value in [('Content-Type', 'application/octet-stream; raw=ÿ'), ('X-Raw', 'þ'),
                            ('X-Dup', 'first'), ('X-Dup', 'second'), ('X-Literal', r'\udcff')]:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


setattr(ByteOrigin, 'do_GEÿT', ByteOrigin.respond)


class NativeJSONProtocolAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-native-json-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, _, _ = certificate_fixture(cls.directory, 'native-json')
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), ByteOrigin)
        cls.server.daemon_threads = True
        cls.server.history, cls.server.history_lock = [], threading.Lock()
        cls.addClassCleanup(cls.server.server_close); cls.addClassCleanup(cls.server.shutdown)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.host = f'127.0.0.1:{cls.server.server_port}'
        cls.base = 'http://' + cls.host
        cls.native = NativeHarness(cls.directory, ca)
        cls.addClassCleanup(cls.native.close)
        legacy_directory = cls.directory / 'legacy'; legacy_directory.mkdir()
        cls.legacy = EngineHarness(legacy_directory, ca)
        cls.addClassCleanup(cls.legacy.close)

    def setUp(self):
        self.native.configure([]); self.native.command('clear')
        self.legacy.configure([]); self.legacy.command('clear')

    def raw_request(self, engine, target, method=b'GET', body=b''):
        with socket.create_connection(('127.0.0.1', engine.port), timeout=8) as sock:
            sock.sendall(method + b' ' + target + b' HTTP/1.1\r\nHost: ' + self.host.encode() +
                b'\r\nX-Request-Raw: \xff\r\nX-Dup: \xff\r\nX-Dup: \xc3\xbf\r\nContent-Length: ' +
                str(len(body)).encode() + b'\r\n\r\n' + body)
            response = http.client.HTTPResponse(sock); response.begin()
            status, reason, headers, data = response.status, response.reason, response.getheaders(), response.read()
            response.close()
            return status, reason, headers, data

    def test_non_utf8_headers_method_path_and_body_reach_detail_and_export_without_dropped_events(self):
        path = b'/source-' + uuid.uuid4().hex.encode() + b'/\xff?q=\xfe'
        body = b'complete request\0\xff'
        status, reason, _, response = self.raw_request(self.native, path, method=b'GE\xffT', body=body)
        self.assertEqual((status, reason, response), (200, 'Originÿ', BODY))
        url = self.base + path.decode('utf-8', 'surrogateescape')
        row = self.native.flow(url)
        _, detail = self.native.command('detail', id=row['id'])
        self.assertEqual(base64.b64decode(detail['request_method_base64']), b'GE\xffT')
        self.assertEqual(base64.b64decode(detail['request_target_base64']), path)
        self.assertEqual(base64.b64decode(detail['request_url_base64']), self.base.encode() + path)
        self.assertEqual(base64.b64decode(detail['response_reason_base64']), b'Origin\xff')
        self.assertEqual(detail['response_reason'], 'Originÿ')
        request_fields = [(base64.b64decode(k), base64.b64decode(v)) for k, v in detail['request_headers_base64']]
        self.assertIn((b'X-Request-Raw', b'\xff'), request_fields)
        self.assertEqual([v for k, v in request_fields if k.lower() == b'x-dup'], [b'\xff', b'\xc3\xbf'])
        _, exported = self.native.command('export_body', id=row['id'], side='request', decoded=False,
                                          request_fingerprint=detail['request_fingerprint'])
        self.assertEqual(base64.b64decode(exported['base64']), body)
        _, exported = self.native.command('export_body', id=row['id'], side='response', decoded=False)
        self.assertEqual(base64.b64decode(exported['base64']), BODY)
        self.assertIn('\udcff', exported['mime_type'])
        # The native-facing projection contains visible escapes and complete
        # raw sidecars. Python restores sources here; Swift has its own decoder.
        result = next(envelope for envelope in reversed(self.native.envelopes)
                      if envelope['message'].get('event') == 'result' and 'request_headers_base64' in envelope['message'].get('value', {}))
        self.assertTrue(result['source_text'])
        self.assertIn(r'\udcff', result['message']['value']['path'])
        self.assertEqual(result['message']['value']['request_target_form'], 'relative')

    def test_raw_byte_edits_are_atomic_and_keep_source_fingerprint_guards_body_export(self):
        path = '/editing-' + uuid.uuid4().hex
        url = self.base + path
        self.native.configure([{'kind': 'breakpoint_request', 'match': url}, {'kind': 'breakpoint_response', 'match': url}])
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.raw_request, self.native, path.encode(), b'POST', b'original body')
            first = self.native.flow(url, 'paused')
            _, before = self.native.command('detail', id=first['id'])
            b64 = lambda value: base64.b64encode(value).decode()
            self.native.command('resume', id=first['id'], pause_id=first['pause_id'], stage='request', action='continue',
                request_edit={'headers_base64': [[b64(b'X-Byte-Edit'), b64(b'\x80\xff')]], 'body_base64': b64(b'changed\0\xff')})
            second = self.native.wait(lambda event: event.get('event') == 'flow' and event['flow']['id'] == first['id']
                and event['flow'].get('pause_stage') == 'response')['flow']
            with self.assertRaisesRegex(AssertionError, 'source request changed'):
                self.native.command('export_body', id=first['id'], side='request', decoded=False,
                                    request_fingerprint=before['request_fingerprint'])
            self.native.command('resume', id=second['id'], pause_id=second['pause_id'], stage='response', action='continue',
                response_edit={'headers_base64': [[b64(b'X-Response-Edit'), b64(b'\x81\xfe')]],
                               'reason_base64': b64(b'Edited\xff')})
            status, reason, headers, body = pending.result(timeout=8)
        self.assertEqual((status, reason, body), (200, 'Editedÿ', BODY))
        self.assertIn(('X-Response-Edit', '\x81þ'), headers)
        with self.server.history_lock:
            observed = next(row for row in reversed(self.server.history) if path.encode() in row['line'])
        self.assertIn((b'X-Byte-Edit', b'\x80\xff'), observed['headers'])
        self.assertEqual(observed['body'], b'changed\0\xff')
        final = self.native.flow(url)
        _, detail = self.native.command('detail', id=final['id'])
        self.assertEqual(base64.b64decode(detail['response_reason_base64']), b'Edited\xff')
        _, exported = self.native.command('export_body', id=first['id'], side='request', decoded=False,
                                          request_fingerprint=detail['request_fingerprint'])
        self.assertEqual(base64.b64decode(exported['base64']), b'changed\0\xff')

    def test_legacy_jsonl_source_fields_and_har_are_not_rewritten_by_native_projection(self):
        path = b'/legacy-' + uuid.uuid4().hex.encode()
        self.assertEqual(self.raw_request(self.legacy, path)[0], 200)
        row = self.legacy.flow(self.base + path.decode())
        _, detail = self.legacy.command('detail', id=row['id'])
        self.assertIn(['X-Request-Raw', '\udcff'], [list(pair) for pair in detail['request_headers']])
        self.assertNotIn('native_json', self.legacy.events[-1])
        _, original = self.legacy.command('export_har')
        self.legacy.command('clear'); self.legacy.command('import_har', har=original)
        self.assertEqual(self.legacy.command('export_har')[1], original)
        self.native.command('import_har', har=original)
        self.assertEqual(self.native.command('export_har')[1], original)
        saved = self.directory / 'raw-source.har'
        self.native.command('save_har', path=str(saved))
        self.assertEqual(json.loads(saved.read_text()), original)


if __name__ == '__main__':
    unittest.main()
