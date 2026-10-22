"""Actual WS/WSS byte/type capture, bounded previews and retained paging.

LENS_TEST_ENGINE selects a packaged engine. LENS_WEBSOCKET_DETAILS_DIR optionally
retains synthetic native-detail fixtures and actual HAR files privately.
All clients select the proxy explicitly; host proxy/trust settings are untouched.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest

from test_e2e import EngineHarness, read_exact
from test_protocols import protocol_certificates


PREVIEW = 4096
RETENTION = 32 * 1024 * 1024


def frame(opcode, payload=b'', *, final=True, masked=False):
    head = bytes([(0x80 if final else 0) | opcode])
    flag = 0x80 if masked else 0
    length = len(payload)
    if length < 126:
        head += bytes([flag | length])
    elif length < 65536:
        head += bytes([flag | 126]) + struct.pack('!H', length)
    else:
        head += bytes([flag | 127]) + struct.pack('!Q', length)
    # A deterministic all-zero client mask remains a valid masked wire frame.
    return head + (b'\0' * 4 if masked else b'') + payload


def receive_frame(stream):
    head = read_exact(stream, 2)
    length = head[1] & 127
    if length == 126:
        length = struct.unpack('!H', read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack('!Q', read_exact(stream, 8))[0]
    if length > 40 * 1024 * 1024:
        raise ValueError('Fixture frame exceeds its explicit 40 MiB limit')
    mask = read_exact(stream, 4) if head[1] & 128 else None
    payload = read_exact(stream, length)
    if mask and mask != b'\0' * 4:
        payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
    return head[0] & 15, bool(head[0] & 0x80), payload


class WebSocketOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.connection.settimeout(20)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        accept = base64.b64encode(hashlib.sha1(
            (self.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()
        ).digest()).decode()
        self.send_response(101)
        self.send_header('Connection', 'Upgrade')
        self.send_header('Upgrade', 'websocket')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        pending, kind = bytearray(), None
        try:
            while True:
                opcode, final, payload = receive_frame(self.rfile)
                if opcode == 8:
                    self.wfile.write(frame(8, payload))
                    self.wfile.flush()
                    break
                if opcode == 9:
                    self.wfile.write(frame(10, payload))
                    self.wfile.flush()
                    continue
                if opcode in (1, 2):
                    kind = opcode
                    pending = bytearray()
                elif opcode != 0 or kind is None:
                    raise ValueError('Invalid owned fixture continuation')
                pending.extend(payload)
                if not final:
                    continue
                payload = bytes(pending)
                with self.server.history_lock:
                    self.server.history.append((self.path, kind, payload))
                if self.path == '/fragmented':
                    cut = max(1, len(payload) // 2)
                    self.wfile.write(frame(kind, payload[:cut], final=False))
                    self.wfile.write(frame(0, payload[cut:]))
                else:
                    self.wfile.write(frame(kind, payload))
                self.wfile.flush()
                pending, kind = bytearray(), None
        except (EOFError, OSError):
            pass
        finally:
            self.close_connection = True


class WireClient:
    def __init__(self, engine, server, secure):
        self.socket = socket.create_connection(('127.0.0.1', engine.port), timeout=20)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.stream = None
        self.engine, self.server, self.secure = engine, server, secure

    def upgrade(self, path):
        host = 'localhost' if self.secure else '127.0.0.1'
        authority = f'{host}:{self.server.server_port}'
        self.url = f'{"https" if self.secure else "http"}://{authority}{path}'
        if self.secure:
            self.socket.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
            head = bytearray()
            while not head.endswith(b'\r\n\r\n'):
                chunk = self.socket.recv(1)
                if not chunk:
                    raise EOFError('CONNECT response ended before its header terminator')
                head.extend(chunk)
                if len(head) > 65536:
                    raise AssertionError('CONNECT response exceeded header limit')
            if b' 200 ' not in head.split(b'\r\n')[0]:
                raise AssertionError(f'CONNECT failed: {head!r}')
            context = ssl.create_default_context(cafile=self.engine.ready['ca_cert'])
            self.socket = context.wrap_socket(self.socket, server_hostname=host)
        self.stream = self.socket.makefile('rb')
        key = base64.b64encode(b'Lens-owned-ws-01').decode()
        target = path if self.secure else self.url
        self.socket.sendall((f'GET {target} HTTP/1.1\r\nHost: {authority}\r\n'
                             'Connection: Upgrade\r\nUpgrade: websocket\r\n'
                             'Sec-WebSocket-Version: 13\r\n'
                             f'Sec-WebSocket-Key: {key}\r\n\r\n').encode())
        status = self.stream.readline()
        if b' 101 ' not in status:
            raise AssertionError(f'Upgrade failed: {status!r}')
        while True:
            line = self.stream.readline()
            if line == b'\r\n':
                break
            if not line:
                raise AssertionError('Upgrade ended before header terminator')
        return self

    def send(self, opcode, payload, *, fragmented=False):
        if fragmented:
            cut = max(1, len(payload) // 2)
            self.socket.sendall(frame(opcode, payload[:cut], final=False, masked=True)
                                + frame(0, payload[cut:], masked=True))
        else:
            self.socket.sendall(frame(opcode, payload, masked=True))
        pending, kind = bytearray(), None
        while True:
            received, final, part = receive_frame(self.stream)
            if received in (1, 2):
                kind = received
            elif received != 0:
                raise AssertionError(f'Unexpected data opcode {received}')
            pending.extend(part)
            if final:
                return kind, bytes(pending)

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        self.socket.close()

    def normal_close(self):
        self.socket.sendall(frame(8, b'\x03\xe8', masked=True))
        opcode, _, body = receive_frame(self.stream)
        if opcode != 8 or body != b'\x03\xe8':
            raise AssertionError('Normal WS close handshake did not return code 1000')
        self.close()


class WebSocketCaptureAcceptance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lens-websocket-wire-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(self.directory)
        self.servers = []
        for secure in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), WebSocketOrigin)
            server.history, server.history_lock = [], threading.Lock()
            self.addCleanup(server.server_close)
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, name='owned-websocket-origin')
            worker.start()
            self.addCleanup(self.close_origin, server, worker)
            self.servers.append(server)
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)

    @staticmethod
    def close_origin(server, worker):
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError('Owned WebSocket origin did not join')

    def client(self, path='/messages', secure=False):
        client = WireClient(self.engine, self.servers[int(secure)], secure)
        self.addCleanup(client.close)
        return client.upgrade(path)

    def detail(self, client, count):
        flow = self.engine.flow(client.url)
        deadline = time.monotonic() + 10
        while True:
            detail = self.engine.command('detail', id=flow['id'])[1]
            if detail.get('messages_total') == count:
                return detail
            if time.monotonic() >= deadline:
                self.fail(f'Expected {count} retained messages, got {detail.get("messages_total")}')
            time.sleep(.01)

    def retain(self, name, detail):
        selected = os.environ.get('LENS_WEBSOCKET_DETAILS_DIR')
        if selected:
            folder = Path(selected).resolve()
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = folder / f'{name}.json'
            with path.open('w') as handle:
                os.chmod(path, 0o600)
                json.dump(detail, handle, ensure_ascii=False)
            self.engine.command('save_har', path=str(folder / f'{name}.har'))

    def assert_message(self, message, payload, opcode, direction, index):
        self.assertEqual(base64.b64decode(message['content_base64'], validate=True), payload[:PREVIEW])
        self.assertEqual(message['content_bytes'], len(payload))
        self.assertEqual(message['preview_truncated'], len(payload) > PREVIEW)
        self.assertEqual(message['opcode'], opcode)
        self.assertEqual(message['direction'], direction)
        self.assertEqual(message['index'], index)
        self.assertIs(message['dropped'], False)
        self.assertIs(message['injected'], False)

    def test_http_text_binary_empty_and_opcode_identity(self):
        client = self.client()
        payloads = [(1, 'Hello 世界'.encode()), (2, b'valid UTF-8 stays binary'),
                    (2, b'\x00\xff\xc0\xaf'), (2, b'')]
        for opcode, payload in payloads:
            self.assertEqual(client.send(opcode, payload), (opcode, payload))
        client.normal_close()
        detail = self.detail(client, 8)
        for i, (opcode, payload) in enumerate(payloads):
            for side, direction in enumerate(('send', 'receive')):
                self.assert_message(detail['messages'][2 * i + side], payload, opcode, direction, 2 * i + side)
        self.assertEqual([(o, p) for _, o, p in self.servers[0].history], payloads)
        self.retain('plain', detail)

    def test_strict_wss_both_directions(self):
        client = self.client('/strict-wss', secure=True)
        self.assertIsNotNone(client.socket.getpeercert())
        for opcode, payload in [(1, 'TLS 文本'.encode()), (2, b'\xff\x00secure')]:
            self.assertEqual(client.send(opcode, payload), (opcode, payload))
        client.normal_close()
        detail = self.detail(client, 4)
        self.assertEqual([m['opcode'] for m in detail['messages']], [1, 1, 2, 2])
        self.retain('wss', detail)

    def test_fragmentation_is_reassembled_sdk_message_not_frame_count(self):
        client = self.client('/fragmented')
        # The cut at byte 15 splits a UTF-8 scalar; only complete reassembled
        # messages may be interpreted as text by either endpoint or inspector.
        payload = b'A' + '零一二三四五六七八九'.encode()
        self.assertEqual(client.send(1, payload, fragmented=True), (1, payload))
        client.normal_close()
        detail = self.detail(client, 2)
        self.assert_message(detail['messages'][0], payload, 1, 'send', 0)
        self.assert_message(detail['messages'][1], payload, 1, 'receive', 1)
        self.retain('fragmented', detail)

    def test_preview_limit_full_har_stop_reopen(self):
        client = self.client('/large-preview')
        payload = bytes(range(256)) * 48 + b'\x00\xfftail'
        self.assertEqual(client.send(2, payload), (2, payload))
        client.normal_close()
        detail = self.detail(client, 2)
        for i, direction in enumerate(('send', 'receive')):
            self.assert_message(detail['messages'][i], payload, 2, direction, i)
        self.engine.command('stop_capture')
        self.assertEqual(self.engine.command('detail', id=detail['id'])[1], detail)
        path = self.directory / 'full.har'
        self.engine.command('save_har', path=str(path))
        original = json.loads(path.read_text())
        messages = original['log']['entries'][0]['_webSocketMessages']
        self.assertEqual([base64.b64decode(m['data']) for m in messages], [payload, payload])
        self.assertEqual([m['opcode'] for m in messages], [2, 2])
        self.retain('large', detail)
        self.engine.command('clear')
        with self.assertRaises(AssertionError):
            self.engine.command('websocket_messages', id=detail['id'], offset=0, limit=50)
        after = len(self.engine.events)
        self.engine.command('load_har', path=str(path))
        restored = self.engine.flow(client.url, after=after)
        reopened = self.engine.command('detail', id=restored['id'])[1]
        self.assertEqual(reopened['messages'], detail['messages'])
        saved = self.directory / 'reopened.har'
        self.engine.command('save_har', path=str(saved))
        self.assertEqual(json.loads(saved.read_text()), original)
        self.retain('reopened', reopened)

    def test_bounded_paging_and_stale_generation(self):
        client = self.client('/paging')
        expected = []
        for i in range(61):
            payload = f'message-{i:03}'.encode()
            self.assertEqual(client.send(2, payload), (2, payload))
            expected.extend([payload, payload])
        detail = self.detail(client, 122)
        self.assertEqual(len(detail['messages']), 50)
        self.assertEqual(detail['messages_offset'], 0)
        self.assertEqual(detail['messages_limit'], 50)
        self.assertEqual(detail['messages_next_offset'], 50)
        generation, offset, collected = detail['messages_generation'], 0, []
        while offset is not None:
            page = self.engine.command('websocket_messages', id=detail['id'], offset=offset,
                                       limit=23, generation=generation)[1]
            self.assertLessEqual(len(page['messages']), 23)
            self.assertEqual(page['generation'], generation)
            self.assertEqual(page['total'], 122)
            collected.extend(page['messages'])
            offset = page['next_offset']
        self.assertEqual([m['index'] for m in collected], list(range(122)))
        self.assertEqual([base64.b64decode(m['content_base64']) for m in collected], expected)
        for fields in ({'offset': -1, 'limit': 1}, {'offset': 0, 'limit': 51},
                       {'offset': True, 'limit': 1}, {'offset': 0, 'limit': 0}):
            with self.assertRaises(AssertionError):
                self.engine.command('websocket_messages', id=detail['id'], **fields)
        self.retain('paged', detail)
        self.assertEqual(client.send(1, b'new generation'), (1, b'new generation'))
        latest = self.detail(client, 124)
        self.assertGreater(latest['messages_generation'], generation)
        with self.assertRaisesRegex(AssertionError, 'generation|changed|stale'):
            self.engine.command('websocket_messages', id=detail['id'], offset=50,
                                limit=50, generation=generation)
        client.normal_close()

    def test_stop_closes_active_socket_retains_messages_and_clear_removes_owner(self):
        client = self.client('/active-stop')
        self.assertEqual(client.send(1, b'retained before stop'), (1, b'retained before stop'))
        detail = self.detail(client, 2)
        self.engine.command('stop_capture')
        with self.assertRaises((EOFError, OSError)):
            receive_frame(client.stream)
        client.close()
        self.assertIsNone(self.engine.process.poll(), 'Stopped session owner must remain inspectable')
        self.assertEqual(self.engine.command('detail', id=detail['id'])[1]['messages'], detail['messages'])
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', self.engine.port), timeout=.5)
        self.retain('stopped', self.engine.command('detail', id=detail['id'])[1])
        self.engine.command('clear')
        with self.assertRaises(AssertionError):
            self.engine.command('websocket_messages', id=detail['id'], offset=0, limit=1)

    def test_count_retention_keeps_latest_2000_messages_with_disclosure(self):
        client = self.client('/count-retention')
        for i in range(1005):
            payload = str(i).encode()
            self.assertEqual(client.send(2, payload), (2, payload))
        detail = self.detail(client, 2000)
        self.assertIs(detail['messages_truncated'], True)
        self.assertEqual(base64.b64decode(detail['messages'][0]['content_base64']), b'5')
        page = self.engine.command('websocket_messages', id=detail['id'], offset=1998, limit=2)[1]
        self.assertEqual([base64.b64decode(m['content_base64']) for m in page['messages']], [b'1004'] * 2)
        self.assertIs(page['retention_truncated'], True)
        client.normal_close()

    def test_har_duplicate_timestamps_and_legacy_unknown_metadata(self):
        client = self.client('/historical')
        self.assertEqual(client.send(2, b'UTF-8 binary history'), (2, b'UTF-8 binary history'))
        client.normal_close()
        self.detail(client, 2)
        document = self.engine.command('export_har')[1]
        entry = document['log']['entries'][0]
        entry.pop('_webSocketMessagesTruncated', None)
        messages = entry['_webSocketMessages']
        for message in messages:
            message['time'] = 0
        messages[0].update(opcode=2, dropped=True, injected=True,
                           fixture_metadata={'source': 'explicit historical annotation'})
        for key in ('opcode', 'dropped', 'injected'):
            messages[1].pop(key, None)
        path = self.directory / 'historical.har'
        path.write_text(json.dumps(document))
        self.engine.command('stop_capture')
        self.engine.command('clear')
        after = len(self.engine.events)
        self.engine.command('load_har', path=str(path))
        flow = self.engine.flow(client.url, after=after)
        detail = self.engine.command('detail', id=flow['id'])[1]
        self.assertEqual(detail['messages_total'], 2)
        self.assertIsNone(detail['messages_truncated'], 'Legacy absent retention coverage remains unknown')
        page = self.engine.command('websocket_messages', id=flow['id'], offset=0, limit=50)[1]
        self.assertIsNone(page['retention_truncated'])
        self.assertEqual(page['messages'], detail['messages'])
        self.assertEqual([m['timestamp'] for m in detail['messages']], [0, 0])
        self.assertEqual([m['index'] for m in detail['messages']], [0, 1])
        self.assertEqual([m['opcode'] for m in detail['messages']], [2, None])
        self.assertEqual([m['dropped'] for m in detail['messages']], [True, None])
        self.assertEqual([m['injected'] for m in detail['messages']], [True, None])
        saved = self.directory / 'historical-reexport.har'
        self.engine.command('save_har', path=str(saved))
        restored_entry = json.loads(saved.read_text())['log']['entries'][0]
        self.assertNotIn('_webSocketMessagesTruncated', restored_entry)
        restored = restored_entry['_webSocketMessages']
        self.assertEqual(restored, messages, 'Legacy unknowns and extra source metadata must survive')
        self.retain('historical', detail)

    def test_byte_retention_evicts_old_messages_without_changing_wire(self):
        client = self.client('/byte-retention')
        payload = b'\x00\xff' * (6 * 1024 * 1024)
        for _ in range(3):
            self.assertEqual(client.send(2, payload), (2, payload))
        detail = self.detail(client, 2)
        self.assertIs(detail['messages_truncated'], True)
        self.assertLessEqual(sum(m['content_bytes'] for m in detail['messages']), RETENTION)
        for i, direction in enumerate(('send', 'receive')):
            self.assert_message(detail['messages'][i], payload, 2, direction, i)
        client.normal_close()

    def test_single_oversized_message_is_capture_omission_not_wire_drop(self):
        client = self.client('/oversized')
        payload = b'\xff' * (RETENTION + 1)
        self.assertEqual(client.send(2, payload), (2, payload))
        client.normal_close()
        detail = self.detail(client, 0)
        self.assertIs(detail['messages_truncated'], True)
        self.assertEqual(detail['messages'], [])
        self.assertEqual(self.servers[0].history[0][2], payload)


if __name__ == '__main__':
    unittest.main(verbosity=2)
