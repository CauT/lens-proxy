"""Actual proxy close/rename/recovery with live HTTP and TCP/UDP clients."""
import base64
import json
from pathlib import Path
import socket
import socketserver
import threading
import time

from test_e2e import EngineHarness
from test_session_workflows import SessionFixture


class SessionLifecycleWire(SessionFixture):
    def test_named_close_copy_restores_exact_entries_and_keeps_other_session_live(self):
        self.request('/old', b'\0\xfforiginal')
        old = self.engine.flow(self.url + '/old')
        self.engine.command('rename_session', session_id='default', name='API 中文')
        current = self.engine.command('new_session')[1]['capture_session_id']
        self.request('/other', b'other')
        before = {identity: self.entries(identity) for identity in ('default', current)}
        copy = self.directory / 'close-copy.lens.json'
        result = self.engine.command('close_session', session_id='default', backup_path=str(copy))[1]
        self.assertEqual([room['id'] for room in result['sessions']], [current])
        self.assertEqual(result['capture_session_id'], current)
        self.request('/still-live')
        self.assertEqual(len(self.entries(current)), 2)
        inspection = self.directory / 'inspection'; inspection.mkdir()
        restored = EngineHarness(inspection, None, inspect_workspace=copy)
        try:
            self.assertEqual(restored.ready['sessions'][0]['name'], 'API 中文')
            self.assertTrue(restored.ready['capture_stopped'])
            for identity, expected in before.items():
                self.assertEqual(restored.command('export_har', session_id=identity)[1]['log']['entries'], expected)
            detail = restored.command('detail', session_id='default', id=old['id'])[1]
            self.assertEqual(base64.b64decode(detail['request_body_base64']), b'\0\xfforiginal')
        finally: restored.close()
        self.assertEqual(copy.stat().st_mode & 0o777, 0o600)

    def test_close_paused_repeat_joins_job_while_other_session_and_listener_continue(self):
        self.request('/repeat')
        source = self.engine.flow(self.url + '/repeat')
        self.engine.configure([{'kind': 'breakpoint_request', 'match': self.url + '/repeat', 'timeout_seconds': 30}])
        job = self.engine.command('repeat', session_id='default', id=source['id'], count=20, concurrency=1, interval_ms=1000)[1]
        self.engine.wait(lambda event: event.get('event') == 'flow' and event['flow']['id'] != source['id'] and event['flow']['state'] == 'paused')
        current = self.engine.command('new_session')[1]['capture_session_id']
        self.request('/other')
        started = time.monotonic()
        self.engine.command('close_session', session_id='default', discard=True)
        self.assertLess(time.monotonic() - started, 5)
        done = self.engine.wait(lambda event: event.get('event') == 'repeat_done' and event.get('job_id') == job['job_id'])
        self.assertEqual(done['state'], 'cancelled'); self.assertGreater(done['cancelled'], 0)
        self.request('/healthy-after-close')
        self.assertEqual(len(self.entries(current)), 2)
        self.engine.command('stop_capture')
        status = self.engine.command('network_status')[1]
        self.assertFalse(status['public_listeners']); self.assertFalse(status['internal_listeners'])

    def test_split_upload_continues_without_reappearing_after_its_session_closes(self):
        url = self.url + '/late-body'
        with socket.create_connection(('127.0.0.1', self.engine.port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(f'POST {url} HTTP/1.1\r\nHost: 127.0.0.1:{self.origin.server_port}\r\nContent-Length: 4\r\nConnection: close\r\n\r\n'.encode())
            self.engine.wait(lambda event: event.get('event') == 'flow' and event['flow']['url'] == url)
            closed = self.engine.command('close_session', session_id='default', discard=True)[1]
            current = closed['capture_session_id']
            self.assertEqual(closed['sessions'][0]['number'], 2)
            client.sendall(b'late')
            reply = b''
            while data := client.recv(65536): reply += data
            self.assertIn(b'200 OK', reply)
        self.assertFalse(self.entries(current))
        self.request('/new-owner')
        self.assertEqual(len(self.entries(current)), 1)
        closed_again = self.engine.command('close_session', session_id=current, discard=True)[1]
        self.assertEqual(closed_again['sessions'][0]['number'], 3)

    def test_failed_copy_and_invalid_rename_keep_recorded_data_addressable(self):
        self.request('/retained')
        before = self.entries('default')
        identity = self.engine.flow(self.url + '/retained')['id']
        original = self.engine.command('detail', session_id='default', id=identity)[1]
        with self.assertRaisesRegex(AssertionError, 'failed'):
            self.engine.command('rename_session', session_id='default', name='\n')
        self.assertEqual(self.engine.command('session_status')[1]['sessions'][0]['name'], 'Untitled Session 1')
        with self.assertRaisesRegex(AssertionError, 'failed'):
            self.engine.command('close_session', session_id='default', backup_path=str(self.directory / 'missing/copy.json'))
        retained = self.entries('default')
        self.assertEqual(len(retained), len(before))
        # Connection timestamp_end may settle after the completed HTTP message;
        # it is live source evidence, not a frozen byte-preservation invariant.
        for field in ('request', 'response', 'startedDateTime'):
            self.assertEqual(retained[0][field], before[0][field])
        detail = self.engine.command('detail', session_id='default', id=identity)[1]
        for field in ('request_url_base64', 'request_target_base64', 'request_headers_base64',
                      'request_body_base64', 'response_headers_base64', 'response_body_base64'):
            self.assertEqual(detail[field], original[field])
        current = self.engine.command('session_status')[1]['capture_session_id']
        self.assertNotEqual(current, 'default')
        self.request('/continue-after-failed-copy')
        self.assertEqual(len(self.entries(current)), 1)

    def test_live_raw_connections_forward_after_close_without_retaining_late_bytes(self):
        class TCPEcho(socketserver.BaseRequestHandler):
            def handle(self):
                while data := self.request.recv(65536): self.request.sendall(data[::-1])
        class UDPEcho(socketserver.BaseRequestHandler):
            def handle(self):
                data, listener = self.request; listener.sendto(data[::-1], self.client_address)
        tcp_origin = socketserver.ThreadingTCPServer(('127.0.0.1', 0), TCPEcho)
        udp_origin = socketserver.ThreadingUDPServer(('127.0.0.1', 0), UDPEcho)
        for server in (tcp_origin, udp_origin):
            server.daemon_threads = True
            worker = threading.Thread(target=server.serve_forever); worker.start()
            self.addCleanup(worker.join); self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        listeners = []
        for _ in range(2):
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0)); listeners.append(reservation.getsockname()[1])
        directory = self.directory / 'raw'; directory.mkdir()
        raw = EngineHarness(directory, self.ca, extra_args=('--initialize-from-stdin',), initial_configuration={
            'rules': [], 'ssl_hosts': '*', 'tcp_forwards': [{'listen_port': listeners[0], 'target_host': '127.0.0.1', 'target_port': tcp_origin.server_address[1]}],
            'udp_forwards': [{'listen_port': listeners[1], 'target_host': '127.0.0.1', 'target_port': udp_origin.server_address[1]}]})
        self.addCleanup(raw.close)
        copy = directory / 'raw-copy.lens.json'
        with socket.create_connection(('127.0.0.1', listeners[0]), timeout=5) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.settimeout(5); udp.settimeout(5)
            tcp.sendall(b'first TCP'); self.assertEqual(tcp.recv(65536), b'PCT tsrif')
            udp.sendto(b'first UDP', ('127.0.0.1', listeners[1])); self.assertEqual(udp.recv(65536), b'PDU tsrif')
            raw.wait(lambda event: event.get('event') == 'udp_association' and event['association']['received_datagrams'] == 1)
            result = raw.command('close_session', session_id='default', backup_path=str(copy))[1]
            current = result['capture_session_id']; cut = len(raw.events)
            tcp.sendall(b'late TCP'); self.assertEqual(tcp.recv(65536), b'PCT etal')
            udp.sendto(b'late UDP', ('127.0.0.1', listeners[1])); self.assertEqual(udp.recv(65536), b'PDU etal')
            self.assertFalse(raw.command('tcp_status', session_id=current)[1]['streams'])
            self.assertFalse(raw.command('udp_status', session_id=current)[1]['associations'])
            self.assertFalse([event for event in raw.events[cut:] if event.get('session_id') == 'default' and event.get('event') in ('tcp_stream', 'udp_association')])
        raw.command('stop_capture')
        inspection = directory / 'inspection'; inspection.mkdir()
        restored = EngineHarness(inspection, None, inspect_workspace=copy)
        try:
            streams = restored.command('tcp_status', session_id='default')[1]['streams']
            chunks = restored.command('tcp_detail', session_id='default', id=streams[0]['id'])[1]['chunks']
            self.assertEqual(b''.join(base64.b64decode(chunk['base64']) for chunk in chunks if chunk['direction'] == 'send'), b'first TCP')
            associations = restored.command('udp_status', session_id='default')[1]['associations']
            self.assertEqual(associations[0]['sent_datagrams'], 1)
        finally: restored.close()
