"""Real proxy/control workflow acceptance for independent recording sessions."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import tempfile
import unittest

import httpx
from test_e2e import EngineHarness, certificate_fixture, start_fixture


class SessionFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lens-sessions-wire-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        ca, _, _ = certificate_fixture(self.directory, 'sessions')
        self.ca = ca
        self.origin, self.worker = start_fixture('session origin')
        self.addCleanup(self.worker.join)
        self.addCleanup(self.origin.server_close)
        self.addCleanup(self.origin.shutdown)
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)
        self.url = f'http://127.0.0.1:{self.origin.server_port}'

    def request(self, path, content=b'body'):
        with httpx.Client(proxy=self.engine.proxy, trust_env=False, timeout=10) as client:
            response = client.post(self.url + path, content=content)
            response.raise_for_status()
            return response

    def entries(self, room):
        return self.engine.command('export_har', session_id=room)[1]['log']['entries']


class SessionWorkflows(SessionFixture):
    def test_new_session_at_headers_preserves_inflight_body_and_shared_proxy_identity(self):
        old_url = self.url + '/old-split-body'
        with socket.create_connection(('127.0.0.1', self.engine.port), timeout=5) as client:
            client.settimeout(5)
            client.sendall(f'POST {old_url} HTTP/1.1\r\nHost: 127.0.0.1:{self.origin.server_port}\r\nContent-Length: 4\r\nConnection: close\r\n\r\n'.encode())
            admitted = self.engine.wait(lambda event: event.get('event') == 'flow' and event['flow']['url'] == old_url)['flow']
            self.assertEqual(admitted['session_id'], 'default')
            self.assertFalse(admitted['request_body_available'])
            self.engine.command('recording', enabled=False)
            catalog = self.engine.command('new_session')[1]
            room = catalog['capture_session_id']
            self.assertTrue(catalog['recording'])
            self.assertEqual(catalog['sessions'][1]['name'], 'Untitled Session 2')
            client.sendall(b'\x00\xffOK')
            received = b''
            while chunk := client.recv(65536): received += chunk
            self.assertIn(b'200 OK', received)
        self.request('/new-complete', b'new')
        old = self.engine.flow(old_url)
        new = self.engine.flow(self.url + '/new-complete')
        self.assertEqual(old['session_id'], 'default'); self.assertEqual(new['session_id'], room)
        self.assertEqual(base64.b64decode(self.entries('default')[0]['request']['postData']['text']), b'\x00\xffOK')
        self.assertEqual(len(self.entries(room)), 1)
        self.assertEqual(self.engine.command('session_status')[1]['capture_session_id'], room)
        # Viewing/exporting an old session never recreates a listener or CA.
        self.assertTrue(Path(self.engine.ready['ca_cert']).is_file())
        self.engine.command('clear', session_id=room)
        self.assertFalse(self.entries(room)); self.assertEqual(len(self.entries('default')), 1)

    def test_old_breakpoint_and_replay_repeat_stay_with_their_source_session(self):
        url = self.url + '/old-paused'
        self.engine.configure([{'kind': 'breakpoint_request', 'match': url, 'timeout_seconds': 30}])
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(self.request, '/old-paused')
            paused = self.engine.flow(url, state='paused')
            room = self.engine.command('new_session')[1]['capture_session_id']
            self.engine.configure([])
            self.engine.command('resume', session_id='default', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='discard')
            self.assertEqual(pending.result(timeout=5).status_code, 200)
        self.engine.flow(url)
        replay, _ = self.engine.command('replay', session_id='default', id=paused['id'])
        finished = self.engine.wait(lambda event: event.get('event') == 'request_finished' and event.get('command_id') == replay)
        self.assertEqual(finished['session_id'], 'default')
        repeat = self.engine.command('repeat', session_id='default', id=paused['id'], count=2, concurrency=1, interval_ms=0)[1]
        done = self.engine.wait(lambda event: event.get('event') == 'repeat_done' and event.get('job_id') == repeat['job_id'])
        self.assertEqual(done['session_id'], 'default'); self.assertEqual(done['completed'], 2)
        self.assertEqual(len(self.entries('default')), 4); self.assertFalse(self.entries(room))

    def test_atomic_workspace_reopens_all_sessions_without_listeners_or_new_ca(self):
        self.request('/first', b'\x00\xfffirst')
        first_id = self.engine.flow(self.url + '/first')['id']
        room = self.engine.command('new_session')[1]['capture_session_id']
        self.request('/second', b'second')
        before = {identity: self.entries(identity) for identity in ('default', room)}
        self.engine.command('stop_capture')
        path = self.directory / 'workspace.lens.json'
        self.engine.command('save_workspace', path=str(path))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        other_dir = self.directory / 'inspection'; other_dir.mkdir()
        reopened = EngineHarness(other_dir, None, inspect_workspace=path)
        try:
            self.assertTrue(reopened.ready['capture_stopped'])
            self.assertEqual(reopened.ready['capture_session_id'], room)
            self.assertFalse((other_dir / 'engine-state' / 'mitmproxy-ca.pem').exists())
            with self.assertRaises(ConnectionRefusedError): socket.create_connection(('127.0.0.1', reopened.port), timeout=.5)
            for identity, entries in before.items():
                self.assertEqual(reopened.command('export_har', session_id=identity)[1]['log']['entries'], entries)
            detail = reopened.command('detail', session_id='default', id=first_id)[1]
            self.assertEqual(base64.b64decode(detail['request_body_base64']), b'\x00\xfffirst')
        finally: reopened.close()
        self.assertEqual(reopened.process.returncode, 0)

    def test_open_har_creates_an_independent_view_and_failed_open_keeps_catalog(self):
        self.request('/original')
        path = self.directory / 'old.har'
        self.engine.command('save_har', session_id='default', path=str(path))
        room = self.engine.command('new_session')[1]['capture_session_id']
        catalog = self.engine.command('open_session', path=str(path))[1]
        self.assertEqual(catalog['capture_session_id'], room)
        opened = catalog['view_session_id']; self.assertNotEqual(opened, room)
        self.assertEqual(self.entries(opened), json.loads(path.read_text())['log']['entries'])
        self.assertEqual(len(self.entries('default')), 1); self.assertFalse(self.entries(room))
        before = self.engine.command('session_status')[1]
        path.write_text('{invalid')
        with self.assertRaisesRegex(AssertionError, 'failed'): self.engine.command('open_session', path=str(path))
        self.assertEqual(self.engine.command('session_status')[1], before)
        self.assertEqual(len(self.entries('default')), 1)

    def test_existing_tcp_and_udp_owners_keep_their_session_across_new_session(self):
        import socketserver
        import threading
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                payload, listener = self.request
                listener.sendto(payload[::-1], self.client_address)
        udp_origin = socketserver.ThreadingUDPServer(('127.0.0.1', 0), Echo)
        udp_origin.daemon_threads = True
        worker = threading.Thread(target=udp_origin.serve_forever)
        worker.start()
        self.addCleanup(worker.join); self.addCleanup(udp_origin.server_close); self.addCleanup(udp_origin.shutdown)
        reservations = [socket.socket() for _ in range(2)]
        try:
            for value in reservations: value.bind(('127.0.0.1', 0))
            tcp_port, udp_port = (value.getsockname()[1] for value in reservations)
        finally:
            for value in reservations: value.close()
        directory = self.directory / 'raw'; directory.mkdir()
        raw = EngineHarness(directory, self.ca, extra_args=('--initialize-from-stdin',), initial_configuration={
            'rules': [], 'ssl_hosts': '*', 'tcp_forwards': [{'listen_port': tcp_port, 'target_host': '127.0.0.1', 'target_port': self.origin.server_port}],
            'udp_forwards': [{'listen_port': udp_port, 'target_host': '127.0.0.1', 'target_port': udp_origin.server_address[1]}]})
        self.addCleanup(raw.close)
        with socket.create_connection(('127.0.0.1', tcp_port), timeout=5) as old_tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old_udp:
            old_tcp.settimeout(5); old_udp.settimeout(5)
            old_stream = raw.wait(lambda event: event.get('event') == 'tcp_stream' and event['stream']['state'] == 'open')['stream']['id']
            old_udp.sendto(b'old UDP', ('127.0.0.1', udp_port)); self.assertEqual(old_udp.recv(65536), b'PDU dlo')
            raw.wait(lambda event: event.get('event') == 'udp_association' and event['association']['received_datagrams'] == 1)
            room = raw.command('new_session')[1]['capture_session_id']
            request = b'POST /raw-old HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nlate'
            old_tcp.sendall(request); old_tcp.shutdown(socket.SHUT_WR)
            reply = b''
            while chunk := old_tcp.recv(65536): reply += chunk
            self.assertIn(b'200 OK', reply)
            old_udp.sendto(b'late UDP', ('127.0.0.1', udp_port)); self.assertEqual(old_udp.recv(65536), b'PDU etal')
            with socket.create_connection(('127.0.0.1', tcp_port), timeout=5) as new_tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new_udp:
                new_tcp.settimeout(5); new_udp.settimeout(5)
                new_tcp.sendall(request.replace(b'raw-old', b'raw-new')); new_tcp.shutdown(socket.SHUT_WR)
                while new_tcp.recv(65536): pass
                new_udp.sendto(b'new UDP', ('127.0.0.1', udp_port)); self.assertEqual(new_udp.recv(65536), b'PDU wen')
        raw.command('stop_capture')
        first = raw.command('tcp_status', session_id='default')[1]['streams']
        second = raw.command('tcp_status', session_id=room)[1]['streams']
        self.assertEqual([value['id'] for value in first], [old_stream]); self.assertEqual(len(second), 1)
        chunks = raw.command('tcp_detail', session_id='default', id=old_stream)[1]['chunks']
        self.assertEqual(b''.join(base64.b64decode(chunk['base64']) for chunk in chunks if chunk['direction'] == 'send'), request)
        self.assertEqual(b''.join(base64.b64decode(chunk['base64']) for chunk in chunks if chunk['direction'] == 'receive'), reply)
        old_associations = raw.command('udp_status', session_id='default')[1]['associations']
        new_associations = raw.command('udp_status', session_id=room)[1]['associations']
        self.assertEqual(len(old_associations), 1); self.assertEqual(len(new_associations), 1)
        self.assertEqual(old_associations[0]['sent_datagrams'], 2); self.assertEqual(new_associations[0]['sent_datagrams'], 1)
        path = directory / 'raw-workspace.lens.json'; raw.command('save_workspace', path=str(path))
        inspection = directory / 'inspection'; inspection.mkdir()
        reopened = EngineHarness(inspection, None, inspect_workspace=path)
        try:
            for identity in ('default', room):
                for command, field in (('tcp_status', 'streams'), ('udp_status', 'associations')):
                    self.assertEqual([v['id'] for v in reopened.command(command, session_id=identity)[1][field]], [v['id'] for v in raw.command(command, session_id=identity)[1][field]])
        finally: reopened.close()
