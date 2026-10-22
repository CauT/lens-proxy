"""Actual loopback SYN-queue waits verify selected deadlines, errors and recovery."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import httpx
from test_e2e import EngineHarness
from test_protocols import protocol_certificates
from test_network_features import free_port
from connection_deadline_fixture import SaturatedListener


class ConnectionDeadlineAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory(prefix='lens-connect-ca-')
        cls.addClassCleanup(cls.certificates.cleanup)
        cls.ca, _, _ = protocol_certificates(Path(cls.certificates.name))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lens-connect-wire-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.blocked = SaturatedListener()
        self.addCleanup(self.blocked.close)

    def engine(self, **initial):
        engine = EngineHarness(self.directory, self.ca, extra_args=['--initialize-from-stdin'],
            initial_configuration={'network': {'connect_timeout_seconds': 1}, **initial})
        self.addCleanup(engine.close)
        return engine

    @staticmethod
    def request(engine, url):
        with httpx.Client(proxy=engine.proxy, trust_env=False, timeout=8) as client:
            return client.get(url)

    def test_real_tcp_deadline_is_visible_in_capture_and_retained_har(self):
        engine = self.engine()
        url = f'http://127.0.0.1:{self.blocked.address[1]}/connection-timeout'
        started = time.monotonic(); response = self.request(engine, url)
        self.assertEqual(response.status_code, 502)
        self.assertLess(time.monotonic() - started, 3)
        flow = engine.flow(url, state='error')
        self.assertIn('DNS/TCP connection timed out after 1 s', flow['error'])
        _, status = engine.command('network_status')
        self.assertEqual(status['sdk']['pending_connects'], 0)
        path = self.directory / 'timeout.har'
        engine.command('save_har', path=str(path))
        document = json.loads(path.read_text())
        engine.command('stop_capture'); engine.command('clear')
        after = len(engine.events)
        engine.command('load_har', path=str(path))
        restored = engine.flow(url, state='error', after=after)
        self.assertEqual(restored['error'], flow['error'])
        _, exported = engine.command('export_har'); self.assertEqual(exported, document)

    def test_live_update_keeps_current_attempt_deadline_and_changes_next_attempt(self):
        engine = self.engine()
        base = f'http://127.0.0.1:{self.blocked.address[1]}'
        with ThreadPoolExecutor(max_workers=1) as pool:
            started = time.monotonic(); pending = pool.submit(self.request, engine, base+'/first')
            while True:
                _, status = engine.command('network_status')
                if status['sdk']['pending_connects'] == 1:break
                self.assertLess(time.monotonic()-started, 2);time.sleep(.01)
            engine.command('configure', rules=[], network={'connect_timeout_seconds': 3})
            self.assertEqual(pending.result(timeout=4).status_code, 502)
            self.assertLess(time.monotonic()-started, 2.7)
        self.assertIn('after 1 s', engine.flow(base+'/first', state='error')['error'])
        started = time.monotonic();self.assertEqual(self.request(engine, base+'/second').status_code,502)
        self.assertGreaterEqual(time.monotonic()-started,2.8)
        self.assertIn('after 3 s',engine.flow(base+'/second', state='error')['error'])
        engine.command('configure',rules=[],network={'upload_kbps':0,'download_kbps':0})
        _, status=engine.command('network_status');self.assertEqual(status['connect_timeout_seconds'],3)

    def test_established_http_response_can_take_longer_than_connection_timeout(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_GET(self):
                time.sleep(1.2);self.send_response(200);self.send_header('Content-Length','10');self.end_headers();self.wfile.write(b'late reply')
        origin=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=origin.serve_forever);worker.start()
        try:
            engine=self.engine();response=self.request(engine,f'http://127.0.0.1:{origin.server_port}/slow-response')
            self.assertEqual((response.status_code,response.content),(200,b'late reply'))
            _, status=engine.command('network_status');self.assertEqual(status['sdk']['pending_connects'],0)
        finally:
            origin.shutdown();origin.server_close();worker.join(3);self.assertFalse(worker.is_alive())

    def test_raw_tcp_forwarding_uses_same_selected_deadline(self):
        port=free_port();engine=self.engine(tcp_forwards=[{'listen_port':port,'target_host':'127.0.0.1','target_port':self.blocked.address[1]}])
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            self.assertEqual(client.recv(1),b'')
        stream=engine.wait(lambda event:event.get('event')=='tcp_stream' and event['stream']['state']=='error')['stream']
        self.assertIn('TCP DNS/connection timed out after 1 s',stream['error'])
        engine.command('stop_capture')
        _, status=engine.command('network_status');self.assertEqual(status['pending_cleanup'],0)
