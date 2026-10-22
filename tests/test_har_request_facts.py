"""Actual proxy capture -> HAR -> request source identity, with atomic rejection."""
import base64
import copy
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from test_e2e import EngineHarness, certificate_fixture
from test_native_json_protocol import ByteOrigin


class RequestOrigin(ByteOrigin):
    do_OPTIONS = ByteOrigin.respond


class HARRequestFactsAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-har-request-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, _, _ = certificate_fixture(cls.directory, 'request-facts')
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), RequestOrigin)
        cls.server.daemon_threads = True
        cls.server.history, cls.server.history_lock = [], threading.Lock()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)

    def setUp(self):
        self.engine.command('clear')
        self.engine.configure([])

    def capture(self, target, method=b'POST', host=None):
        host = host or f'127.0.0.1:{self.server.server_port}'.encode()
        body = b'raw\0\xffbody'
        start = len(self.engine.events)
        with socket.create_connection(('127.0.0.1', self.engine.port), timeout=8) as sock:
            sock.sendall(method + b' ' + target + b' HTTP/1.1\r\nHost: ' + host
                         + b'\r\nX-Bytes: \xff\r\nX-Dup: first\r\nX-Dup: second\r\n'
                         + b'Content-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 200)
            response.read()
        event = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow']['state'] == 'complete', after=start)
        flow = event['flow']
        _, detail = self.engine.command('detail', id=flow['id'])
        self.assertEqual(flow['request_target_source'], 'capture')
        return flow, detail

    def saved(self, name):
        path = self.directory / name
        self.engine.command('save_har', path=str(path))
        return path, json.loads(path.read_text())

    def reopened(self, path):
        self.engine.command('clear')
        start = len(self.engine.events)
        self.engine.command('load_har', path=str(path))
        flow = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('imported'), after=start)['flow']
        return self.engine.command('detail', id=flow['id'])[1]

    def test_actual_opaque_target_method_headers_body_and_fingerprint_roundtrip(self):
        target = b'/raw\xff?q=\xfe&x=1&x=2'
        flow, detail = self.capture(target, b'GE\xffT')
        path, original = self.saved('opaque.har')
        self.assertEqual(base64.b64decode(original['log']['entries'][0]['_lensRequestFacts']['path_base64']), target)
        restored = self.reopened(path)
        self.assertEqual(restored['request_target_source'], 'har_facts')
        for key in ('request_method_base64', 'request_target_base64', 'request_url_base64', 'request_headers_base64', 'request_fingerprint', 'request_body_base64', 'response_body_base64'):
            self.assertEqual(restored[key], detail[key], key)
        self.assertEqual(self.saved('opaque-again.har')[1], original)
        with self.server.history_lock:
            observed = self.server.history[-1]
        self.assertEqual(observed['line'], b'GE\xffT ' + target + b' HTTP/1.1\r\n')
        self.assertEqual(observed['body'], b'raw\0\xffbody')

    def test_actual_options_asterisk_remains_asterisk(self):
        _, detail = self.capture(b'*', b'OPTIONS')
        path, original = self.saved('asterisk.har')
        restored = self.reopened(path)
        self.assertEqual(base64.b64decode(restored['request_target_base64']), b'*')
        self.assertEqual(restored['request_fingerprint'], detail['request_fingerprint'])
        self.assertEqual(self.saved('asterisk-again.har')[1], original)
        with self.server.history_lock:
            self.assertEqual(self.server.history[-1]['line'], b'OPTIONS * HTTP/1.1\r\n')

    def test_actual_route_is_distinct_from_display_host_after_reopen(self):
        routed = f'http://127.0.0.1:{self.server.server_port}/split?x=1&x=2'
        flow, detail = self.capture(routed.encode(), host=b'shown.test:8443')
        self.assertEqual(flow['url'], 'http://shown.test:8443/split?x=1&x=2')
        self.assertEqual(flow['routed_url'], routed)
        path, original = self.saved('split.har')
        restored = self.reopened(path)
        self.assertEqual(restored['routed_url'], routed)
        self.assertEqual(restored['request_fingerprint'], detail['request_fingerprint'])
        self.assertEqual(self.saved('split-again.har')[1], original)

    def test_legacy_raw_path_is_restored_as_derived_without_inventing_facts(self):
        _, detail = self.capture(b'/legacy\xff?x=1&x=2')
        path, document = self.saved('legacy.har')
        del document['log']['entries'][0]['_lensRequestFacts']
        path.write_text(json.dumps(document))
        restored = self.reopened(path)
        self.assertEqual(restored['request_target_source'], 'har_url')
        self.assertEqual(restored['request_target_base64'], detail['request_target_base64'])
        self.assertEqual(restored['request_headers_base64'], detail['request_headers_base64'])
        self.assertEqual(self.saved('legacy-again.har')[1], document)

    def test_late_invalid_request_facts_reject_entire_import_and_preserve_file(self):
        flow, detail = self.capture(b'/existing')
        path, document = self.saved('existing.har')
        original_file = path.read_bytes()
        source = document['log']['entries'][0]
        for label, mutate, message in (
            ('version', lambda v: v.update(version=2), 'version'),
            ('contradiction', lambda v: v.update(path_base64='L290aGVy'), 'contradicts'),
            ('base64', lambda v: v.update(path_base64='Lx=='), 'canonical'),
            ('late-budget', lambda v: v.update(http_version_base64='A' * (16 * 1024 * 1024)), 'budget'),
        ):
            with self.subTest(label=label):
                bad = copy.deepcopy(source)
                mutate(bad['_lensRequestFacts'])
                incoming = copy.deepcopy(document)
                incoming['log']['entries'] = [source, bad]
                selected = self.directory / (label + '.har')
                selected.write_text(json.dumps(incoming))
                with self.assertRaisesRegex(AssertionError, message):
                    self.engine.command('load_har', path=str(selected))
                current = self.engine.command('detail', id=flow['id'])[1]
                self.assertEqual(current['request_fingerprint'], detail['request_fingerprint'])
                self.assertEqual(path.read_bytes(), original_file)
                self.assertEqual(self.saved('still-existing.har')[1], document)


if __name__ == '__main__':
    unittest.main(verbosity=2)
