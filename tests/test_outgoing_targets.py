"""Real captured/reopened target facts through Compose, Replay and Repeat."""
import base64
import copy
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

import h2.config
import h2.connection
import h2.events

from test_e2e import EngineHarness
from test_native_json_protocol import ByteOrigin
from test_protocols import protocol_certificates


class TargetOrigin(ByteOrigin):
    do_OPTIONS = ByteOrigin.respond


class OutgoingTargetsAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='lens-outgoing-targets-')
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(cls.directory)
        cls.origins = []
        for secure in (False, True):
            origin = ThreadingHTTPServer(('127.0.0.1', 0), TargetOrigin)
            origin.daemon_threads = True
            origin.history, origin.history_lock = [], threading.Lock()
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                origin.socket = context.wrap_socket(origin.socket, server_side=True)
            cls.addClassCleanup(origin.server_close)
            cls.addClassCleanup(origin.shutdown)
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            cls.origins.append(origin)
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready['ca_cert'])

    def setUp(self):
        self.engine.configure([])
        self.engine.command('clear')
        self.body = b'whole outgoing body\0\xff' * 19

    def tunnel(self, secure, *, http2=False):
        origin = self.origins[int(secure)]
        authority = f'127.0.0.1:{origin.server_port}'.encode('ascii')
        sock = socket.create_connection(('127.0.0.1', self.engine.port), timeout=10)
        self.addCleanup(sock.close)
        sock.sendall(b'CONNECT ' + authority + b' HTTP/1.1\r\nHost: ' + authority + b'\r\n\r\n')
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            value = sock.recv(1)
            self.assertTrue(value, 'proxy closed CONNECT before headers')
            response.extend(value)
            self.assertLessEqual(len(response), 65536)
        self.assertTrue(response.startswith(b'HTTP/1.1 200 '), response)
        if secure:
            context = ssl.create_default_context(cafile=self.engine.ready['ca_cert'])
            context.set_alpn_protocols(['h2'] if http2 else ['http/1.1'])
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            sock = context.wrap_socket(sock, server_hostname='127.0.0.1')
            self.addCleanup(sock.close)
            if http2:
                self.assertEqual(sock.selected_alpn_protocol(), 'h2')
        return sock, authority

    def capture(self, secure, target, *, method=b'POST', host=None, http2=False):
        after = len(self.engine.events)
        sock, authority = self.tunnel(secure, http2=http2)
        host = host or authority
        if http2:
            connection = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding=None))
            connection.initiate_connection()
            connection.send_headers(1, [(b':method', method), (b':scheme', b'https'),
                (b':authority', host), (b':path', target), (b'x-dup', b'first'),
                (b'x-dup', b'second'), (b'x-bytes', b'\xff'),
                (b'content-length', str(len(self.body)).encode())])
            connection.send_data(1, self.body, end_stream=True)
            sock.sendall(connection.data_to_send())
            complete = False
            while not complete:
                data = sock.recv(65536)
                self.assertTrue(data)
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        self.assertIn((b':status', b'200'), event.headers)
                    if isinstance(event, h2.events.DataReceived):
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    complete |= isinstance(event, h2.events.StreamEnded)
                pending = connection.data_to_send()
                if pending:
                    sock.sendall(pending)
        else:
            sock.sendall(method + b' ' + target + b' HTTP/1.1\r\nHost: ' + host +
                b'\r\nX-Dup: first\r\nX-Dup: second\r\nX-Bytes: \xff\r\nContent-Length: ' +
                str(len(self.body)).encode() + b'\r\nConnection: close\r\n\r\n' + self.body)
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 200)
            response.read()
        sock.close()
        flow = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow']['state'] == 'complete', after=after)['flow']
        detail = self.engine.command('detail', id=flow['id'])[1]
        self.assertEqual(base64.b64decode(detail['request_target_base64']), target)
        if http2:
            self.assertEqual(detail['http_version'], 'HTTP/2.0')
        return flow, detail, host

    def reopen(self, detail):
        path = self.directory / 'source.har'
        self.engine.command('save_har', path=str(path))
        self.engine.command('clear')
        after = len(self.engine.events)
        self.engine.command('load_har', path=str(path))
        flow = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('imported'), after=after)['flow']
        reopened = self.engine.command('detail', id=flow['id'])[1]
        self.assertEqual(reopened['request_fingerprint'], detail['request_fingerprint'])
        return flow, path

    def execute(self, operation, source):
        after = len(self.engine.events)
        arguments = {'id': source['id']}
        if operation == 'repeat':
            arguments.update(count=2, concurrency=2)
        elif operation == 'compose':
            arguments = {'source_id': source['id'], 'request_edit': {}}
        identity, queued = self.engine.command(operation, **arguments)
        if operation == 'repeat':
            event = self.engine.wait(lambda e: e.get('event') == 'repeat_done' and e.get('job_id') == queued['job_id'], after=after)
            self.assertEqual((event['completed'], event['failed'], event['cancelled']), (2, 0, 0), event)
        else:
            event = self.engine.wait(lambda e: e.get('command_id') == identity and e.get('event') in ('request_finished', 'request_failed'), after=after)
            self.assertEqual(event['event'], 'request_finished', event)
            outgoing = self.engine.command('detail', id=event['flow_id'])[1]
            self.assertEqual(outgoing['request_operation']['source_id'], source['id'])

    def exercise(self, secure, target, *, method=b'POST', host=None, http2=False):
        _, detail, expected_host = self.capture(secure, target, method=method, host=host, http2=http2)
        source, _ = self.reopen(detail)
        origin = self.origins[int(secure)]
        for operation in ('replay', 'repeat', 'compose'):
            with self.subTest(secure=secure, target=target, operation=operation):
                with origin.history_lock:
                    before = len(origin.history)
                self.execute(operation, source)
                with origin.history_lock:
                    observed = origin.history[before:]
                self.assertEqual(len(observed), 2 if operation == 'repeat' else 1)
                for record in observed:
                    self.assertEqual(record['line'], method + b' ' + target + b' HTTP/1.1\r\n')
                    self.assertEqual(record['body'], self.body)
                    self.assertEqual([v for k, v in record['headers'] if k.lower() == b'host'], [expected_host])
                    self.assertEqual([v for k, v in record['headers'] if k.lower() == b'x-dup'], [b'first', b'second'])
                    self.assertEqual([v for k, v in record['headers'] if k.lower() == b'x-bytes'], [b'\xff'])
                retained = self.engine.command('detail', id=source['id'])[1]
                self.assertEqual(retained['request_fingerprint'], detail['request_fingerprint'])

    def test_raw_path_query_bytes_over_http_and_strict_tls(self):
        for secure in (False, True):
            self.setUp()
            self.exercise(secure, b'/raw\xff?q=\xfe&x=1&x=2')

    def test_empty_query_delimiter_over_http_and_strict_tls(self):
        for secure in (False, True):
            self.setUp()
            self.exercise(secure, b'/empty?')

    def test_utf8_nfd_and_literal_percent_target_bytes_over_http_and_strict_tls(self):
        target = '/café/e\u0301/%2f/%FF?literal=%252f&nfd=e\u0301&x=1&x=2'.encode('utf-8')
        for secure in (False, True):
            self.setUp()
            self.exercise(secure, target)

    def test_options_asterisk_over_http_and_strict_tls(self):
        for secure in (False, True):
            self.setUp()
            self.exercise(secure, b'*', method=b'OPTIONS')

    def test_routing_and_host_remain_independent_over_http_and_strict_tls(self):
        for secure in (False, True):
            self.setUp()
            self.exercise(secure, b'/split?x=1&x=2', host=b'shown.test:9443')

    def test_h2_authority_survives_translation_to_actual_http1_origin(self):
        self.exercise(True, b'/h2-authority?x=1&x=2', host=b'shown.test:9443', http2=True)

    def test_control_target_rejected_before_queuing_without_origin_side_effect(self):
        _, detail, _ = self.capture(False, b'/source')
        _, path = self.reopen(detail)
        document = json.loads(path.read_text())
        entry = document['log']['entries'][0]
        for target in (b'/bad\r\nX-Injected: yes', b'/bad\x00target', b'/bad target'):
            with self.subTest(target=target):
                changed = copy.deepcopy(document)
                value = changed['log']['entries'][0]
                value['_lensRequestFacts']['path_base64'] = base64.b64encode(target).decode()
                prefix = entry['request']['url'].rsplit('/source', 1)[0]
                value['request']['url'] = prefix + target.decode('ascii')
                self.engine.command('clear')
                after = len(self.engine.events)
                self.engine.command('import_har', har=changed)
                source = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('imported'), after=after)['flow']
                with self.origins[0].history_lock:
                    before = len(self.origins[0].history)
                for operation in ('replay', 'repeat', 'compose'):
                    arguments = {'source_id': source['id'], 'request_edit': {}} if operation == 'compose' else {'id': source['id']}
                    with self.assertRaises(AssertionError):
                        self.engine.command(operation, **arguments)
                with self.origins[0].history_lock:
                    self.assertEqual(len(self.origins[0].history), before)

    def test_oversized_connection_list_remains_inspectable_but_refuses_outgoing_work(self):
        _, detail, _ = self.capture(False, b'/connection-resource')
        _, path = self.reopen(detail)
        document = json.loads(path.read_text())
        document['log']['entries'][0]['request']['headers'].append(
            {'name': 'Connection', 'value': ',' * 65536})
        self.engine.command('clear')
        after = len(self.engine.events)
        self.engine.command('import_har', har=document)
        source = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('imported'), after=after)['flow']
        original = self.engine.command('detail', id=source['id'])[1]
        with self.origins[0].history_lock:
            before = len(self.origins[0].history)
        for operation in ('replay', 'repeat', 'compose'):
            arguments = {'source_id': source['id'], 'request_edit': {}} if operation == 'compose' else {'id': source['id']}
            with self.subTest(operation=operation), self.assertRaisesRegex(AssertionError, 'Connection header processing exceeds 64 KiB'):
                self.engine.command(operation, **arguments)
        self.assertEqual(self.engine.command('detail', id=source['id'])[1]['request_fingerprint'], original['request_fingerprint'])
        with self.origins[0].history_lock:
            self.assertEqual(len(self.origins[0].history), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
