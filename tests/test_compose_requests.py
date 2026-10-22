"""Actual Compose/Replay/Repeat: retained bytes, explicit sources and operation facts."""
import base64
import copy
import gzip
import ipaddress
from http.server import ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
import uuid

from cryptography import x509
import brotli
import httpx
from test_e2e import EngineHarness
from test_protocols import ProtocolHTTPHandler, protocol_certificates


class Origin(ProtocolHTTPHandler):
    do_PUT = ProtocolHTTPHandler.respond
    do_PATCH = ProtocolHTTPHandler.respond
    do_MiXeD = ProtocolHTTPHandler.respond


class ComposeAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='lens-compose-')
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(cls.directory, additional_sans=(x509.IPAddress(ipaddress.ip_address('::1')),))
        cls.cert, cls.key = cert, key
        cls.origins = []
        for secure in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
            server.daemon_threads = True
            server.history, server.history_lock = [], threading.Lock()
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            cls.addClassCleanup(server.server_close); cls.addClassCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.origins.append(server)
        cls.http = f'http://127.0.0.1:{cls.origins[0].server_port}'
        cls.https = f'https://localhost:{cls.origins[1].server_port}'
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready['ca_cert'])

    def setUp(self):
        self.engine.command('configure', rules=[], access_policy={}, ssl_hosts='*')
        self.engine.command('clear')
        self.after = len(self.engine.events)

    def url(self, label, secure=False):
        return (self.https if secure else self.http) + '/' + label + '-' + uuid.uuid4().hex

    def source(self, payload=b'\x00\xffsource', headers=(), http2=False):
        url = self.url('source', secure=http2)
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=10, http2=http2) as client:
            reply = client.post(url, content=payload, headers=list(headers))
        self.assertEqual(reply.status_code, 200)
        flow = self.engine.flow(url, after=self.after)
        return flow

    def compose(self, **fields):
        after = len(self.engine.events)
        identity, value = self.engine.command('compose', **fields)
        self.assertTrue(value['queued'])
        done = self.engine.wait(lambda e: e.get('command_id') == identity and e.get('event') in ('request_finished', 'request_failed'), after=after)
        self.assertEqual(done['event'], 'request_finished', done)
        self.assertIsNotNone(done['flow_id'])
        flow = self.engine.flows[done['flow_id']]
        self.assertEqual(flow['request_operation']['id'], identity)
        return flow

    def raw_body(self, flow):
        return base64.b64decode(self.engine.command('export_body', id=flow['id'], side='request', decoded=False)[1]['base64'])

    def test_keep_complete_binary_h2_source_above_preview_with_ordered_headers_and_wire_bytes(self):
        payload = bytes(range(256)) * 8300
        source = self.source(payload, [(b'X-Dup', b'one'), (b'X-Dup', b'two'), (b'X-Raw', b'\xff')], http2=True)
        self.assertEqual(source['http_version'], 'HTTP/2.0')
        self.assertTrue(self.engine.command('detail', id=source['id'])[1]['request_truncated'])
        copied = self.compose(source_id=source['id'], request_edit={})
        self.assertEqual(self.raw_body(copied), payload)
        last = self.origins[1].history[-1]
        self.assertEqual(base64.b64decode(last['body']), payload)
        self.assertEqual([v for k, v in last['headers'] if k.lower() == 'x-dup'], ['one', 'two'])
        self.assertEqual([v.encode('latin1') for k, v in last['headers'] if k.lower() == 'x-raw'], [b'\xff'])
        self.assertEqual(copied['request_operation']['source_id'], source['id'])
        self.assertEqual(self.raw_body(source), payload)

    def test_gzip_keep_and_header_only_edit_preserve_exact_source_wire(self):
        wire = gzip.compress(b'compressed binary\x00\xff' * 100, mtime=123)
        source = self.source(wire, [('Content-Encoding', 'gzip')])
        copied = self.compose(source_id=source['id'], request_edit={'headers': [['Content-Encoding', 'gzip'], ['X-Changed', 'yes']]})
        self.assertEqual(self.raw_body(copied), wire)
        self.assertEqual(base64.b64decode(self.origins[0].history[-1]['body']), wire)
        self.assertEqual(self.raw_body(source), wire)

    def test_new_binary_request_and_changed_tls_destination_retain_exact_url_input(self):
        source = self.source()
        target = self.url('edited', secure=True)
        original_input = 'HTTPS' + target[5:]
        payload = b'\x00\xffnew binary'
        composed = self.compose(source_id=source['id'], request_edit={'method': 'PUT', 'url': original_input,
            'headers': [['Content-Type', 'application/octet-stream'], ['X-Dup', '1'], ['X-Dup', '2']],
            'body_base64': base64.b64encode(payload).decode()})
        record = self.origins[1].history[-1]
        self.assertEqual((record['method'], base64.b64decode(record['body'])), ('PUT', payload))
        self.assertEqual(composed['url'], target)
        self.assertEqual(composed['request_operation']['url_input'], original_input)
        new = self.compose(request_edit={'url': self.url('new'), 'method': 'PATCH', 'body_base64': ''})
        self.assertEqual((new['method'], self.raw_body(new)), ('PATCH', b''))
        self.assertIsNone(new['request_operation']['source_id'])

    def test_encoding_change_reuses_complete_decoder_and_explicit_replacement_is_decoded_bytes(self):
        plain = b'coding retained\x00\xff' * 100
        source = self.source(gzip.compress(plain, mtime=123), [('Content-Encoding', 'gzip')])
        changed = self.compose(source_id=source['id'], request_edit={'headers': [['Content-Encoding', 'br']]})
        self.assertEqual(brotli.decompress(self.raw_body(changed)), plain)
        replaced = self.compose(source_id=source['id'], request_edit={'body_base64': base64.b64encode(b'new\x00\xff').decode()})
        self.assertEqual(gzip.decompress(self.raw_body(replaced)), b'new\x00\xff')

    def test_invalid_edits_reject_before_queue_without_touching_source_or_origin(self):
        source = self.source()
        original = self.engine.command('detail', id=source['id'])[1]
        history = len(self.origins[0].history)
        for patch in ({'method': 'BAD METHOD'}, {'method': 'CONNECT'}, {'url': self.url('bad') + '#fragment'},
                      {'headers': [['Host', 'foreign']]}, {'body_base64': 'bad'}, {'other': True}):
            with self.subTest(patch=patch), self.assertRaises(AssertionError):
                self.engine.command('compose', source_id=source['id'], request_edit=patch)
        for args in ({'source_id': 'missing'}, {'source_id': None}, {'request_edit': {}},
                     {'request_edit': {'url': self.url('mixed')}, 'body': 'ambiguous'}):
            with self.subTest(args=args), self.assertRaises(AssertionError): self.engine.command('compose', **args)
        current = self.engine.command('detail', id=source['id'])[1]
        for key in ('url', 'method', 'request_headers', 'request_body_base64'):
            self.assertEqual(current[key], original[key])
        self.assertEqual(len(self.engine.command('export_har')[1]['log']['entries']), 1)
        self.assertEqual(len(self.origins[0].history), history)

    def test_unavailable_source_requires_explicit_body_and_empty_is_a_valid_replacement(self):
        source = self.source()
        har = self.engine.command('export_har')[1]
        entry = har['log']['entries'][0]
        entry.pop('_lensRawRequestBody'); entry['request'].pop('postData', None); entry['request']['bodySize'] = -1
        self.engine.command('clear')
        import_after = len(self.engine.events)
        self.engine.command('import_har', har=har)
        source = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow'].get('imported'), after=import_after)['flow']
        self.assertFalse(source['request_body_available'])
        with self.assertRaises(AssertionError): self.engine.command('compose', source_id=source['id'], request_edit={})
        explicit = self.compose(source_id=source['id'], request_edit={'body_base64': ''})
        self.assertEqual(self.raw_body(explicit), b'')

    def test_queued_snapshots_survive_source_clear_and_complete_with_correct_identity(self):
        source = self.source()
        self.engine.configure([{'kind': 'breakpoint_request', 'match': source['url']}])
        identities = []
        for _ in range(4):
            identities.append(self.engine.command('compose', source_id=source['id'], request_edit={})[0])
        self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow']['state'] == 'paused'
            and sum(row.get('state') == 'paused' for row in self.engine.flows.values()) == 4, after=self.after)
        queued, _ = self.engine.command('compose', source_id=source['id'], request_edit={})
        self.engine.configure([])
        self.engine.command('clear')
        for identity in [*identities, queued]:
            result = self.engine.wait(lambda e: e.get('command_id') == identity and e.get('event') == 'request_finished', after=self.after)
            if identity == queued:
                flow = self.engine.flows[result['flow_id']]
                self.assertEqual((self.raw_body(flow), flow['request_operation']['source_id']), (b'\x00\xffsource', source['id']))

    def test_compose_access_denial_is_a_completed_http_response_and_has_no_origin_side_effect(self):
        source = self.source()
        target = self.url('blocked')
        self.engine.command('configure', rules=[], ssl_hosts='*', access_policy={'block_enabled': True, 'block': [target]})
        flow = self.compose(source_id=source['id'], request_edit={'url': target})
        self.assertEqual((flow['status'], flow['access_decision']['matched_url']), (403, target))
        self.assertFalse(any(item['path'] == httpx.URL(target).path for item in self.origins[0].history))

    def test_replay_repeat_have_correlated_sources_attempts_and_har_facts(self):
        source = self.source()
        replay_id, _ = self.engine.command('replay', id=source['id'])
        replay = self.engine.wait(lambda e: e.get('command_id') == replay_id and e.get('event') == 'request_finished', after=self.after)
        self.assertEqual(self.engine.flows[replay['flow_id']]['request_operation']['kind'], 'replay')
        _, job = self.engine.command('repeat', id=source['id'], count=3, concurrency=2)
        done = self.engine.wait(lambda e: e.get('event') == 'repeat_done' and e.get('job_id') == job['job_id'], after=self.after)
        self.assertEqual((done['source_id'], done['completed'], done['failed'], done['cancelled']), (source['id'], 3, 0, 0))
        rows = [row for row in self.engine.flows.values() if row.get('request_operation', {}).get('id') == job['job_id']]
        self.assertEqual(sorted(row['request_operation']['attempt'] for row in rows), [1, 2, 3])
        self.assertTrue(all(self.raw_body(row) == b'\x00\xffsource' for row in rows))
        har = self.engine.command('export_har')[1]
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)
        for change in ({'kind': 'unknown'}, {'source_id': None}, {'attempt': True}, {'url_input': 'http://example.test/'}):
            bad = copy.deepcopy(har)
            entry = next(row for row in bad['log']['entries'] if row.get('_lensRequestOperation', {}).get('kind') == 'repeat')
            entry['_lensRequestOperation'].update(change)
            with self.subTest(change=change), self.assertRaises(AssertionError): self.engine.command('import_har', har=bad)
            self.assertEqual(self.engine.command('export_har')[1], har)

    def test_cancel_repeat_pauses_only_its_owned_requests_and_releases_other_work(self):
        source = self.source()
        self.engine.configure([{'kind': 'breakpoint_request', 'match': source['url']}])
        _, job = self.engine.command('repeat', id=source['id'], count=8, concurrency=2)
        self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow']['state'] == 'paused'
            and e['flow'].get('request_operation', {}).get('id') == job['job_id'], after=self.after)
        _, done = self.engine.command('cancel_repeat', job_id=job['job_id'])
        self.assertEqual((done['source_id'], done['completed'] + done['failed'] + done['cancelled']), (source['id'], 8))
        other = self.compose(request_edit={'url': self.url('unrelated')})
        self.assertEqual(other['status'], 200)

    def test_ipv6_new_http_and_tls_requests_have_bracketed_authority(self):
        class IPv6Server(ThreadingHTTPServer): address_family = socket.AF_INET6
        for secure in (False, True):
            with self.subTest(secure=secure):
                server = IPv6Server(('::1', 0), Origin); server.daemon_threads = True
                server.history, server.history_lock = [], threading.Lock()
                if secure:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.cert, self.key)
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                url = f"{'HTTPS' if secure else 'HTTP'}://[::1]:{server.server_port}/v6"
                flow = self.compose(request_edit={'url': url})
                record = server.history[-1]
                self.assertEqual([v for k, v in record['headers'] if k.lower() == 'host'], [f'[::1]:{server.server_port}'])
                self.assertEqual(flow['request_operation']['url_input'], url)

    def test_case_sensitive_custom_method_reaches_origin_without_uppercase_normalization(self):
        for secure in (False, True):
            with self.subTest(secure=secure):
                flow = self.compose(request_edit={'url': self.url('method', secure=secure), 'method': 'MiXeD', 'body_base64': base64.b64encode(b'custom method body').decode()})
                record = self.origins[int(secure)].history[-1]
                self.assertEqual((record['method'], flow['method']), ('MiXeD', 'MiXeD'))

    def test_source_fingerprint_rejects_representation_changed_after_editor_loaded(self):
        source = self.source()
        self.engine.configure([{'kind': 'breakpoint_request', 'match': source['url']}])
        identifier, _ = self.engine.command('compose', source_id=source['id'], request_edit={})
        paused = self.engine.wait(lambda e: e.get('event') == 'flow' and e['flow']['state'] == 'paused'
            and e['flow'].get('request_operation', {}).get('id') == identifier, after=self.after)['flow']
        before = self.engine.command('detail', id=paused['id'])[1]
        self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='continue',
            request_edit={'method': 'PUT', 'body_base64': base64.b64encode(b'changed source').decode()})
        self.engine.wait(lambda e: e.get('command_id') == identifier and e.get('event') == 'request_finished', after=self.after)
        self.engine.configure([])
        with self.assertRaises(AssertionError):
            self.engine.command('compose', source_id=paused['id'], source_fingerprint=before['request_fingerprint'], request_edit={})
        current = self.engine.command('detail', id=paused['id'])[1]
        self.assertNotEqual(current['request_fingerprint'], before['request_fingerprint'])
        composed = self.compose(source_id=paused['id'], source_fingerprint=current['request_fingerprint'], request_edit={})
        self.assertEqual((composed['method'], self.raw_body(composed)), ('PUT', b'changed source'))
