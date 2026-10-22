"""Real paused-message editing: atomic patches, representation and pause identity."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import gzip
from http.server import ThreadingHTTPServer
from pathlib import Path
import ssl
import socket
import tempfile
import threading
import unittest
import uuid

import brotli
import httpx
from test_e2e import EngineHarness
from test_protocols import ProtocolHTTPHandler, protocol_certificates, PLAIN


class EditingOrigin(ProtocolHTTPHandler):
    do_PUT = ProtocolHTTPHandler.respond


class BreakpointEditingAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='lens-breakpoint-edit-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, cert, key = protocol_certificates(cls.directory)
        cls.origins = []
        for secure in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), EditingOrigin)
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
        self.pool = ThreadPoolExecutor(max_workers=3)
        self.addCleanup(self.pool.shutdown, wait=True)

    def url(self, label):
        return self.http + '/' + label + '-' + uuid.uuid4().hex

    def request(self, url, body=b'before\x00\xff', method='POST', headers=(), http2=False):
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=8, http2=http2) as client:
            return client.request(method, url, content=body, headers=list(headers))

    def configure(self, url, *stages):
        self.engine.configure([{'kind': 'breakpoint_' + side, 'match': url} for side in stages])

    def paused(self, url, stage, after=None):
        return self.engine.wait(lambda event: event.get('event') == 'flow' and event['flow']['url'] == url
            and event['flow']['state'] == 'paused' and event['flow']['pause_stage'] == stage, after=self.after if after is None else after)['flow']

    def resume(self, flow, action='continue', **fields):
        return self.engine.command('resume', id=flow['id'], pause_id=flow['pause_id'],
                                   stage=flow['pause_stage'], action=action, **fields)

    def detail(self, flow):
        return self.engine.command('detail', id=flow['id'])[1]

    def entry(self, identity):
        return next(row for row in self.engine.command('export_har')[1]['log']['entries']
                    if row['request']['url'] == self.engine.flows[identity]['url'])

    def test_request_method_url_headers_and_binary_body_reach_changed_strict_tls_origin(self):
        original = self.url('original')
        edited = self.https + '/edited?x=1&x=2'
        self.configure(original, 'request')
        pending = self.pool.submit(self.request, original)
        paused = self.paused(original, 'request')
        payload = b'\x00\xff\x80edited binary'
        self.resume(paused, request_edit={'method': 'PUT', 'url': edited,
            'headers': [['X-Duplicate', 'one'], ['X-Duplicate', 'two'], ['Content-Type', 'application/octet-stream']],
            'body_base64': base64.b64encode(payload).decode()})
        reply = pending.result(timeout=8)
        self.assertEqual(reply.status_code, 200)
        origin = reply.json()
        self.assertEqual((origin['method'], origin['path']), ('PUT', '/edited?x=1&x=2'))
        self.assertEqual(base64.b64decode(origin['body']), payload)
        self.assertEqual([v for k, v in origin['headers'] if k.lower() == 'x-duplicate'], ['one', 'two'])
        self.assertIn(['host', f'localhost:{self.origins[1].server_port}'], [[k.lower(), v] for k, v in origin['headers']])
        self.assertIn(['content-length', str(len(payload))], [[k.lower(), v] for k, v in origin['headers']])
        self.assertFalse(any(item['path'] == httpx.URL(original).path for item in self.origins[0].history))
        captured = self.engine.flow(edited, after=self.after)
        self.assertEqual(captured['original_url'], original)
        self.assertIsNone(captured.get('pause_id'))

    def test_response_status_reason_duplicate_headers_and_binary_replacement_survive_har(self):
        url = self.url('response')
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url)
        paused = self.paused(url, 'response')
        payload = b'\x00\xffresponse\x80'
        self.resume(paused, response_edit={'status_code': 418, 'reason': 'Edited reason',
            'headers': [['X-Duplicate', 'first'], ['X-Duplicate', 'last'], ['Content-Type', 'application/octet-stream']],
            'body_base64': base64.b64encode(payload).decode()})
        reply = pending.result(timeout=8)
        self.assertEqual((reply.status_code, reply.reason_phrase, reply.content), (418, 'Edited reason', payload))
        self.assertEqual(reply.headers.get_list('x-duplicate'), ['first', 'last'])
        captured = self.engine.flow(url, after=self.after)
        self.assertEqual(self.detail(captured)['response_reason'], 'Edited reason')
        har = self.engine.command('export_har')[1]
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)

    def test_discard_keeps_exact_gzip_wire_bytes_and_stale_body_draft_is_not_applied(self):
        url = self.http + '/compressed/gzip'
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url)
        paused = self.paused(url, 'response')
        before = self.entry(paused['id'])
        self.resume(paused, action='discard', response_edit={'body_base64': 'malformed draft'})
        self.assertEqual(pending.result(timeout=8).content, PLAIN)
        self.engine.flow(url, after=self.after)
        after = self.entry(paused['id'])
        self.assertEqual(after['_lensRawResponseBody'], before['_lensRawResponseBody'])
        self.assertEqual(after['response']['headers'], before['response']['headers'])
        self.assertEqual(gzip.decompress(base64.b64decode(after['_lensRawResponseBody'])), PLAIN)

    def test_header_only_change_reencodes_full_decoded_body_once(self):
        url = self.http + '/compressed/gzip'
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url)
        paused = self.paused(url, 'response')
        detail = self.detail(paused)
        headers = [[k, ('br' if k.lower() == 'content-encoding' else v)] for k, v in detail['response_headers']
                   if k.lower() not in ('host', 'content-length', 'transfer-encoding')]
        self.resume(paused, response_edit={'headers': headers})
        reply = pending.result(timeout=8)
        self.assertEqual((reply.headers['content-encoding'], reply.content), ('br', PLAIN))
        self.engine.flow(url, after=self.after)
        raw = base64.b64decode(self.entry(paused['id'])['_lensRawResponseBody'])
        self.assertEqual(brotli.decompress(raw), PLAIN)

    def test_invalid_patch_is_atomic_and_keeps_pause_open_for_correction(self):
        url = self.url('atomic')
        self.configure(url, 'request')
        pending = self.pool.submit(self.request, url)
        paused = self.paused(url, 'request')
        before = self.detail(paused)
        for fields in [
            {'request_edit': {'method': 'PUT', 'headers': [['X-Good', 'ok'], ['X-Bad', 'bad\r\nheader']]}},
            {'response_edit': {'status_code': 201}},
            {'request_edit': {'body_base64': '!invalid'}},
            {'request_edit': {'headers': [['Host', 'foreign.test']]}},
            {'request_edit': {'url': 'http://user:password@example.invalid/'}},
            {'request_edit': {'url': self.http + '/fragment#part'}},
            {'request_edit': {'unknown': 'field'}},
            {'request_edit': {'method': 'GET'}, 'request_body': 'ambiguous'},
            {'request_edit': {'method': 'CONNECT'}},
        ]:
            with self.subTest(fields=fields):
                with self.assertRaises(AssertionError): self.resume(paused, **fields)
                current = self.detail(paused)
                for key in ('request_body_base64', 'request_headers', 'method', 'url', 'pause_id', 'state'):
                    self.assertEqual(current[key], before[key])
                self.assertFalse(pending.done())
        self.resume(paused, request_edit={'body_base64': ''})
        self.assertEqual(base64.b64decode(pending.result(timeout=8).json()['body']), b'')

    def test_each_pause_has_fresh_identity_and_old_editor_cannot_resume_next_stage(self):
        url = self.url('stale')
        self.configure(url, 'request', 'response')
        pending = self.pool.submit(self.request, url)
        first = self.paused(url, 'request')
        after = len(self.engine.events)
        self.resume(first)
        second = self.paused(url, 'response', after)
        self.assertEqual(second['id'], first['id'])
        self.assertNotEqual(second['pause_id'], first['pause_id'])
        with self.assertRaises(AssertionError): self.resume(first, action='abort')
        with self.assertRaises(AssertionError): self.resume(first, request_edit={'method': 'GET'})
        self.assertFalse(pending.done())
        self.resume(second, action='discard')
        self.assertEqual(pending.result(timeout=8).status_code, 200)

    def test_edited_destination_still_obeys_original_request_access_policy(self):
        original, target = self.url('policy'), self.url('forbidden')
        self.engine.command('configure', rules=[{'kind': 'breakpoint_request', 'match': original}],
            access_policy={'block_enabled': True, 'block': [target]}, ssl_hosts='*')
        pending = self.pool.submit(self.request, original)
        paused = self.paused(original, 'request')
        self.resume(paused, request_edit={'url': target})
        self.assertEqual(pending.result(timeout=8).status_code, 403)
        decision = self.engine.flow(target, after=self.after)['access_decision']
        self.assertEqual(decision['matched_url'], target)
        for item in self.origins[0].history:
            self.assertNotIn(item['path'], [httpx.URL(original).path, httpx.URL(target).path])

    def test_concurrent_requests_keep_independent_edits_and_pause_tokens(self):
        urls = [self.url('concurrent') for _ in range(2)]
        self.engine.configure([{'kind': 'breakpoint_request', 'match': self.http + '/concurrent-*'}])
        pending = [self.pool.submit(self.request, url) for url in urls]
        paused = [self.paused(url, 'request') for url in urls]
        self.assertNotEqual(paused[0]['pause_id'], paused[1]['pause_id'])
        for index, flow in enumerate(paused):
            self.resume(flow, request_edit={'body_base64': base64.b64encode(bytes([index, 255])).decode()})
        for index, future in enumerate(pending):
            self.assertEqual(base64.b64decode(future.result(timeout=8).json()['body']), bytes([index, 255]))

    def test_no_body_status_requires_explicit_empty_replacement_and_has_valid_wire_framing(self):
        url = self.url('no-body')
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url)
        paused = self.paused(url, 'response')
        with self.assertRaises(AssertionError): self.resume(paused, response_edit={'status_code': 204})
        self.assertEqual(self.detail(paused)['state'], 'paused')
        self.resume(paused, response_edit={'status_code': 204, 'body_base64': ''})
        reply = pending.result(timeout=8)
        self.assertEqual((reply.status_code, reply.content), (204, b''))
        self.assertNotIn('transfer-encoding', reply.headers)
        self.assertNotIn('content-length', reply.headers)

    def test_http2_response_edit_retains_valid_stream_framing(self):
        url = self.https + '/h2-edit-' + uuid.uuid4().hex
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url, http2=True)
        paused = self.paused(url, 'response')
        self.assertEqual(paused['http_version'], 'HTTP/2.0')
        payload = b'\x00\xffh2 edited'
        self.resume(paused, response_edit={'status_code': 201, 'headers': [['X-Edit', 'h2']],
            'body_base64': base64.b64encode(payload).decode()})
        reply = pending.result(timeout=8)
        self.assertEqual((reply.status_code, reply.http_version, reply.content), (201, 'HTTP/2', payload))
        self.assertNotIn('transfer-encoding', reply.headers)

    def test_head_header_edit_preserves_advertised_length_without_creating_payload(self):
        url = self.url('head')
        self.configure(url, 'response')
        pending = self.pool.submit(self.request, url, body=b'', method='HEAD')
        paused = self.paused(url, 'response')
        original = self.detail(paused)
        length = next(v for k, v in original['response_headers'] if k.lower() == 'content-length')
        self.resume(paused, response_edit={'headers': [['X-Edited', 'HEAD']]})
        reply = pending.result(timeout=8)
        self.assertEqual((reply.status_code, reply.content, reply.headers['content-length']), (200, b'', length))
        self.assertEqual(reply.headers['x-edited'], 'HEAD')

    def test_ipv6_url_edit_uses_bracketed_authority_and_preserves_original_input(self):
        class IPv6Origin(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        server = IPv6Origin(('::1', 0), EditingOrigin)
        server.daemon_threads = True
        server.history, server.history_lock = [], threading.Lock()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        original = self.url('ipv6-source')
        source = f'HTTP://[::1]:{server.server_port}/ipv6-edited'
        effective = source.replace('HTTP:', 'http:', 1)
        self.configure(original, 'request')
        pending = self.pool.submit(self.request, original)
        paused = self.paused(original, 'request')
        self.resume(paused, request_edit={'url': source})
        reply = pending.result(timeout=8)
        self.assertEqual(reply.status_code, 200)
        self.assertIn(['host', f'[::1]:{server.server_port}'], [[k.lower(), v] for k, v in reply.json()['headers']])
        captured = self.engine.flow(effective, after=self.after)
        self.assertEqual((captured['original_url'], captured['breakpoint_url']), (original, source))
        har = self.engine.command('export_har')[1]
        self.assertEqual(har['log']['entries'][0]['_lensBreakpointUrl'], source)
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)

    def test_method_edit_to_head_completes_original_post_client_without_missing_body(self):
        url = self.url('post-to-head')
        self.configure(url, 'request')
        pending = self.pool.submit(self.request, url, body=b'')
        paused = self.paused(url, 'request')
        self.resume(paused, request_edit={'method': 'HEAD'})
        reply = pending.result(timeout=9)
        self.assertEqual((reply.status_code, reply.content), (200, b''))
        self.assertTrue(any(item['path'] == httpx.URL(url).path and item['method'] == 'HEAD' for item in self.origins[0].history))
        captured = self.engine.flow(url, after=self.after)
        har = self.engine.command('export_har')[1]
        facts = har['log']['entries'][0]['_lensMethodFraming']
        self.assertEqual((facts['frontend_method'], facts['effective_method']), ('POST', 'HEAD'))
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)


    def test_original_head_client_can_reuse_connection_after_edit_to_post(self):
        url = self.url('head-to-post')
        self.configure(url, 'request')
        def request_then_reuse():
            with httpx.Client(proxy=self.engine.proxy, trust_env=False, timeout=8) as client:
                first = client.head(url)
                second = client.get(url + '-next')
                return first, second
        pending = self.pool.submit(request_then_reuse)
        paused = self.paused(url, 'request')
        self.resume(paused, request_edit={'method': 'POST', 'body_base64': base64.b64encode(b'head edited to post').decode()})
        first, second = pending.result(timeout=9)
        self.assertEqual((first.status_code, first.content, second.status_code), (200, b'', 200))
        self.assertTrue(second.json()['path'].endswith('-next'))

    def test_http2_post_to_head_edit_has_zero_length_frontend_response(self):
        url = self.https + '/h2-head-' + uuid.uuid4().hex
        self.configure(url, 'request')
        pending = self.pool.submit(self.request, url, body=b'', http2=True)
        paused = self.paused(url, 'request')
        self.resume(paused, request_edit={'method': 'HEAD'})
        reply = pending.result(timeout=9)
        self.assertEqual((reply.status_code, reply.http_version, reply.content), (200, 'HTTP/2', b''))
        self.assertEqual(reply.headers['content-length'], '0')

    def test_mixed_http2_method_edits_keep_stream_framing_and_captured_bodies_independent(self):
        base = self.https + '/mixed-' + uuid.uuid4().hex
        head_url, post_url = base + '-head', base + '-post'
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False, timeout=8, http2=True) as client:
            self.assertEqual(client.get(base + '-warmup').http_version, 'HTTP/2')
            self.engine.configure([{'kind': 'breakpoint_request', 'match': base + '*'}])
            head = self.pool.submit(client.head, head_url)
            post = self.pool.submit(client.post, post_url, content=b'')
            head_pause, post_pause = self.paused(head_url, 'request'), self.paused(post_url, 'request')
            self.assertEqual(head_pause['client_connection']['id'], post_pause['client_connection']['id'])
            payload = b'HEAD frontend captures POST entity'
            self.resume(head_pause, request_edit={'method': 'POST', 'body_base64': base64.b64encode(payload).decode()})
            self.resume(post_pause, request_edit={'method': 'HEAD'})
            head_reply, post_reply = head.result(timeout=9), post.result(timeout=9)
            self.assertEqual((head_reply.status_code, head_reply.content, post_reply.status_code, post_reply.content), (200, b'', 200, b''))
            self.assertEqual(post_reply.headers['content-length'], '0')
            captured = self.detail(head_pause)
            self.assertEqual(base64.b64decode(__import__('json').loads(captured['response_body'])['body']), payload)
            self.engine.configure([])
            self.assertEqual(client.get(base + '-next').status_code, 200)

    def test_method_edit_to_head_preserves_synthetic_access_and_local_responses(self):
        for mode in ('access', 'local'):
            with self.subTest(mode=mode):
                self.engine.command('clear')
                self.after = len(self.engine.events)
                original, target = self.url('synthetic-' + mode), self.url('blocked-target')
                rules = [{'kind': 'breakpoint_request', 'match': original}]
                payload = b'local binary\x00\xff'
                if mode == 'local':
                    path = self.directory / 'head-map.bin'
                    path.write_bytes(payload)
                    rules.insert(0, {'kind': 'map_local', 'match': original, 'value': str(path)})
                    rules.append({'kind': 'breakpoint_response', 'match': target})
                self.engine.command('configure', rules=rules, ssl_hosts='*',
                    access_policy={'block_enabled': mode == 'access', 'block': [target]})
                pending = self.pool.submit(self.request, original, body=b'')
                paused = self.paused(original, 'request')
                self.resume(paused, request_edit={'method': 'HEAD', 'url': target})
                if mode == 'local':
                    response = self.paused(target, 'response')
                    self.resume(response, response_edit={'reason': 'Local edited', 'headers': [['X-Local', 'yes']]})
                reply = pending.result(timeout=9)
                self.assertEqual(reply.status_code, 403 if mode == 'access' else 200)
                self.assertEqual(reply.content, b'Blocked by Lens access list' if mode == 'access' else payload)
                captured = self.engine.flow(target, after=self.after)
                self.assertEqual(self.detail(captured)['state'], 'complete')
                entry = self.entry(captured['id'])
                self.assertNotIn('_lensMethodFraming', entry)
                self.assertEqual(entry['_lensFrontendMethod'], 'POST')
