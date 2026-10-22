"""Independent real-wire Rewrite acceptance using explicit loopback proxies.

LENS_TEST_ENGINE selects a packaged engine. Origins, CA and captures are owned
temporary fixtures; no host proxy, trust, GUI or external network is modified.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import gzip
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import socket
import tempfile
import threading
import time
import unittest
import zlib

import brotli
import httpx

from test_e2e import EngineHarness
from test_protocols import protocol_certificates


ENCODE = {'gzip': lambda value: gzip.compress(value, mtime=123456),
          'deflate': zlib.compress, 'br': brotli.compress, 'identity': lambda value: value}
DECODE = {'gzip': gzip.decompress, 'deflate': zlib.decompress,
          'br': brotli.decompress, 'identity': lambda value: value}
REPEATED = [('X-Keep', 'one'), ('X-Change', 'before one'), ('X-Keep', 'two'),
            ('x-change', 'before two'), ('X-Tail', 'last')]


def values(fields, name):
    return [value for key, value in fields if key.lower() == name.lower()]


class RewriteOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        self.connection.settimeout(15)
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        coding = self.headers.get('Content-Encoding', 'identity')
        decoded = DECODE[coding](raw)
        path = self.path.split('?', 1)[0]
        response_coding = path.split('/')[-1] if path.startswith('/coding/') else 'identity'
        response_body = b'A' * 1024 if path == '/response-expansion' else decoded
        response_raw = ENCODE[response_coding](response_body)
        record = {'path': self.path, 'headers': list(self.headers.raw_items()),
                  'raw': raw, 'decoded': decoded, 'response_raw': response_raw,
                  'response_decoded': response_body, 'response_coding': response_coding}
        with self.server.history_lock:
            self.server.history.append(record)
        self.send_response(200, 'Origin reason')
        self.send_header('Content-Type', 'application/octet-stream')
        if response_coding != 'identity':
            self.send_header('Content-Encoding', response_coding)
        for name, value in REPEATED:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(response_raw)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(response_raw)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


class RewriteFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lens-rewrite-wire-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(self.directory)
        self.origins = []
        for secure in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), RewriteOrigin)
            server.history, server.history_lock = [], threading.Lock()
            self.addCleanup(server.server_close)
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, name='owned-rewrite-origin')
            worker.start()
            self.addCleanup(self.close_origin, server, worker)
            self.origins.append(server)
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)
        self.context = ssl.create_default_context(cafile=self.engine.ready['ca_cert'])

    @staticmethod
    def close_origin(server, worker):
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError('Owned Rewrite origin did not join')

    def url(self, path, secure=False):
        return f'{"https://localhost" if secure else "http://127.0.0.1"}:{self.origins[int(secure)].server_port}{path}'

    @staticmethod
    def rule(kind, name='', value='', **fields):
        return {'kind': kind, 'match': '*', 'name': name, 'value': value, **fields}

    def configure(self, *rules):
        self.engine.configure(list(rules))

    def request(self, url, body=b'', headers=(), h2=False):
        with httpx.Client(proxy=self.engine.proxy, verify=self.context, trust_env=False,
                          timeout=10, http2=h2) as client:
            request = client.build_request('POST', url, content=body, headers=list(headers))
            response = client.send(request, stream=True)
            try:
                raw = b''.join(response.iter_raw())
            finally:
                response.close()
        return response, raw

    def raw_get(self, url):
        connection = http.client.HTTPConnection('127.0.0.1', self.engine.port, timeout=10)
        try:
            connection.request('GET', url)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def observed(self, index=-1, secure=False):
        with self.origins[int(secure)].history_lock:
            return self.origins[int(secure)].history[index]

    def entry(self, url):
        return next(entry for entry in self.engine.command('export_har')[1]['log']['entries']
                    if entry['request']['url'] == url)

    def assert_aborted_rewrite(self, url, body=b''):
        start = time.monotonic()
        try:
            self.request(url, body)
        except httpx.HTTPError as failure:
            self.assertNotIsInstance(failure, httpx.TimeoutException)
        else:
            self.fail('Unsafe Rewrite unexpectedly returned an HTTP response')
        self.assertLess(time.monotonic() - start, 5, 'Rewrite failure must not leave a hanging client')
        flow = self.engine.flow(url, 'error')
        self.assertIn('rewrite', flow['error'].lower())
        return self.engine.command('detail', id=flow['id'])[1]


class RewriteWireAcceptance(RewriteFixture):
    def test_default_header_set_preserves_unrelated_duplicate_order_on_http_tls_h2(self):
        self.configure(self.rule('rewrite_request_header', 'X-Change', 'intermediate'),
                       self.rule('rewrite_request_header', 'x-change', 'request final'),
                       self.rule('rewrite_response_header', 'X-Change', 'response final'))
        for secure, h2 in ((False, False), (True, False), (True, True)):
            with self.subTest(secure=secure, h2=h2):
                url = self.url('/headers', secure)
                response, raw = self.request(url, b'unchanged', REPEATED, h2)
                self.assertEqual((response.status_code, raw), (200, b'unchanged'))
                self.assertEqual(response.http_version, 'HTTP/2' if h2 else 'HTTP/1.1')
                actual = self.observed(secure=secure)['headers']
                self.assertEqual(values(actual, 'X-Change'), ['request final'])
                self.assertEqual(response.headers.get_list('X-Change'), ['response final'])
                for fields in (actual, response.headers.multi_items()):
                    self.assertEqual([(key.lower(), value) for key, value in fields
                                      if key.lower() in ('x-keep', 'x-tail')],
                                     [('x-keep', 'one'), ('x-keep', 'two'), ('x-tail', 'last')])

    def test_header_add_remove_and_global_first_replace_keep_field_order(self):
        self.configure(
            self.rule('rewrite_request_header', 'X-Change', 'before three', rewrite_mode='add'),
            self.rule('rewrite_request_header', 'X-Change', 'after', rewrite_mode='replace',
                      rewrite_find='before', rewrite_count='first'),
            self.rule('rewrite_request_header', 'X-Tail', rewrite_mode='remove'),
            self.rule('rewrite_response_header', 'X-Change', 'before three', rewrite_mode='add'),
            self.rule('rewrite_response_header', 'X-Change', 'after', rewrite_mode='replace', rewrite_find='before'),
            self.rule('rewrite_response_header', 'X-Tail', rewrite_mode='remove'))
        response, raw = self.request(self.url('/header-actions'), b'body', REPEATED)
        self.assertEqual(raw, b'body')
        self.assertEqual(values(self.observed()['headers'], 'X-Change'), ['after one', 'before two', 'before three'])
        self.assertEqual(response.headers.get_list('X-Change'), ['after one', 'after two', 'after three'])
        self.assertEqual(values(self.observed()['headers'], 'X-Tail'), [])
        self.assertNotIn('X-Tail', response.headers)

    def test_utf8_literal_body_order_first_all_and_binary_neighbors(self):
        self.configure(self.rule('rewrite_request_body', '甲', '乙', rewrite_count='first'),
                       self.rule('rewrite_request_body', '乙', '丙'),
                       self.rule('rewrite_response_body', '甲', '末'),
                       self.rule('rewrite_response_body', '丙', '终'))
        original = b'\x00\xff' + '甲甲'.encode() + b'\x80tail'
        request_expected = b'\x00\xff' + '丙甲'.encode() + b'\x80tail'
        response_expected = b'\x00\xff' + '终末'.encode() + b'\x80tail'
        response, raw = self.request(self.url('/utf8'), original)
        self.assertEqual(self.observed()['raw'], request_expected)
        self.assertEqual(raw, response_expected)
        self.assertEqual(response.headers['Content-Length'], str(len(response_expected)))

    def test_compressed_rewrites_match_decoded_bytes_and_actual_encoded_framing(self):
        self.configure(self.rule('rewrite_request_body', 'before', '之后'),
                       self.rule('rewrite_response_body', '之后', 'FINAL'))
        original = b'\x00\xffbefore-' + '中文'.encode() + b'-before\x00'
        outgoing = original.replace(b'before', '之后'.encode())
        received = outgoing.replace('之后'.encode(), b'FINAL')
        for coding, secure, h2 in (('gzip', False, False), ('deflate', True, False), ('br', True, True)):
            with self.subTest(coding=coding, secure=secure, h2=h2):
                url = self.url('/coding/' + coding, secure)
                response, raw = self.request(url, ENCODE[coding](original), [('Content-Encoding', coding)], h2)
                observed = self.observed(secure=secure)
                self.assertEqual(observed['decoded'], outgoing)
                self.assertEqual(values(observed['headers'], 'Content-Encoding'), [coding])
                self.assertEqual(values(observed['headers'], 'Content-Length'), [str(len(observed['raw']))])
                self.assertEqual(values(observed['headers'], 'Transfer-Encoding'), [])
                self.assertEqual(response.headers['Content-Length'], str(len(raw)))
                self.assertEqual(response.headers['Content-Encoding'], coding)
                self.assertEqual(DECODE[coding](raw), received)
                entry = self.entry(url)
                self.assertEqual(base64.b64decode(entry['_lensRawRequestBody']), observed['raw'])
                self.assertEqual(base64.b64decode(entry['_lensRawResponseBody']), raw)

    def test_no_match_and_disabled_rewrites_keep_exact_compressed_source_wire(self):
        self.configure(self.rule('rewrite_request_body', 'not-present', 'changed'),
                       self.rule('rewrite_response_body', 'not-present', 'changed'),
                       self.rule('rewrite_request_body', 'source', 'disabled', enabled=False),
                       self.rule('rewrite_response_body', 'source', 'unmatched', match='*never-match*'))
        original = b'source\x00\xffbytes'
        wire = ENCODE['gzip'](original)
        url = self.url('/coding/gzip')
        response, raw = self.request(url, wire, [('Content-Encoding', 'gzip')])
        observed = self.observed()
        self.assertEqual(observed['raw'], wire)
        self.assertEqual(raw, observed['response_raw'])
        self.assertEqual(gzip.decompress(raw), original)
        self.assertEqual(response.headers['Content-Length'], str(len(raw)))

    def test_content_encoding_rewrite_transcodes_from_original_decoded_bytes(self):
        self.configure(self.rule('rewrite_request_header', 'Content-Encoding', 'br'),
                       self.rule('rewrite_response_header', 'Content-Encoding', 'identity'))
        original = '压缩正文'.encode() + b'\x00\xff'
        response, raw = self.request(self.url('/coding/gzip'), ENCODE['gzip'](original), [('Content-Encoding', 'gzip')])
        observed = self.observed()
        self.assertEqual(values(observed['headers'], 'Content-Encoding'), ['br'])
        self.assertEqual(brotli.decompress(observed['raw']), original)
        self.assertEqual(raw, original)
        self.assertEqual(response.headers['Content-Length'], str(len(original)))

    def test_invalid_headers_and_status_reject_whole_configuration_atomically(self):
        stable = self.rule('rewrite_request_header', 'X-Atomic', 'retained')
        self.configure(stable)
        bad = [self.rule('rewrite_request_header', name, value) for name, value in
               [('Bad Name', 'x'), ('X:Bad', 'x'), ('X-Nul', '\0'), ('X-Line', 'a\r\nb'),
                ('Host', 'other.invalid'), ('Content-Length', '1'), ('Transfer-Encoding', 'chunked')]]
        bad += [self.rule('rewrite_response_header', 'Host', 'other.invalid'),
                self.rule('rewrite_response_status', '101', 'Switch'),
                self.rule('rewrite_response_status', '600', 'Invalid'),
                self.rule('rewrite_response_status', '201', 'bad\0reason')]
        for index, invalid in enumerate(bad):
            with self.subTest(invalid=invalid):
                with self.assertRaises(AssertionError):
                    self.configure(self.rule('rewrite_request_header', 'X-Atomic', 'must not publish'), invalid)
                response, _ = self.request(self.url(f'/atomic-{index}'))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(values(self.observed()['headers'], 'X-Atomic'), ['retained'])

    def test_request_body_expansion_over_32mib_aborts_before_origin_and_keeps_source(self):
        self.configure(self.rule('rewrite_request_body', 'A', 'r' * 32769))
        url, original = self.url('/request-expansion'), b'A' * 1024
        detail = self.assert_aborted_rewrite(url, original)
        self.assertEqual(self.origins[0].history, [])
        self.assertEqual(base64.b64decode(detail['request_body_base64']), original)

    def test_response_body_expansion_over_32mib_is_visible_and_keeps_source(self):
        self.configure(self.rule('rewrite_response_body', 'A', 'r' * 32769))
        url = self.url('/response-expansion')
        detail = self.assert_aborted_rewrite(url)
        self.assertEqual(len(self.origins[0].history), 1)
        self.assertEqual(base64.b64decode(detail['response_body_base64']), b'A' * 1024)

    def test_snapshot_isolation_across_request_breakpoint_and_reconfigure(self):
        url = self.url('/snapshot')
        def generation(value):
            return [self.rule('rewrite_request_header', 'X-Generation', value),
                    self.rule('rewrite_request_body', 'source', value),
                    self.rule('rewrite_response_header', 'X-Generation', value),
                    self.rule('rewrite_response_body', value, value + '-response')]
        self.configure(self.rule('breakpoint_request', match=url), *generation('old'))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, url, b'source')
            paused = self.engine.flow(url, 'paused')
            try:
                self.configure(*generation('new'))
            finally:
                self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='continue')
            response, raw = pending.result(timeout=8)
        self.assertEqual(values(self.observed()['headers'], 'X-Generation'), ['old'])
        self.assertEqual(self.observed()['raw'], b'old')
        self.assertEqual(response.headers['X-Generation'], 'old')
        self.assertEqual(raw, b'old-response')
        response, raw = self.request(url, b'source')
        self.assertEqual(self.observed()['raw'], b'new')
        self.assertEqual(response.headers['X-Generation'], 'new')
        self.assertEqual(raw, b'new-response')

    def test_url_rewrite_routes_to_strict_tls_preserving_path_query_and_host(self):
        source = self.url('/source/%2F?x=1&x=2&keep=%2f')
        target = self.url('/target/%2F?x=1&x=2&keep=%2f', secure=True)
        self.configure(self.rule('rewrite_request_url', self.url('/source'), self.url('/target', secure=True)))
        response, raw = self.request(source, b'url body')
        self.assertEqual((response.status_code, raw), (200, b'url body'))
        self.assertEqual(self.origins[0].history, [])
        observed = self.observed(secure=True)
        self.assertEqual(observed['path'], '/target/%2F?x=1&x=2&keep=%2f')
        self.assertEqual(values(observed['headers'], 'Host'), [f'localhost:{self.origins[1].server_port}'])
        flow = self.engine.flow(target)
        self.assertEqual(flow['original_url'], source)
        entry = self.entry(target)
        self.assertEqual(entry['_lensOriginalUrl'], source)
        self.engine.command('clear')
        self.engine.command('import_har', har={'log': {'version': '1.2', 'creator': {'name': 'Lens test', 'version': '1'}, 'entries': [entry]}})
        self.assertEqual(self.entry(target), entry)

    def test_query_modes_preserve_unmatched_raw_segments_empty_fields_and_key_spelling(self):
        self.configure(self.rule('rewrite_request_query', 'tag', '新 值+', rewrite_mode='set'),
                       self.rule('rewrite_request_query', 'added key', '值 ', rewrite_mode='add'),
                       self.rule('rewrite_request_query', 'plus key', rewrite_mode='remove'))
        path = '/query/%2f?tag=one&ta%67=two&bad%ZZ=raw&%FF=opaque&bare&&keep=%2f&tag=three&plus+key=old&plus%20key=two&last='
        status, _ = self.raw_get(self.url(path))
        self.assertEqual(status, 200)
        self.assertEqual(self.observed()['path'], '/query/%2f?tag=%E6%96%B0%20%E5%80%BC%2B&bad%ZZ=raw&%FF=opaque&bare&&keep=%2f&last=&added%20key=%E5%80%BC%20')

    def test_query_remove_no_match_preserves_bare_query_marker(self):
        self.configure(self.rule('rewrite_request_query', 'absent', rewrite_mode='remove'))
        self.assertEqual(self.raw_get(self.url('/bare?'))[0], 200)
        self.assertEqual(self.observed()['path'], '/bare?')

    def test_changed_literal_url_preserves_bare_query_marker(self):
        self.configure(self.rule('rewrite_request_url', 'before-marker', 'after-marker'))
        self.assertEqual(self.raw_get(self.url('/before-marker?'))[0], 200)
        self.assertEqual(self.observed()['path'], '/after-marker?')

    def test_new_compose_preserves_selected_bare_query_marker(self):
        url, body = self.url('/composed?'), b'compose marker body'
        after = len(self.engine.events)
        identity, queued = self.engine.command('compose', request_edit={
            'url': url, 'method': 'POST', 'body_base64': base64.b64encode(body).decode()})
        self.assertTrue(queued['queued'])
        done = self.engine.wait(lambda event: event.get('command_id') == identity
                                and event.get('event') in ('request_finished', 'request_failed'), after=after)
        self.assertEqual(done['event'], 'request_finished', done)
        self.assertEqual(self.observed()['path'], '/composed?')
        self.assertEqual(self.observed()['raw'], body)

    def test_growing_query_over_64kib_aborts_before_origin(self):
        self.configure(self.rule('rewrite_request_query', 'added', 'v' * 6000))
        self.assert_aborted_rewrite(self.url('/large-query?padding=' + 'x' * 60000))
        self.assertEqual(self.origins[0].history, [])

    def test_url_first_then_all_rules_apply_in_order(self):
        source = self.url('/url-before/before?keep=before')
        target = self.url('/url-after/done?keep=done')
        self.configure(self.rule('rewrite_request_url', 'before', 'after', rewrite_count='first'),
                       self.rule('rewrite_request_url', 'before', 'done'))
        response, _ = self.request(source)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.observed()['path'], '/url-after/done?keep=done')
        self.assertEqual(self.engine.flow(target)['original_url'], source)

    def test_url_rewrite_routes_to_ipv6_with_bracketed_host(self):
        class IPv6Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        try:
            server = IPv6Server(('::1', 0), RewriteOrigin)
        except OSError as failure:
            self.skipTest(f'IPv6 loopback unavailable: {failure}')
        server.history, server.history_lock = [], threading.Lock()
        self.addCleanup(server.server_close)
        worker = threading.Thread(target=server.serve_forever, name='owned-rewrite-ipv6-origin')
        worker.start()
        self.addCleanup(self.close_origin, server, worker)
        source = self.url('/ipv6-source?x=1&x=2')
        target = f'http://[::1]:{server.server_port}/ipv6-target?x=1&x=2'
        self.configure(self.rule('rewrite_request_url', source, target))
        response, raw = self.request(source, b'IPv6 bytes')
        self.assertEqual((response.status_code, raw), (200, b'IPv6 bytes'))
        with server.history_lock:
            self.assertEqual(len(server.history), 1)
            observed = server.history[0]
        self.assertEqual(observed['path'], '/ipv6-target?x=1&x=2')
        self.assertEqual(values(observed['headers'], 'Host'), [f'[::1]:{server.server_port}'])
        self.assertEqual(self.origins[0].history, [])

    def test_url_rewrite_immediately_checks_mapped_destination_access(self):
        source, denied, allowed = self.url('/source'), self.url('/denied'), self.url('/allowed')
        self.engine.command('configure', ssl_hosts='*', rules=[
            self.rule('rewrite_request_url', source, denied),
            self.rule('rewrite_request_url', denied, allowed)], access_policy={
                'block_enabled': True, 'block': [denied], 'allow_enabled': False,
                'allow': [], 'action': 'respond'})
        response, _ = self.request(source)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.origins[0].history, [])
        flow = self.engine.flow(denied)
        self.assertEqual(flow['access_decision']['matched_url'], denied)

    def test_invalid_effective_url_aborts_without_forwarding(self):
        source = self.url('/invalid-url')
        self.configure(self.rule('rewrite_request_url', source, 'ftp://invalid.example/resource'))
        self.assert_aborted_rewrite(source)
        self.assertEqual(self.origins[0].history, [])

    def test_large_codec_diagnostic_cannot_bypass_abort_and_roundtrips_complete(self):
        # A valid HTTP/1.0 absolute-form request needs no Host field. Keeping its
        # header list empty admits the maximum single replacement field itself,
        # reaching codec failure rather than the aggregate-header growth guard.
        codec = 'x' * (65536 - len('Content-Encoding') - 4)
        self.configure(self.rule('rewrite_request_header', 'Content-Encoding', codec))
        url = self.url('/large-codec-diagnostic')
        with socket.create_connection(('127.0.0.1', self.engine.port), timeout=5) as client:
            client.sendall(f'GET {url} HTTP/1.0\r\n\r\n'.encode())
            received = bytearray()
            while chunk := client.recv(65536):
                received.extend(chunk)
                self.assertLessEqual(len(received), 512 * 1024)
        self.assertEqual(received, b'', 'Diagnostic admission must not let the original request forward')
        self.assertEqual(self.origins[0].history, [])
        flow = self.engine.flow(url, 'error')
        reason = flow['error']
        self.assertIn(codec, reason)
        self.assertGreater(len(reason.encode()), 65536)
        path = self.directory / 'large-rewrite-diagnostic.har'
        self.engine.command('save_har', path=str(path))
        document = json.loads(path.read_text())
        self.assertEqual(document['log']['entries'][0]['_lensRewriteError'], reason)
        self.engine.command('clear')
        self.engine.command('load_har', path=str(path))
        after = self.directory / 'large-rewrite-diagnostic-reopened.har'
        self.engine.command('save_har', path=str(after))
        self.assertEqual(json.loads(after.read_text()), document)

    def test_response_status_reason_and_bodyless_status_conflict(self):
        self.configure(self.rule('rewrite_response_status', '201', 'Rewritten reason'))
        response, raw = self.request(self.url('/status'), b'body')
        self.assertEqual((response.status_code, response.reason_phrase, raw), (201, 'Rewritten reason', b'body'))
        self.assertEqual(response.headers['Content-Length'], '4')
        for status in ('204', '304'):
            with self.subTest(status=status):
                self.configure(self.rule('rewrite_response_status', status, 'Bodyless'))
                self.assert_aborted_rewrite(self.url('/status-' + status), b'nonempty')


if __name__ == '__main__':
    unittest.main(verbosity=2)
