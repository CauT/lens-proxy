"""Real multipart captures retain exact bytes independently of native formatting.

Run with the bundled runtime. LENS_TEST_ENGINE also selects a packaged engine;
LENS_MULTIPART_DETAILS_DIR optionally retains synthetic detail JSON for native QA.
No system proxy, trust store, or external network is used.
"""
import base64
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

import httpx

from test_e2e import EngineHarness
from test_protocols import protocol_certificates


PREVIEW_BYTES = 2 * 1024 * 1024
FORM_TYPE = 'multipart/form-data; boundary="lens:form?=1"'
FORM = (
    b'preamble retained\r\n--lens:form?=1\r\n'
    b'Content-Disposition: form-data; name="tag"\r\n\r\nfirst\r\n'
    b'--lens:form?=1\r\nContent-Disposition: form-data; name="tag"\r\n'
    b'X-Part: one\r\nX-Part: two\r\n\r\nsecond\r\n'
    b'--lens:form?=1\r\n'
    b'Content-Disposition: form-data; name="upload"; filename="a;\\"b.bin"\r\n'
    b'Content-Type: application/octet-stream\r\n\r\n'
    b'\x00\xffbinary\r\n--lens:form?=1-not-a-delimiter\r\n'
    b'--lens:form?=1--\r\nepilogue retained'
)
MIXED_TYPE = 'multipart/mixed; boundary="outer:reply"'
MIXED = (
    b'--outer:reply\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
    + '第一段'.encode() + b'\r\n--outer:reply\r\n'
    b'Content-Type: multipart/alternative; boundary=inner-reply\r\n\r\n'
    b'--inner-reply\r\nContent-Type: text/plain\r\n\r\nplain\r\n'
    b'--inner-reply\r\nContent-Type: text/html\r\n'
    b'X-Part: first\r\nX-Part: second\r\n\r\n<p>html</p>\r\n'
    b'--inner-reply--\r\n\r\n--outer:reply--\r\n'
)


class MultipartOrigin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with self.server.history_lock:
            self.server.history.append((self.path, list(self.headers.raw_items()), body))
        if self.path == '/large':
            payload, mime, encoding = body, 'multipart/form-data; boundary=large-upload', None
        elif self.path == '/gzip':
            payload, mime, encoding = gzip.compress(MIXED, mtime=123456), MIXED_TYPE, 'gzip'
        else:
            payload, mime, encoding = MIXED, MIXED_TYPE, None
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('X-Multipart-Origin', 'first')
        self.send_header('X-Multipart-Origin', 'second')
        self.send_header('Connection', 'close')
        if encoding:
            self.send_header('Content-Encoding', encoding)
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class MultipartWireAcceptance(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lens-multipart-wire-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        ca, cert, key = protocol_certificates(self.directory)
        self.origins = []
        # Cleanup is registered immediately, including setup failures. Engines and
        # clients close first; server_close joins non-daemon request handlers.
        for secure in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), MultipartOrigin)
            server.history, server.history_lock = [], threading.Lock()
            self.addCleanup(server.server_close)
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, name='multipart-origin')
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
            raise AssertionError('Owned multipart origin did not stop')

    def capture(self, path, body=FORM, mime=FORM_TYPE, *, secure=False, encoding=None):
        server = self.origins[int(secure)]
        url = f'{"https://localhost" if secure else "http://127.0.0.1"}:{server.server_port}{path}'
        headers = [('Content-Type', mime), ('X-Multipart-Request', 'first'),
                   ('X-Multipart-Request', 'second'), ('Connection', 'close')]
        if encoding:
            headers.append(('Content-Encoding', encoding))
        with httpx.Client(proxy=self.engine.proxy, verify=self.context,
                          trust_env=False, timeout=15) as client:
            response = client.post(url, content=body, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get_list('X-Multipart-Origin'), ['first', 'second'])
        with server.history_lock:
            history = list(server.history)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0][0], path)
        self.assertEqual(history[0][2], body, 'Origin received altered multipart wire bytes')
        self.assertEqual([v for k, v in history[0][1] if k.lower() == 'x-multipart-request'],
                         ['first', 'second'])
        flow = self.engine.flow(url)
        detail = self.engine.command('detail', id=flow['id'])[1]
        self.assertEqual(flow['scheme'], 'https' if secure else 'http')
        return detail, response.content

    def retain_detail(self, name, detail):
        destination = os.environ.get('LENS_MULTIPART_DETAILS_DIR')
        if destination:
            directory = Path(destination).resolve()
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f'{name}.json').write_text(json.dumps(detail, ensure_ascii=False))
            # Persist the actual retained capture for optional native GUI import;
            # detail is only a bounded preview and cannot reconstruct a HAR.
            self.engine.command('save_har', path=str(directory / f'{name}.har'))

    def assert_preview(self, detail, request, response):
        for side, expected in [('request', request), ('response', response)]:
            self.assertEqual(base64.b64decode(detail[f'{side}_body_base64']), expected[:PREVIEW_BYTES])
            self.assertEqual(detail[f'{side}_truncated'], len(expected) > PREVIEW_BYTES)

    @staticmethod
    def har_body(description):
        return (base64.b64decode(description['text']) if description.get('encoding') == 'base64'
                else description['text'].encode())

    def stop_save_reopen(self, detail, request_decoded, response_decoded, request_raw, response_raw):
        self.engine.command('stop_capture')
        self.assertIsNone(self.engine.process.poll())
        self.assertEqual(self.engine.command('detail', id=detail['id'])[1], detail)
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', self.engine.port), timeout=.5)
        path = self.directory / 'multipart.har'
        self.engine.command('save_har', path=str(path))
        document = json.loads(path.read_text())
        self.assertEqual(len(document['log']['entries']), 1)
        entry = document['log']['entries'][0]
        self.assertEqual(self.har_body(entry['request']['postData']), request_decoded)
        self.assertEqual(self.har_body(entry['response']['content']), response_decoded)
        self.assertEqual(base64.b64decode(entry['_lensRawRequestBody']), request_raw)
        self.assertEqual(base64.b64decode(entry['_lensRawResponseBody']), response_raw)
        for side, raw, decoded in [('request', request_raw, request_decoded),
                                    ('response', response_raw, response_decoded)]:
            for decode, expected in [(False, raw), (True, decoded)]:
                exported = self.engine.command('export_body', id=detail['id'], side=side, decoded=decode)[1]
                self.assertEqual(base64.b64decode(exported['base64']), expected)
                self.assertEqual(exported['bytes'], len(expected))
        self.engine.command('clear')
        after = len(self.engine.events)
        self.engine.command('load_har', path=str(path))
        restored = self.engine.flow(detail['url'], after=after)
        reopened = self.engine.command('detail', id=restored['id'])[1]
        self.assert_preview(reopened, request_decoded, response_decoded)
        self.assertEqual(reopened['request_headers'], detail['request_headers'])
        self.assertEqual(reopened['response_headers'], detail['response_headers'])
        _, reexported = self.engine.command('export_har')
        self.assertEqual(reexported, document, 'Reopening changed a full captured HAR')
        return reopened

    def test_http_form_duplicate_names_headers_quoted_filename_and_false_boundary(self):
        detail, received = self.capture('/form')
        self.assertEqual(received, MIXED)
        self.assert_preview(detail, FORM, MIXED)
        self.assertTrue(detail['request_binary'])
        # The false boundary and escaped quote survive transport as bytes, along
        # with both repeated form values and both repeated per-part header lines.
        self.assertEqual(base64.b64decode(detail['request_body_base64']).count(b'name="tag"'), 2)
        self.retain_detail('form-http', detail)

    def test_strict_tls_nested_mixed_response_is_complete(self):
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self.context.check_hostname)
        detail, received = self.capture('/nested', secure=True)
        self.assertEqual(received, MIXED)
        self.assert_preview(detail, FORM, MIXED)
        self.assertFalse(detail['response_binary'])
        self.retain_detail('nested-https', detail)

    def test_gzip_multipart_preview_is_decoded_and_har_retains_exact_compression(self):
        raw_request = gzip.compress(FORM, mtime=654321)
        raw_response = gzip.compress(MIXED, mtime=123456)
        detail, received = self.capture('/gzip', raw_request, encoding='gzip', secure=True)
        self.assertEqual(received, MIXED)
        self.assert_preview(detail, FORM, MIXED)
        self.retain_detail('gzip-https', detail)
        reopened = self.stop_save_reopen(detail, FORM, MIXED, raw_request, raw_response)
        self.retain_detail('gzip-reopened', reopened)

    def test_large_file_preview_cut_does_not_truncate_capture_or_saved_har(self):
        # The 2 MiB cut lies inside a binary part; the next part and closing
        # delimiter exist only in the retained complete capture.
        body = (b'--large-upload\r\nContent-Disposition: form-data; name="upload"; filename="large.bin"\r\n'
                b'Content-Type: application/octet-stream\r\n\r\n'
                + bytes(range(256)) * 8449
                + b'\r\n--large-upload\r\nContent-Disposition: form-data; name="after"\r\n\r\n'
                b'after-preview-cut\r\n--large-upload--\r\n')
        self.assertGreater(len(body), PREVIEW_BYTES)
        detail, received = self.capture('/large', body, 'multipart/form-data; boundary=large-upload')
        self.assertEqual(received, body)
        self.assert_preview(detail, body, body)
        self.assertNotIn(b'after-preview-cut', base64.b64decode(detail['request_body_base64']))
        self.retain_detail('large-http', detail)
        reopened = self.stop_save_reopen(detail, body, body, body, body)
        self.retain_detail('large-reopened', reopened)


if __name__ == '__main__':
    unittest.main(verbosity=2)
