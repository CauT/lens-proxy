"""Distinct outgoing facts: source identity, raw fingerprints and hop ownership."""
import copy
import unittest
from unittest.mock import patch
from mitmproxy import http
from mitmproxy.test import tflow
from outgoing import request_fingerprint, prepare_compose, import_operation, operation_facts, transport_headers, snapshot_request, RequestTokens, INTERNAL_TOKEN_LENGTH, REPLAY_HEADER


class OutgoingFacts(unittest.TestCase):
    def test_new_legacy_and_selected_compose_share_exact_prepared_empty_query_target(self):
        selected = tflow.tflow()
        for command, flows in (({"request_edit": {"url": "http://example.test/empty?"}}, {}),
                               ({"method": "GET", "url": "http://example.test/empty?", "body": ""}, {}),
                               ({"source_id": selected.id, "request_edit": {"url": "http://example.test/empty?"}}, {selected.id: selected})):
            with self.subTest(command=command):
                result = prepare_compose(command, flows)
                self.assertEqual(result.snapshot.target, b"/empty?")
                self.assertEqual(result.url_input, "http://example.test/empty?")

    def test_owned_tokens_survive_pending_release_but_not_a_new_instance_or_tampering(self):
        owner = RequestTokens()
        value = owner.new().encode('ascii')
        self.assertEqual(len(value), INTERNAL_TOKEN_LENGTH)
        self.assertTrue(owner.owns(value))
        self.assertFalse(RequestTokens().owns(value))
        changed = value[:-1] + (b'0' if value[-1:] != b'0' else b'1')
        for foreign in (changed, b'', value + b'0', value.upper(), b'\xff' * INTERNAL_TOKEN_LENGTH,
                        b'0' * INTERNAL_TOKEN_LENGTH, 'text', None):
            with self.subTest(value=foreign): self.assertFalse(owner.owns(foreign))

    def test_generated_head_boundary_includes_complete_authenticated_token(self):
        request = http.Request.make('GET', 'http://example.test/', headers={'X-Pad': ''})
        initial = snapshot_request(request)
        size = len(b'GET / HTTP/1.1\r\n\r\n')
        size += sum(len(name) + len(value) + 4 for name, value in initial.headers)
        size += len(REPLAY_HEADER) + INTERNAL_TOKEN_LENGTH + 4
        request.headers['X-Pad'] = 'x' * (65536 - size)
        snapshot_request(request)
        request.headers['X-Pad'] += 'x'
        with patch('outgoing.h11.Request', side_effect=AssertionError('must preflight')):
            with self.assertRaisesRegex(ValueError, '64 KiB'): snapshot_request(request)

    def test_connection_interpretation_is_bounded_before_split_allocation(self):
        class NoSplit(bytes):
            def split(self, *_args, **_kwargs):
                raise AssertionError('Oversized Connection must not be split')
        for fields in (((b'Connection', NoSplit(b',' * 65536)),),
                       ((b'Connection', NoSplit(b'a' * 32768)), (b'Connection', NoSplit(b'b' * 32768)))):
            with self.subTest(count=len(fields)), self.assertRaisesRegex(ValueError, 'processing exceeds 64 KiB'):
                transport_headers(fields)

    def test_complete_head_budget_and_duplicate_host_fail_before_h11_allocation(self):
        for change, reason in (('target', '64 KiB'), ('headers', '64 KiB'), ('duplicate_host', 'one Host')):
            request = http.Request.make('GET', 'http://example.test/')
            if change == 'target':
                request.data.path = b'/' + b'x' * 65536
            elif change == 'headers':
                request.headers.add('X-Large', 'x' * 65536)
            else:
                request.headers.add('Host', 'first.test')
                request.headers.add('Host', 'second.test')
            before = request.get_state()
            with self.subTest(change=change), patch('outgoing.h11.Request', side_effect=AssertionError('must preflight')):
                with self.assertRaisesRegex(ValueError, reason):
                    snapshot_request(request)
            self.assertEqual(request.get_state(), before)

    def test_fingerprint_covers_source_representation_but_not_connection_or_live_state(self):
        source = tflow.tflow(resp=True)
        baseline = request_fingerprint(source.request)
        source.response.content = b'changed response'
        source.metadata['new display fact'] = True
        self.assertEqual(request_fingerprint(source.request), baseline)
        for change in ('body', 'method', 'header', 'trailer', 'url', 'unavailable'):
            request = source.request.copy()
            if change == 'body': request.raw_content = b'new bytes'
            elif change == 'method': request.method = 'gEt'
            elif change == 'header': request.headers.add('X-Dup', 'new')
            elif change == 'trailer': request.trailers = http.Headers([(b'X-Trailer', b'new')])
            elif change == 'url': request.url = 'http://other.test/new'
            else: request.raw_content = None
            with self.subTest(change=change): self.assertNotEqual(request_fingerprint(request), baseline)
        request = source.request.copy(); request.method = 'OPTIONS'; request.path = '*'
        asterisk = request_fingerprint(request); request.path = ''
        self.assertNotEqual(request_fingerprint(request), asterisk)
        request = source.request.copy(); request.raw_content = b''
        empty = request_fingerprint(request); request.raw_content = None
        self.assertNotEqual(request_fingerprint(request), empty)

    def test_operation_import_retains_source_input_and_rejects_incoherent_facts(self):
        good = operation_facts('compose', 'request identity', 'source identity', 'HTTP://[::1]:80/x')
        imported = import_operation(good)
        self.assertEqual(imported, good); self.assertIsNot(imported, good)
        for changes in ({'kind': []}, {'id': None}, {'source_id': []}, {'url_input': 'http://user:password@example.test/'},
                        {'url_input': 'http://example.test/#fragment'}, {'attempt': 1}, {'extra': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): import_operation({**good, **changes})
        for attempt in (True, 0, 1001, '1', None):
            with self.assertRaises(ValueError): import_operation(dict(kind='repeat', id='job', source_id='source', url_input=None, attempt=attempt))
        with self.assertRaises(ValueError): import_operation(operation_facts('replay', 'id'))

    def test_transport_rebuilds_only_hop_fields_and_keeps_origin_auth_and_wire_values(self):
        fields = ((b'Connection', b'X-Hop, keep-alive, x-\xff'), (b'X-Hop', b'private hop'),
            (b'X-', b'not the malformed nominee'), (b'Proxy-Authorization', b'transport'),
            (b'Authorization', b'origin credential'), (b'Content-Encoding', b'gzip'),
            (b'X-Dup', b'first'), (b'X-Dup', b'\xff'), (b'Host', b'old'), (b'Content-Length', b'10'))
        outgoing = transport_headers(fields)
        self.assertEqual(outgoing, ((b'X-', b'not the malformed nominee'), (b'Authorization', b'origin credential'),
            (b'Content-Encoding', b'gzip'), (b'X-Dup', b'first'), (b'X-Dup', b'\xff')))
        self.assertEqual(len(fields), 10)

    def test_legacy_text_and_source_guards_share_the_request_owner(self):
        prepared = prepare_compose({'method': 'POST', 'url': 'https://example.test/a', 'headers': [['Content-Encoding', 'gzip']], 'body': '中文'}, {})
        import gzip
        self.assertEqual(gzip.decompress(prepared.snapshot.body), '中文'.encode())
        source = tflow.tflow()
        fingerprint = request_fingerprint(source.request)
        command = {'source_id': source.id, 'source_fingerprint': fingerprint, 'request_edit': {}}
        self.assertEqual(prepare_compose(command, {source.id: source}).snapshot.body, source.request.raw_content)
        for value in (None, '', '0' * 64, fingerprint.upper()):
            if value == fingerprint: continue
            with self.assertRaises(ValueError): prepare_compose({**command, 'source_fingerprint': value}, {source.id: source})
        with self.assertRaises(ValueError): prepare_compose({'source_fingerprint': fingerprint, 'request_edit': {'url': 'http://example.test/'}}, {})
