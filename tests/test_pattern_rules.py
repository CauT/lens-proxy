"""Real HTTP/strict-TLS/H2 acceptance for named Rewrite sets and patterns."""
import base64
from concurrent.futures import ThreadPoolExecutor
import gzip
import json
from pathlib import Path
import time

import httpx
from test_rewrite import RewriteFixture, REPEATED, values


class PatternRulesAcceptance(RewriteFixture):
    def group(self, name, rules, *, enabled=True, locations=None):
        return {'kind': 'rewrite_set', 'id': name, 'name': name, 'enabled': enabled,
                'locations': ['*'] if locations is None else locations, 'rewrite_rules': rules}

    def test_capture_groups_unicode_and_headers_on_http_strict_tls_and_h2(self):
        actions = [self.rule('rewrite_request_body', r'old (\d+)', 'new:$1', rewrite_regex=True),
                   self.rule('rewrite_response_body', r'new:(\d+)', 'final:$1', rewrite_regex=True),
                   self.rule('rewrite_request_header', r'X-(Change)', 'after-$1', rewrite_mode='replace', rewrite_name_regex=True,
                             rewrite_new_name='Seen-$1', rewrite_find=r'before (\w+)', rewrite_regex=True)]
        self.configure(self.group('API captures', actions))
        for secure, h2 in ((False, False), (True, False), (True, True)):
            with self.subTest(secure=secure, h2=h2):
                payload = 'old 12 中文\x00\xff'.encode('utf-8')
                url = self.url('/coding/gzip', secure)
                response, raw = self.request(url, gzip.compress(payload, mtime=0), [*REPEATED, ('Content-Encoding', 'gzip')], h2=h2)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.http_version, 'HTTP/2' if h2 else 'HTTP/1.1')
                self.assertEqual(gzip.decompress(raw), 'final:12 中文\x00\xff'.encode('utf-8'))
                observed = self.observed(secure=secure)
                self.assertEqual(observed['decoded'], 'new:12 中文\x00\xff'.encode('utf-8'))
                self.assertEqual(values(observed['headers'], 'Seen-Change'), ['after-one', 'after-two'])
                self.assertEqual(values(observed['headers'], 'X-Keep'), ['one', 'two'])
                flow = self.engine.flow(url)
                self.assertEqual(base64.b64decode(self.engine.command('detail', id=flow['id'])[1]['response_body_base64']), gzip.decompress(raw))

    def test_url_and_query_patterns_keep_unselected_encoded_fields_and_empty_marker(self):
        self.configure(self.group('route', [self.rule('rewrite_request_url', r'/old\?', '/new?', rewrite_regex=True),
            self.rule('rewrite_request_query', '(to)(ken)', 'new+$1', rewrite_mode='replace', rewrite_name_regex=True,
                      rewrite_new_name='$2-$1', rewrite_find=r'OLD (\d+)', rewrite_regex=True, rewrite_case_sensitive=False, rewrite_whole=True, rewrite_count='first')]))
        for secure in (False, True):
            response, _ = self.request(self.url('/old?%74oken=old+12&token=old%2023&keep=%2f&&bad=%zz', secure), b'body')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.observed(secure=secure)['path'], '/new?ken-to=new%2B12&token=old%2023&keep=%2f&&bad=%zz')

    def test_independent_sets_locations_order_and_disabled_choices(self):
        first = self.group('one', [self.rule('rewrite_request_header', 'X-Set', 'first')], locations=['never', '*match*'])
        second = self.group('two', [self.rule('rewrite_request_header', 'X-Set', 'second')], enabled=False)
        self.configure(first, second)
        self.request(self.url('/match'))
        self.assertEqual(values(self.observed()['headers'], 'X-Set'), ['first'])
        second['enabled'] = True
        self.configure(first, second); self.request(self.url('/match'))
        self.assertEqual(values(self.observed()['headers'], 'X-Set'), ['second'])
        self.configure(second, first); self.request(self.url('/match'))
        self.assertEqual(values(self.observed()['headers'], 'X-Set'), ['first'])
        self.configure(self.group('empty', first['rewrite_rules'], locations=[])); self.request(self.url('/match'))
        self.assertFalse(values(self.observed()['headers'], 'X-Set'))

    def test_group_scope_selects_original_request_and_effective_response_and_freezes_generation(self):
        url = self.url('/old')
        actions = [self.rule('rewrite_request_url', '/old', '/new'), self.rule('rewrite_request_header', 'X-Set', 'original')]
        self.configure(self.rule('breakpoint_request', timeout_seconds=30),
            self.group('original', actions, locations=['*/old']),
            self.group('response', [self.rule('rewrite_response_body', '(old)', 'captured:$1', rewrite_regex=True)], locations=['*/new']))
        with ThreadPoolExecutor(max_workers=1) as worker:
            request = worker.submit(self.request, url, b'old')
            paused = self.engine.flow(url, state='paused')
            self.configure(self.group('replacement', [self.rule('rewrite_response_body', 'old', 'later')]))
            self.engine.command('resume', id=paused['id'], pause_id=paused['pause_id'], stage='request', action='discard')
            response, raw = request.result(timeout=5)
        self.assertEqual(raw, b'captured:old')
        self.assertEqual(self.observed()['path'], '/new')
        self.assertEqual(values(self.observed()['headers'], 'X-Set'), ['original'])

    def test_invalid_pattern_or_group_keeps_previous_accepted_generation(self):
        self.configure(self.group('accepted', [self.rule('rewrite_request_header', 'X-Set', 'accepted')]))
        for bad in (self.group('bad', [self.rule('rewrite_request_body', '(', 'bad', rewrite_regex=True)]),
                    self.group('bad', [self.rule('rewrite_request_body', '(a)', '$9', rewrite_regex=True)]),
                    self.group('bad', [{'kind': 'block'}])):
            with self.subTest(bad=bad), self.assertRaises(AssertionError): self.configure(bad)
        self.request(self.url('/still-accepted'))
        self.assertEqual(values(self.observed()['headers'], 'X-Set'), ['accepted'])

    def test_match_timeout_aborts_before_origin_preserves_reason_and_recovers_for_other_urls(self):
        url = self.url('/slow')
        self.configure(self.rule('rewrite_request_body', '(a|aa)+$', 'no', match='*/slow', rewrite_regex=True, rewrite_timeout_ms=20))
        started = time.monotonic()
        self.assert_aborted_rewrite(url, b'a' * 2000 + b'!')
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(self.origins[0].history)
        detail = self.engine.command('detail', id=self.engine.flow(url, state='error')['id'])[1]
        self.assertIn('time budget', detail['error'])
        self.assertEqual(base64.b64decode(detail['request_body_base64']), b'a' * 2000 + b'!')
        response, raw = self.request(self.url('/healthy'), b'unchanged')
        self.assertEqual(raw, b'unchanged')

    def test_repeated_query_growth_is_rejected_before_origin_and_keeps_original_target(self):
        url = self.url('/growth?' + '&'.join(['k=x'] * 100))
        self.configure(self.rule('rewrite_request_query', 'k', 'a' * 32768, rewrite_mode='replace', rewrite_find='x'))
        self.assert_aborted_rewrite(url, b'body')
        self.assertFalse(self.origins[0].history)
        detail = self.engine.command('detail', id=self.engine.flow(url, state='error')['id'])[1]
        self.assertIn('before allocation', detail['error'])
        self.assertEqual(base64.b64decode(detail['request_url_base64']).decode('utf-8'), url)

    def test_stop_during_pending_pattern_request_closes_listeners_and_joins_jobs(self):
        url = self.url('/pending')
        self.configure(self.rule('rewrite_request_body', '(a|aa)+$', 'no', rewrite_regex=True, rewrite_timeout_ms=1000))
        with ThreadPoolExecutor(max_workers=1) as worker:
            request = worker.submit(self.request, url, b'a' * 10000 + b'!')
            self.engine.flow(url, state='pending')
            # A control command completes while a pattern request is pending.
            self.engine.command('session_status')
            self.engine.command('stop_capture')
            try: request.result(timeout=3)
            except httpx.HTTPError: pass
        status = self.engine.command('network_status')[1]
        self.assertFalse(status['public_listeners']); self.assertFalse(status['internal_listeners'])
        self.assertTrue(status['sdk']['admission_closed'])
        self.assertFalse(self.origins[0].history)
        self.engine.close()
        self.assertEqual(self.engine.process.returncode, 0)
