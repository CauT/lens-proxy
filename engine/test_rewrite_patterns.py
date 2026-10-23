import asyncio
import contextlib
import copy
import io
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

from mitmproxy import http
from engine import Lens, RulePlan
from rewrite import prepare
from rewrite_text import TextRewrite
from test_rewrite import request_flow


class PatternBoundaries(unittest.TestCase):
    def test_unicode_groups_named_groups_quoting_and_opaque_bytes_are_preserved(self):
        operation = TextRewrite.prepare({'rewrite_regex': True}, r'(?<key>\w+)=(\d+)', '${key}:$2;\\$1', 1024)
        source = '\u4e2d\u6587=12 x=34'.encode() + b'\xff'
        self.assertEqual(operation.plan(source, 1024).render(), '\u4e2d\u6587:12;$1 x:34;$1'.encode() + b'\xff')
        literal = TextRewrite.prepare({}, 'x', '$1\\end', 1024)
        self.assertEqual(literal.plan(b'x', 1024).render(), b'$1\\end')
        empty = TextRewrite.prepare({'rewrite_regex': True}, '', 'entire', 1024)
        self.assertEqual(empty.plan(b'anything', 1024).render(), b'entire')

    def test_first_whole_case_and_invalid_group_selections_are_explicit(self):
        operation = TextRewrite.prepare({'rewrite_regex': True, 'rewrite_count': 'first'}, r'foo|(?:a|aa)+$', 'hit', 1024)
        self.assertEqual(operation.plan(b'foo ' + b'a' * 300 + b'!', 1024).render(), b'hit ' + b'a' * 300 + b'!')
        whole = TextRewrite.prepare({'rewrite_whole': True, 'rewrite_case_sensitive': False}, 'match', 'yes', 1024)
        self.assertEqual(whole.plan(b'MATCH', 1024).render(), b'yes')
        self.assertEqual(whole.plan(b'prefix MATCH', 1024).render(), b'prefix MATCH')
        for value in ('$2', '${missing}', '$', 'tail\\'):
            with self.subTest(value=value), self.assertRaises(ValueError): TextRewrite.prepare({'rewrite_regex': True}, '(a)', value, 1024)
        for choice in ({'rewrite_regex': 1}, {'rewrite_timeout_ms': True}, {'rewrite_timeout_ms': 5001}):
            with self.subTest(choice=choice), self.assertRaises(ValueError): TextRewrite.prepare(choice, 'a', 'b', 1024)

    def test_capture_expansion_is_measured_before_allocating_output_and_timeout_is_bounded(self):
        operation = TextRewrite.prepare({'rewrite_regex': True}, '(a+)', '$1$1$1', 1024)
        with patch('rewrite_text.bytearray', side_effect=AssertionError('must not allocate expanded output'), create=True):
            with self.assertRaisesRegex(ValueError, 'before allocation'): operation.plan(b'a' * 512, 1024)
        slow = TextRewrite.prepare({'rewrite_regex': True, 'rewrite_timeout_ms': 5}, '(a|aa)+$', 'no', 1024)
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'time budget'): slow.plan(b'a' * 1000 + b'!', 4096)
        self.assertLess(time.monotonic() - start, .5)

    def test_name_and_value_groups_rename_only_value_matches_and_preserve_duplicate_order(self):
        flow = request_flow()
        flow.request.headers = http.Headers([(b'X-Foo', b'id=12 id=13'), (b'Other', b'keep'), (b'x-Bar', b'unmatched'), (b'X-FOO', b'id=14')])
        action = prepare({'kind': 'rewrite_request_header', 'rewrite_mode': 'replace', 'name': 'X-(Foo|Bar)',
            'rewrite_name_regex': True, 'rewrite_new_name': 'Seen-$1', 'rewrite_find': r'id=(\d+)', 'value': 'item-$1', 'rewrite_regex': True, 'rewrite_count': 'first'})
        action.edit(flow, 'request').apply(flow)
        self.assertEqual(flow.request.headers.fields, ((b'Seen-Foo', b'item-12 id=13'), (b'Other', b'keep'), (b'x-Bar', b'unmatched'), (b'X-FOO', b'id=14')))
        bad = prepare({'kind': 'rewrite_request_header', 'rewrite_mode': 'replace', 'name': 'Seen-(.*)', 'rewrite_name_regex': True,
            'rewrite_new_name': 'Content-Length', 'rewrite_find': '(.*)', 'rewrite_regex': True, 'value': '$1'})
        before = flow.request.get_state()
        with self.assertRaises(ValueError): bad.edit(flow, 'request')
        self.assertEqual(flow.request.get_state(), before)

    def test_query_replaces_decoded_values_renames_names_and_keeps_untouched_source_bytes(self):
        flow = request_flow()
        flow.request.data.path = b'/api?%61bc=old+12&abc=old%2023&keep=%2f&&bad=%zz'
        action = prepare({'kind': 'rewrite_request_query', 'rewrite_mode': 'replace', 'name': '(a)(bc)', 'rewrite_name_regex': True,
            'rewrite_new_name': '$2-$1', 'rewrite_find': r'old (\d+)', 'rewrite_regex': True, 'value': 'new+$1', 'rewrite_count': 'first'})
        action.edit(flow, 'request').apply(flow)
        self.assertEqual(flow.request.data.path, b'/api?bc-a=new%2B12&abc=old%2023&keep=%2f&&bad=%zz')
        operation = prepare({'kind': 'rewrite_request_query', 'rewrite_mode': 'remove', 'name': '^a', 'rewrite_name_regex': True})
        operation.edit(flow, 'request').apply(flow)
        self.assertEqual(flow.request.data.path, b'/api?bc-a=new%2B12&keep=%2f&&bad=%zz')
        missing = request_flow(); missing.request.data.path = b'/no-query'
        replacement = prepare({'kind': 'rewrite_request_query', 'rewrite_mode': 'replace', 'name': 'missing', 'rewrite_find': 'old', 'value': 'new'})
        replacement.edit(missing, 'request').apply(missing)
        self.assertEqual(missing.request.data.path, b'/no-query')

    def test_opaque_url_and_unmatched_header_source_are_not_revalidated(self):
        flow = request_flow(); flow.request.data.path = b'/opaque\xff?empty='
        action = prepare({'kind': 'rewrite_request_url', 'name': 'never matching', 'value': 'new', 'rewrite_regex': True})
        action.edit(flow, 'request').apply(flow)
        self.assertEqual(flow.request.data.path, b'/opaque\xff?empty=')
        flow.request.headers = http.Headers([(b'X-Old', b'opaque\0source')])
        header = prepare({'kind': 'rewrite_request_header', 'name': 'X-Old', 'rewrite_name_regex': True, 'rewrite_mode': 'replace', 'rewrite_find': 'absent', 'value': 'new'})
        original = flow.request.headers
        self.assertIs(header.fields(original), original)

    def test_query_aggregate_expansion_rejects_before_any_value_render(self):
        flow = request_flow(); flow.request.data.path = b'/p?k=x&k=x'
        action = prepare({'kind': 'rewrite_request_query', 'name': 'k', 'rewrite_mode': 'replace', 'rewrite_find': 'x', 'value': 'a' * 40})
        with patch('rewrite.URL_BYTES', 64), patch('rewrite.TextRewrite.plan', wraps=action.operation.plan) as planning:
            with patch('rewrite_text.TextPlan.render', side_effect=AssertionError('must not render rejected output')):
                with self.assertRaisesRegex(ValueError, 'before allocation'): action.edit(flow, 'request')
        self.assertEqual(flow.request.data.path, b'/p?k=x&k=x')


class SetConfiguration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO()); self.output.__enter__()
        master = Mock(); master.addons.get.return_value = None
        self.lens = Lens(master, Path('/tmp'), 8890)

    async def asyncTearDown(self):
        await self.lens.close(); self.output.__exit__(None, None, None)

    async def configure(self, rules):
        return await self.lens.command({'command': 'configure', 'rules': rules})

    def group(self, name='first', enabled=True, value='one', locations=None):
        return {'kind': 'rewrite_set', 'id': name, 'name': name, 'enabled': enabled, 'locations': ['*'] if locations is None else locations,
            'rewrite_rules': [{'kind': 'rewrite_request_header', 'name': 'X-Set', 'value': value}]}

    async def test_named_scopes_locations_enable_order_and_immutable_generation(self):
        first, second = self.group(), self.group('second', value='two')
        rules = [first, second]; before = copy.deepcopy(rules)
        await self.configure(rules)
        self.assertEqual(rules, before)
        snapshot = self.lens.rules
        self.assertIsNot(snapshot[0].scope, snapshot[1].scope)
        first['locations'][0] = 'never'; first['rewrite_rules'][0]['value'] = 'mutated'
        flow = request_flow(); await self.lens.request(flow)
        self.assertEqual(flow.request.headers['X-Set'], 'two')
        await self.configure([self.group(), self.group('second', enabled=False, value='two')])
        flow = request_flow(); await self.lens.request(flow)
        self.assertEqual(flow.request.headers['X-Set'], 'one')
        await self.configure([self.group(locations=[])])
        flow = request_flow(); await self.lens.request(flow)
        self.assertNotIn('X-Set', flow.request.headers)
        plan = RulePlan.select(snapshot, 0, flow.request.url)
        self.assertEqual(len(plan.request_rules), 2)

    async def test_invalid_late_group_preserves_previous_configuration_and_limits_all_rows(self):
        await self.configure([self.group()]); previous = self.lens.rules
        invalid = self.group('invalid'); invalid['rewrite_rules'] = [{'kind': 'block'}]
        with self.assertRaises(ValueError): await self.configure([self.group('new'), invalid])
        self.assertIs(self.lens.rules, previous)
        excessive = self.group(); excessive['locations'] = ['*'] * 500
        with self.assertRaises(ValueError): await self.configure([excessive])
        self.assertIs(self.lens.rules, previous)

    async def test_pattern_worker_cancellation_joins_execution_and_does_not_publish_edit(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        await self.configure([{'kind': 'rewrite_request_body', 'name': '(old)', 'value': 'new', 'rewrite_regex': True}])
        action = self.lens.rules[0].rewrite
        original = type(action).edit
        def edit(owner, flow, stage):
            entered.set(); release.wait(2)
            return original(owner, flow, stage)
        flow = request_flow()
        with patch.object(type(action), 'edit', edit):
            task = asyncio.create_task(self.lens.request(flow))
            await asyncio.to_thread(entered.wait, 2)
            task.cancel(); await asyncio.sleep(0)
            task.cancel(); await asyncio.sleep(0)
            self.assertEqual(self.lens.rewrite_worker._value, 0)
            self.assertFalse(task.done()); self.assertTrue(self.lens.file_tasks)
            release.set()
            with self.assertRaises(asyncio.CancelledError): await task
        self.assertFalse(self.lens.file_tasks)
        self.assertEqual(flow.request.raw_content, b'old')

    async def test_cancelled_worker_observes_late_failure_before_releasing_ownership(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        def failed():
            entered.set(); release.wait(2)
            raise ValueError("late matching failure")
        task = asyncio.create_task(self.lens.file_work(failed))
        await asyncio.to_thread(entered.wait, 2)
        worker = next(iter(self.lens.file_tasks))
        task.cancel(); await asyncio.sleep(0)
        release.set()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertFalse(self.lens.file_tasks)
        self.assertFalse(worker._log_traceback, "Late failure was never observed by its owner")
