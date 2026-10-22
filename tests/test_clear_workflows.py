"""Actual proxy bytes, stopped copies and pause semantics for confirmed Clear."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from test_e2e import EngineHarness
from test_session_workflows import SessionFixture


class ClearWorkflows(SessionFixture):
    def test_copy_clear_keeps_other_room_and_reopens_exact_original_bytes(self):
        self.request('/first', b'\0\xfffirst')
        original = self.engine.flow(self.url + '/first')
        second = self.engine.command('new_session')[1]['capture_session_id']
        self.request('/second', b'other')
        path = self.directory / 'clear-copy.json'
        self.assertTrue(self.engine.command('clear', session_id='default', backup_path=str(path))[1])
        self.assertFalse(self.entries('default')); self.assertEqual(len(self.entries(second)), 1)
        self.request('/after-clear')
        self.assertEqual(len(self.entries(second)), 2)
        inspection = self.directory / 'inspection'; inspection.mkdir()
        restored = EngineHarness(inspection, None, inspect_workspace=path)
        try:
            detail = restored.command('detail', session_id='default', id=original['id'])[1]
            self.assertEqual(base64.b64decode(detail['request_body_base64']), b'\0\xfffirst')
            self.assertEqual(len(restored.command('export_har', session_id=second)[1]['log']['entries']), 1)
            self.assertTrue(restored.ready['capture_stopped'])
        finally:
            restored.close()

    def test_failed_copy_keeps_real_request_paused_then_successful_clear_continues_it(self):
        url = self.url + '/paused'
        self.engine.configure([{'kind': 'breakpoint_request', 'match': url, 'timeout_seconds': 30},
                               {'kind': 'breakpoint_response', 'match': url, 'timeout_seconds': 30}])
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.request, '/paused', b'\0\xffpaused')
            flow = self.engine.flow(url, state='paused')
            with self.assertRaisesRegex(AssertionError, 'failed'):
                self.engine.command('clear', backup_path=str(self.directory / 'missing/copy.json'))
            self.assertFalse(pending.done())
            retained = self.engine.command('detail', id=flow['id'])[1]
            self.assertEqual(retained['pause_id'], flow['pause_id'])
            path = self.directory / 'paused-copy.json'
            self.assertTrue(self.engine.command('clear', backup_path=str(path))[1])
            self.assertEqual(pending.result(timeout=5).status_code, 200)
        self.assertFalse(self.entries('default'))
        copied = json.loads(path.read_text())['sessions'][0]['har']['log']['entries'][0]
        self.assertEqual(base64.b64decode(copied['_lensRawRequestBody']), b'\0\xffpaused')
        self.assertEqual(copied['response']['status'], 0)

    def test_invalid_copy_paths_never_turn_into_destructive_clear(self):
        self.request('/keep', b'\0\xffkeep')
        original = self.engine.flow(self.url + '/keep')
        for value in (None, 42, 'relative.json', '/tmp/bad\0path'):
            with self.subTest(value=value), self.assertRaisesRegex(AssertionError, 'failed'):
                self.engine.command('clear', backup_path=value)
            detail = self.engine.command('detail', id=original['id'])[1]
            self.assertEqual(base64.b64decode(detail['request_body_base64']), b'\0\xffkeep')
