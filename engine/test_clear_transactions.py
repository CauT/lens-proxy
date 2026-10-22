"""Clear snapshot ownership under copy failure, traffic and cancellation."""
import asyncio
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import engine
from engine import Lens
from forwarding import parse_forwards
from sessions import load_workspace
from test_sessions import captured


class ClearTransactions(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events = []
        self.output = patch.object(engine, 'emit', side_effect=lambda event, **values: self.events.append((event, values)))
        self.output.start(); self.addCleanup(self.output.stop)
        self.lens = Lens(None, self.root, 8890)

    async def asyncTearDown(self):
        await self.lens.close()

    async def clear(self, **values):
        return await self.lens.command({'command': 'clear', 'session_id': 'default', **values})

    async def test_copy_preserves_all_rooms_and_raw_records_while_clear_targets_only_http(self):
        first = self.lens.sessions.capture
        flow = captured(b'original'); self.lens.adopt_flows([flow], first); flow.intercept()
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'example.test', 'target_port': 80}], [])[0]
        tcp = first.tcp.begin(forward); tcp.data('receive', b'TCP')
        udp = first.udp.begin(forward, ('127.0.0.1', 12000), ('127.0.0.1', 10001)); udp.connected(('127.0.0.1', 80)); udp.data('receive', b'UDP')
        second = self.lens.sessions.create()
        other = captured(b'other'); self.lens.adopt_flows([other], second)
        path = self.root / 'copy.json'
        self.assertTrue(await self.clear(backup_path=str(path)))
        self.assertFalse(first.flows); self.assertFalse(flow.intercepted)
        self.assertTrue(flow.metadata['lens_skip_breakpoints'])
        self.assertIsNone(flow.error)
        self.assertIs(second.flows[other.id], other)
        self.assertEqual(len(first.tcp.streams), 1); self.assertEqual(len(first.udp.associations), 1)
        restored = load_workspace(path)
        self.assertEqual(restored.lookup(first.id).flows[flow.id].response.raw_content, b'original reply')
        self.assertEqual(len(restored.lookup(first.id).tcp.streams), 1)
        self.assertEqual(len(restored.lookup(first.id).udp.associations), 1)
        self.assertEqual([(event, values) for event, values in self.events if event == 'removed'],
                         [('removed', {'id': flow.id, 'session_id': first.id})])

    async def test_failed_atomic_replace_keeps_records_pause_and_existing_destination(self):
        flow = captured(); self.lens.adopt_flows([flow]); flow.intercept()
        destination = self.root / 'existing-directory'; destination.mkdir()
        sentinel = destination / 'previous'; sentinel.write_bytes(b'keep')
        with self.assertRaises(OSError):
            await self.clear(backup_path=str(destination))
        self.assertIs(self.lens.flows[flow.id], flow); self.assertTrue(flow.intercepted)
        self.assertNotIn('lens_skip_breakpoints', flow.metadata)
        self.assertEqual(sentinel.read_bytes(), b'keep')
        self.assertFalse(any(event == 'removed' for event, _ in self.events))

    async def pending_copy(self, *, cancel):
        old = captured(b'old'); self.lens.adopt_flows([old])
        entered, release = threading.Event(), threading.Event()
        original = engine.save_workspace
        def blocked(*args):
            entered.set()
            if not release.wait(5): raise TimeoutError('Test copy was not released')
            return original(*args)
        path = self.root / 'held.json'
        with patch.object(engine, 'save_workspace', blocked):
            task = asyncio.create_task(self.clear(backup_path=str(path)))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                new = captured(b'new'); self.lens.adopt_flows([new])
                if cancel:
                    task.cancel(); await asyncio.sleep(0); task.cancel(); await asyncio.sleep(0)
                    self.assertFalse(task.done()); self.assertTrue(self.lens.file_tasks)
                release.set()
                if cancel:
                    with self.assertRaises(asyncio.CancelledError): await task
                    self.assertEqual(set(self.lens.flows), {old.id, new.id})
                else:
                    self.assertTrue(await task)
                    self.assertEqual(set(self.lens.flows), {new.id})
                self.assertEqual(set(load_workspace(path).capture.flows), {old.id})
                self.assertFalse(self.lens.file_tasks)
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)

    async def test_new_arrivals_during_copy_are_not_cleared_or_fabricated_in_snapshot(self):
        await self.pending_copy(cancel=False)

    async def test_repeated_cancellation_joins_copy_and_does_not_clear_any_records(self):
        await self.pending_copy(cancel=True)


if __name__ == '__main__':
    unittest.main()
