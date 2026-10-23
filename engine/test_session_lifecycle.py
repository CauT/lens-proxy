"""Session identity/close ownership and workspace compatibility boundaries."""
import asyncio
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import engine
from engine import Lens
from sessions import CaptureSessions, load_workspace, save_workspace
from test_sessions import captured
from forwarding import parse_forwards


class SessionLifecycle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = []
        self.emit = patch.object(engine, 'emit', side_effect=lambda event, **values: self.events.append((event, values)))
        self.emit.start(); self.addCleanup(self.emit.stop)
        self.lens = Lens(None, self.root, 8890)
        self.lens.sessions.emit = lambda event, **values: self.events.append((event, values))

    async def asyncTearDown(self):
        await self.lens.close()

    async def command(self, operation, **values):
        return await self.lens.command({'command': operation, **values})

    async def test_rename_preserves_identity_and_invalid_names_leave_catalog_unchanged(self):
        first = self.lens.sessions.capture
        result = await self.command('rename_session', name='API \u4e2d\u6587 🦊')
        self.assertEqual(result['sessions'][0], {'id': first.id, 'number': 1, 'name': 'API \u4e2d\u6587 🦊'})
        for name in ('', ' ', 'bad\nname', '\0', 'x' * 4097, '\ud800', None, 42):
            with self.subTest(name=str(name)[:20]), self.assertRaises(ValueError):
                await self.command('rename_session', name=name)
        self.assertEqual(self.lens.sessions.public()['sessions'], result['sessions'])

    async def test_close_requires_explicit_choice_and_last_close_keeps_unique_numbered_destination(self):
        before = self.lens.sessions.public()
        with self.assertRaisesRegex(ValueError, 'explicit discard'):
            await self.command('close_session')
        self.assertEqual(self.lens.sessions.public(), before)
        first = self.lens.sessions.capture
        closed = await self.command('close_session', discard=True)
        self.assertEqual([r['number'] for r in closed['sessions']], [2])
        self.assertNotEqual(closed['capture_session_id'], first.id)
        again = await self.command('close_session', discard=True)
        self.assertEqual([r['number'] for r in again['sessions']], [3])
        self.assertEqual(self.lens.sessions.tcp_pool.recorders, [self.lens.sessions.capture.tcp])
        self.assertEqual(self.lens.sessions.udp_pool.recorders, [self.lens.sessions.capture.udp])
        with self.assertRaisesRegex(ValueError, 'no longer available'):
            await self.command('detail', session_id=first.id, id='gone')

    async def test_close_aborts_pauses_suppresses_late_capture_and_preserves_other_sessions(self):
        first = self.lens.sessions.capture
        flow = captured(); self.lens.prepare_capture(flow); self.lens.remember(flow); flow.intercept()
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'example.test', 'target_port': 80}], [])[0]
        tcp = first.tcp.begin(forward); tcp.data('receive', b'old TCP')
        udp = first.udp.begin(forward, ('127.0.0.1', 12000), ('127.0.0.1', 10001)); udp.connected(('127.0.0.1', 80)); udp.data('receive', b'old UDP')
        second = self.lens.sessions.create()
        other = captured(b'other'); self.lens.adopt_flows([other], second)
        result = await self.command('close_session', session_id=first.id, discard=True)
        self.assertFalse(flow.intercepted); self.assertIsNotNone(flow.error)
        self.assertEqual(result['capture_session_id'], second.id)
        self.assertIs(second.flows[other.id], other)
        self.assertFalse(first.flows); self.assertFalse(first.tcp.streams); self.assertFalse(first.udp.associations)
        self.events.clear()
        flow.response.raw_content = b'late'; self.lens.remember(flow)
        tcp.data('receive', b'late TCP'); tcp.finish('closed')
        udp.data('receive', b'late UDP'); udp.finish('idle')
        self.assertFalse(self.events)
        self.assertEqual(self.lens.sessions.owner(flow), first)
        self.assertFalse(first.flows)

    async def test_workspace_copy_before_close_restores_closed_and_other_http_raw_and_names(self):
        first = self.lens.sessions.capture
        await self.command('rename_session', name='Saved API')
        flow = captured(b'\0\xffbody'); self.lens.adopt_flows([flow])
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'example.test', 'target_port': 80}], [])[0]
        tcp = first.tcp.begin(forward); tcp.data('receive', b'full TCP')
        udp = first.udp.begin(forward, ('127.0.0.1', 12000), ('127.0.0.1', 10001)); udp.connected(('127.0.0.1', 80)); udp.data('receive', b'full UDP')
        second = self.lens.sessions.create(); self.lens.adopt_flows([captured(b'other')], second)
        path = self.root / 'close-copy.lens.json'
        await self.command('close_session', session_id=first.id, backup_path=str(path))
        restored = load_workspace(path)
        self.assertEqual(restored.lookup(first.id).public()['name'], 'Saved API')
        self.assertEqual(restored.lookup(first.id).flows[flow.id].request.raw_content, b'\0\xffbody')
        self.assertEqual(restored.lookup(first.id).tcp.snapshot()[0]['chunks'][0]['content'], b'full TCP')
        self.assertEqual(restored.lookup(first.id).udp.snapshot()[0]['datagrams'][0]['content'], b'full UDP')
        self.assertEqual(len(restored.lookup(second.id).flows), 1)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(restored.create().number, 3)

    async def test_failed_backup_keeps_source_and_existing_file_and_resumes_publication(self):
        room = self.lens.sessions.capture
        flow = captured(); self.lens.adopt_flows([flow])
        path = self.root / 'copy.json'; path.write_bytes(b'previous valid copy')
        with patch('sessions.export_flow', side_effect=ValueError('injected write failure')):
            with self.assertRaisesRegex(ValueError, 'injected write'):
                await self.command('close_session', backup_path=str(path))
        self.assertEqual(path.read_bytes(), b'previous valid copy')
        self.assertIs(self.lens.sessions.lookup(room.id), room)
        self.assertFalse(room.closed); self.assertIs(room.flows[flow.id], flow)
        self.assertNotEqual(self.lens.sessions.capture.id, room.id)
        self.events.clear(); self.lens.remember(flow)
        self.assertEqual(self.events[-1][1]['flow']['session_id'], room.id)

    async def test_repeated_cancellation_during_copy_joins_worker_and_keeps_session_addressable(self):
        room = self.lens.sessions.capture; self.lens.adopt_flows([captured()])
        entered, release = threading.Event(), threading.Event()
        original = engine.save_workspace
        def blocked(*args):
            entered.set(); release.wait(2); return original(*args)
        with patch.object(engine, 'save_workspace', blocked):
            task = asyncio.create_task(self.command('close_session', backup_path=str(self.root / 'copy.json')))
            await asyncio.to_thread(entered.wait, 2)
            task.cancel(); await asyncio.sleep(0); task.cancel(); await asyncio.sleep(0)
            self.assertFalse(task.done()); self.assertTrue(self.lens.file_tasks)
            self.assertIs(self.lens.sessions.lookup(room.id), room)
            release.set()
            with self.assertRaises(asyncio.CancelledError): await task
        self.assertFalse(self.lens.file_tasks); self.assertFalse(room.closed)
        self.assertIs(self.lens.sessions.lookup(room.id), room)


class WorkspaceVersions(unittest.TestCase):
    def test_v1_loads_and_v2_roundtrips_custom_names_and_high_water_after_close(self):
        sessions = CaptureSessions()
        sessions.rename(sessions.capture, 'Old capture')
        latest = sessions.create(); sessions.begin_close(latest); sessions.discard(latest)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'workspace.json'
            save_workspace(path, sessions.snapshot())
            restored = load_workspace(path)
            self.assertEqual(restored.public(), sessions.public())
            self.assertEqual(restored.create().number, 3)
            document = json.loads(path.read_text())
            document['version'] = 1; document.pop('last_number')
            for room in document['sessions']: room.pop('name')
            path.write_text(json.dumps(document))
            legacy = load_workspace(path)
            self.assertEqual(legacy.capture.public()['name'], 'Untitled Session 1')
            self.assertEqual(legacy.create().number, 2)
