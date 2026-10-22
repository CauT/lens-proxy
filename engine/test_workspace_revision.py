import asyncio
import gc
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import weakref
from unittest.mock import patch

from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData, WebSocketMessage
import engine
from forwarding import parse_forwards
from sessions import load_workspace, save_workspace
from workspace_revision import WorkspaceRevision


class WorkspaceMutationOwnership(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.events = []
        self.emitter = patch.object(engine, 'emit', side_effect=lambda event, **v: self.events.append((event, v)))
        self.emitter.start(); self.addCleanup(self.emitter.stop)
        self.lens = engine.Lens(None, self.directory, 8890)
        self.addAsyncCleanup(self.lens.close)

    def flow(self, body=b'complete body'):
        flow = tflow.tflow(resp=True)
        flow.request.raw_content = body
        flow.response.raw_content = body + b' response'
        self.lens.prepare_capture(flow)
        self.lens.remember(flow)
        return flow

    def forward(self, transport='TCP'):
        return parse_forwards([{'listen_port': 18891, 'target_host': 'localhost', 'target_port': 18892}], [], transport=transport)[0]

    async def test_saved_snapshot_cut_does_not_include_later_arrival(self):
        first = self.flow(b'first')
        revision = self.lens.workspace_revision.current()
        entered, release = threading.Event(), threading.Event()
        path = self.directory/'saved.lens.json'
        def held(destination, snapshot):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test save release timed out')
            return save_workspace(destination, snapshot)
        with patch.object(engine, 'save_workspace', held):
            task = asyncio.create_task(self.lens.command({'command': 'save_workspace', 'path': str(path)}))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                second = self.flow(b'late')
            finally:
                release.set()
            result = await task
        self.assertEqual(result['workspace_revision'], revision)
        self.assertEqual(result['current_workspace_revision'], self.lens.workspace_revision.current())
        self.assertNotEqual(result['workspace_revision'], result['current_workspace_revision'])
        restored = load_workspace(path)
        self.assertEqual(list(restored.capture.flows), [first.id])
        self.assertNotIn(second.id, restored.capture.flows)

    async def test_quiet_save_and_stop_report_the_same_revision(self):
        self.flow()
        result = await self.lens.command({'command': 'save_workspace', 'path': str(self.directory/'quiet.lens.json')})
        stopped = await self.lens.command({'command': 'stop_capture'})
        self.assertEqual(result['workspace_revision'], result['current_workspace_revision'])
        self.assertEqual(result['workspace_revision'], stopped['workspace_revision'])
        self.assertTrue(stopped['capture_stopped'])

    async def test_catalog_and_http_mutations_but_not_publication_or_queries(self):
        state = self.lens.workspace_revision
        self.assertFalse(self.lens.sessions.has_content())
        room = self.lens.sessions.create()
        self.assertTrue(self.lens.sessions.has_content())
        before = state.current()
        self.lens.sessions.rename(room, 'Named room')
        self.assertNotEqual(state.current(), before)
        before = state.current()
        self.lens.sessions.rename(room, 'Named room')
        self.lens.sessions.activate(room)
        self.lens.publish_sessions()
        await self.lens.command({'command':'session_status'})
        self.assertEqual(state.current(), before)
        self.flow()
        self.assertNotEqual(state.current(), before)
        before = state.current()
        await self.lens.command({'command':'clear'})
        self.assertNotEqual(state.current(), before)
        before = state.current()
        await self.lens.command({'command':'clear'})
        self.assertEqual(state.current(), before)

    async def test_tcp_bytes_and_terminal_metadata_precede_throttled_summary(self):
        stream = self.lens.sessions.capture.tcp.begin(self.forward())
        stream.connected(('127.0.0.1',18892))
        stream.last_emit = time.monotonic()
        events = len(self.events)
        before = self.lens.workspace_revision.current()
        stream.data('send', b'\0\xffnew bytes')
        self.assertNotEqual(before, self.lens.workspace_revision.current())
        self.assertEqual(len(self.events), events, 'fixture did not exercise the summary throttle')
        before = self.lens.workspace_revision.current()
        stream.finish('closed')
        self.assertNotEqual(before, self.lens.workspace_revision.current())
        before = self.lens.workspace_revision.current()
        self.lens.sessions.capture.tcp.clear()
        self.assertNotEqual(before, self.lens.workspace_revision.current())

    async def test_udp_empty_datagrams_drops_and_terminal_state_are_mutations(self):
        association = self.lens.sessions.capture.udp.begin(self.forward('UDP'), ('127.0.0.1',18893), ('127.0.0.1',18891))
        association.connected(('127.0.0.1',18892))
        association.last_emit = time.monotonic()
        events = len(self.events)
        before = self.lens.workspace_revision.current()
        association.data('send', b'')
        self.assertNotEqual(before, self.lens.workspace_revision.current())
        self.assertEqual(len(self.events), events)
        before = self.lens.workspace_revision.current()
        association.dropped('receive', 1, 4)
        self.assertNotEqual(before, self.lens.workspace_revision.current())
        before = self.lens.workspace_revision.current()
        association.finish('cancelled')
        self.assertNotEqual(before, self.lens.workspace_revision.current())

    async def test_restored_raw_callbacks_bind_the_new_engine_revision_owner(self):
        self.flow()
        path = self.directory/'restored.lens.json'
        await self.lens.command({'command':'save_workspace','path':str(path)})
        self.lens.use_workspace(load_workspace(path, self.lens.sessions.emit))
        before = self.lens.workspace_revision.current()
        self.lens.sessions.capture.tcp.begin(self.forward())
        self.assertNotEqual(before, self.lens.workspace_revision.current())
        self.lens.prepare_workspace_baseline()
        self.assertEqual(self.lens.workspace_base_revision, self.lens.workspace_revision.current())
        self.assertTrue(self.lens.workspace_base_has_content)

    async def test_websocket_messages_advance_the_snapshot_revision(self):
        flow = self.flow()
        flow.websocket = WebSocketData()
        path = self.directory/'websocket.lens.json'
        saved = await self.lens.command({'command':'save_workspace','path':str(path)})
        flow.websocket.messages.append(WebSocketMessage(2, True, b'\0\xffnew websocket bytes'))
        self.lens.websocket_message(flow)
        self.assertNotEqual(saved['workspace_revision'], self.lens.workspace_revision.current())
        restored = load_workspace(path)
        self.assertEqual(restored.capture.flows[flow.id].websocket.messages, [])

    async def test_equal_sdk_client_ids_do_not_merge_physical_owners_or_gc_cleanup(self):
        first = self.flow()
        reference = weakref.ref(first.client_conn)
        self.lens.sessions.create()
        second = tflow.tflow(resp=True)
        second.client_conn.id = first.client_conn.id
        self.assertEqual(first.client_conn, second.client_conn)
        self.assertIsNot(first.client_conn, second.client_conn)
        self.lens.prepare_capture(second); self.lens.remember(second)
        await self.lens.command({'command':'clear','session_id':'default'})
        del first
        gc.collect()
        self.assertIsNone(reference())
        before = self.lens.workspace_revision.current()
        self.lens.sessions.connection_timing_changed(second.client_conn)
        self.assertNotEqual(before, self.lens.workspace_revision.current())

    async def test_imported_connection_times_do_not_become_live_mutations(self):
        self.flow()
        path = self.directory/'frozen.lens.json'
        await self.lens.command({'command':'save_workspace','path':str(path)})
        self.lens.use_workspace(load_workspace(path))
        restored = next(iter(self.lens.flows.values()))
        before = self.lens.workspace_revision.current()
        self.lens.sessions.connection_timing_changed(restored.client_conn)
        self.assertEqual(before, self.lens.workspace_revision.current())

    async def test_coalescing_keeps_the_latest_revision_and_owns_timer_cleanup(self):
        events = []
        state = WorkspaceRevision(lambda event, **v: events.append((event,v)))
        state.enable()
        for _ in range(100):
            state.changed()
        self.assertIsNotNone(state.pending)
        self.assertFalse(events)
        state.flush()
        self.assertIsNone(state.pending)
        self.assertEqual(events, [('workspace_state',{'workspace_revision':state.current()})])
        state.changed(); state.close()
        self.assertIsNone(state.pending)
        self.assertFalse(state.enabled)
        self.assertEqual(events[-1][1]['workspace_revision'], state.current())
