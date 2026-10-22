import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mitmproxy.test import tflow
import engine
from engine import Lens
from sessions import CaptureSessions, save_workspace, load_workspace
from har import export_flow


def captured(payload=b'body'):
    flow = tflow.tflow(resp=True)
    flow.request.raw_content = payload
    flow.response.raw_content = payload + b' reply'
    return flow


class SessionOwnership(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lens = Lens(None, Path(self.temp.name), 8890)
        self.events = []
        self.emit = patch.object(engine, 'emit', side_effect=lambda event, **values: self.events.append((event, values)))
        self.emit.start(); self.addCleanup(self.emit.stop)

    async def test_new_session_keeps_old_requests_and_starts_recording_without_rebinding_proxy(self):
        old = captured()
        self.lens.prepare_capture(old)
        self.lens.remember(old)
        self.lens.recording = False
        result = await self.lens.command({'command': 'new_session'})
        self.assertTrue(self.lens.recording)
        self.assertEqual(result['view_session_id'], result['capture_session_id'])
        self.assertEqual(len(result['sessions']), 2)
        self.assertEqual(self.lens.flows, {})
        self.assertIs(self.lens.sessions.lookup('default').flows[old.id], old)
        old.response.raw_content = b'late original reply'
        self.lens.remember(old)
        self.assertEqual(self.events[-1][1]['flow']['session_id'], 'default')
        self.assertEqual(self.lens.flows, {})
        new = captured(b'next')
        self.lens.prepare_capture(new); self.lens.remember(new)
        self.assertEqual(self.lens.sessions.owner(new).id, result['capture_session_id'])

    async def test_duplicate_runtime_ids_are_separate_and_clear_is_scoped(self):
        old = captured(b'old')
        self.lens.adopt_flows([old])
        second = (await self.lens.command({'command': 'new_session'}))['capture_session_id']
        other = captured(b'new'); other.id = old.id
        self.lens.adopt_flows([other])
        identity = next(iter(self.lens.flows))
        first = await self.lens.command({'command': 'detail', 'id': identity, 'session_id': 'default'})
        latter = await self.lens.command({'command': 'detail', 'id': identity, 'session_id': second})
        self.assertNotEqual(first['response_body_base64'], latter['response_body_base64'])
        await self.lens.command({'command': 'clear', 'session_id': second})
        self.assertFalse(self.lens.flows)
        self.assertEqual(len(self.lens.sessions.lookup('default').flows), 1)
        with self.assertRaisesRegex(ValueError, 'session'):
            await self.lens.command({'command': 'detail', 'id': identity, 'session_id': 'missing'})

    async def test_import_completion_is_bound_before_file_await(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def read(*args):
            started.set(); await release.wait()
            return [captured(b'file')]
        self.lens.file_work = read
        loading = asyncio.create_task(self.lens.command({'command': 'load_har', 'path': '/tmp/owned.har', 'session_id': 'default'}))
        await started.wait()
        await self.lens.command({'command': 'new_session'})
        release.set(); await loading
        self.assertFalse(self.lens.flows)
        self.assertEqual(len(self.lens.sessions.lookup('default').flows), 1)

    async def test_header_admission_and_authenticated_outgoing_choose_owner_once(self):
        flow = captured()
        self.lens.prepare_capture(flow)
        await self.lens.command({'command': 'new_session'})
        self.assertTrue(self.lens.prepare_capture(flow))
        self.assertEqual(self.lens.sessions.owner(flow).id, 'default')
        from outgoing import PendingRequest, REPLAY_HEADER
        token = self.lens.request_tokens.new()
        pending = PendingRequest({'kind': 'compose', 'id': 'job'}, session=self.lens.sessions.lookup('default'))
        self.lens.pending_requests[token] = pending
        generated = captured(); generated.request.headers[REPLAY_HEADER] = token
        self.assertTrue(self.lens.prepare_capture(generated))
        self.assertIs(self.lens.sessions.owner(generated), pending.session)
        self.assertIs(pending.flow, generated)
        self.assertNotIn(REPLAY_HEADER, generated.request.headers)
        self.assertTrue(self.lens.prepare_capture(generated))

    async def test_global_retention_spans_sessions_and_keeps_paused_owner(self):
        old = captured(); old.intercept()
        self.lens.prepare_capture(old); self.lens.remember(old)
        await self.lens.command({'command': 'new_session'})
        with patch.object(engine, 'MAX_FLOWS', 2):
            first, second = captured(b'first'), captured(b'second')
            self.lens.prepare_capture(first); self.lens.remember(first)
            self.lens.prepare_capture(second); self.lens.remember(second)
        self.assertIn(old.id, self.lens.sessions.lookup('default').flows)
        self.assertNotIn(first.id, self.lens.flows)
        self.assertIn(second.id, self.lens.flows)
        await self.lens.command({'command': 'clear', 'session_id': 'default'})
        self.assertFalse(old.intercepted)


class WorkspacePersistence(unittest.TestCase):
    def test_workspace_roundtrip_preserves_duplicate_ids_between_maps_and_public_har(self):
        sessions = CaptureSessions()
        old = captured(b'\0\xfffirst')
        sessions.owner(old); sessions.capture.flows[old.id] = old
        new = sessions.create()
        another = old.copy(); another.id = old.id; another.response.raw_content = b'other'
        sessions.owner(another, new); new.flows[another.id] = another
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'workspace.json'
            save_workspace(path, sessions.snapshot())
            restored = load_workspace(path)
            self.assertEqual(restored.public(), sessions.public())
            for identity, room in sessions.items.items():
                self.assertEqual(list(restored.lookup(identity).flows), list(room.flows))
                self.assertEqual([export_flow(flow) for flow in restored.lookup(identity).flows.values()],
                                 [export_flow(flow) for flow in room.flows.values()])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_invalid_workspace_fails_before_publishing_or_replacing_previous_file(self):
        sessions = CaptureSessions()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'workspace.json'
            save_workspace(path, sessions.snapshot())
            valid = path.read_bytes()
            document = json.loads(valid)
            for invalid in (None, True, 'missing'):
                document['capture_session_id'] = invalid
                path.write_text(json.dumps(document))
                with self.subTest(invalid=invalid), self.assertRaises(ValueError): load_workspace(path)
            path.write_bytes(valid)
            broken = captured(); broken.response.raw_content = b'x' * 20
            sessions.owner(broken); sessions.capture.flows[broken.id] = broken
            with patch('sessions.export_flow', side_effect=ValueError('injected serialization failure')):
                with self.assertRaisesRegex(ValueError, 'serialization'):
                    save_workspace(path, sessions.snapshot())
            self.assertEqual(path.read_bytes(), valid)
            self.assertEqual(list(Path(folder).iterdir()), [path])

class RawSessionOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_raw_owners_survive_new_session_and_only_selected_commands_clear_them(self):
        from forwarding import parse_forwards
        from udp_capture import DATAGRAM_OVERHEAD
        events = []
        rooms = CaptureSessions(lambda event, **values: events.append((event, values)))
        first = rooms.capture
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'EXAMPLE.test.', 'target_port': 80}], [])[0]
        tcp = first.tcp.begin(forward); tcp.connected(('127.0.0.1', 80))
        udp = first.udp.begin(forward, ('127.0.0.1', 20001), ('127.0.0.1', 10001))
        udp.connected(('127.0.0.1', 80))
        second = rooms.create()
        tcp.data('receive', b'late TCP'); tcp.finish('closed')
        udp.data('receive', b'late UDP'); udp.finish('idle')
        self.assertEqual(events[-1][1]['session_id'], first.id)
        self.assertFalse(second.tcp.streams); self.assertFalse(second.udp.associations)
        lens = Lens(None, Path('/tmp/unused-session-test'), 8890); lens.sessions = rooms
        self.assertEqual((await lens.command({'command': 'tcp_detail', 'session_id': first.id, 'id': tcp.value['id']}))['total'], 1)
        with self.assertRaises(KeyError): await lens.command({'command': 'tcp_detail', 'session_id': second.id, 'id': tcp.value['id']})
        await lens.command({'command': 'clear_udp', 'session_id': second.id})
        self.assertEqual(first.udp.cost, len(b'late UDP') + DATAGRAM_OVERHEAD)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'all.lens.json'; save_workspace(path, rooms.snapshot())
            restored_events = []
            restored = load_workspace(path, lambda event, **values: restored_events.append((event, values)))
            self.assertFalse(restored_events)  # No event before the complete catalog is admitted.
            self.assertEqual(restored.public(), rooms.public())
            self.assertEqual(restored.lookup(first.id).tcp.snapshot()[0]['chunks'][0]['content'], b'late TCP')
            self.assertEqual(restored.lookup(first.id).udp.snapshot()[0]['datagrams'][0]['content'], b'late UDP')
            restored.lookup(first.id).tcp.clear()
            self.assertEqual(restored_events[-1][1]['session_id'], first.id)

    async def test_global_raw_budget_and_count_are_shared_without_moving_active_owners(self):
        from forwarding import parse_forwards
        from tcp_capture import CHUNK_OVERHEAD
        from udp_capture import DATAGRAM_OVERHEAD
        rooms = CaptureSessions()
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'example.test', 'target_port': 80}], [])[0]
        first = rooms.capture
        old_tcp = first.tcp.begin(forward); old_tcp.data('send', b'old')
        old_udp = first.udp.begin(forward, ('127.0.0.1', 20001), ('127.0.0.1', 10001)); old_udp.connected(('127.0.0.1', 80)); old_udp.data('send', b'old')
        rooms.tcp_pool.limit = CHUNK_OVERHEAD + 3
        rooms.udp_pool.limit = DATAGRAM_OVERHEAD + 3
        second = rooms.create()
        new_tcp = second.tcp.begin(forward); new_tcp.data('send', b'new')
        new_udp = second.udp.begin(forward, ('127.0.0.1', 20002), ('127.0.0.1', 10001)); new_udp.connected(('127.0.0.1', 80)); new_udp.data('send', b'new')
        self.assertFalse(old_tcp.retained); self.assertFalse(old_udp.retained)
        old_tcp.data('send', b'after eviction'); old_udp.data('send', b'after eviction')
        self.assertEqual(first.tcp.cost, 0); self.assertEqual(first.udp.cost, 0)
        self.assertEqual(sum(r.tcp.cost for r in rooms.items.values()), CHUNK_OVERHEAD + 3)
        self.assertEqual(sum(r.udp.cost for r in rooms.items.values()), DATAGRAM_OVERHEAD + 3)
        rooms.tcp_pool.count = rooms.udp_pool.count = 1
        third = rooms.create()
        third.tcp.begin(forward); third.udp.begin(forward, ('127.0.0.1', 20003), ('127.0.0.1', 10001))
        self.assertFalse(new_tcp.retained); self.assertFalse(new_udp.retained)
        for room in rooms.items.values(): room.udp.clear()

    async def test_raw_import_admission_preserves_other_sessions_on_shared_budget_failure(self):
        from forwarding import parse_forwards
        rooms = CaptureSessions()
        forward = parse_forwards([{'listen_port': 10001, 'target_host': 'example.test', 'target_port': 80}], [])[0]
        old = rooms.capture.tcp.begin(forward); old.data('send', b'keep')
        rooms.tcp_pool.count = 1
        second = rooms.create()
        with self.assertRaisesRegex(ValueError, 'shared'):
            rooms.tcp_pool.admit_replacement(second.tcp, 1, 0)
        self.assertTrue(old.retained)
        self.assertEqual(old.chunks[0]['content'], b'keep')
