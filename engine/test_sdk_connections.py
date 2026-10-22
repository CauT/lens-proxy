"""Real SDK handler ownership plus injected stream cleanup outcome regressions."""
import asyncio
import contextlib
import inspect
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from mitmproxy import options
from mitmproxy.utils.asyncio_utils import set_eager_task_factory
from mitmproxy.proxy.layers.tcp import TCPLayer
from mitmproxy.proxy.mode_servers import ProxyConnectionHandler
from mitmproxy.proxy.mode_specs import ProxyMode

from engine import Lens
from network import ProxyRelays
from sdk_connections import SDKConnections


class ListenerOwners:
    """Inject only the SDK manager's known close-without-join behavior."""
    def __init__(self):
        self.instances = []

    def __iter__(self):
        return iter(self.instances)

    async def update(self, modes):
        assert modes == []
        for instance in self.instances:
            for server in instance._servers:
                server.close()
            instance._servers = []
        self.instances = []
        return True


class SDKRealOwnership(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Master.run uses this exact pinned SDK context. Finalizers can complete
        # inside create_task, before its returned task is assigned to a field.
        eager = set_eager_task_factory()
        eager.__enter__()
        self.addCleanup(eager.__exit__, None, None, None)
        self.directory = tempfile.TemporaryDirectory(prefix='lens-sdk-owner-')
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.lens = Lens(None, Path(self.directory.name), 8890)
        self.proxy = SimpleNamespace(connections={}, servers=ListenerOwners())
        self.lens.proxy_server = lambda: self.proxy
        self.outer_tasks = set()
        self.handlers = []
        self.clients = []
        self.origin_writers = set()
        self.origin_eof = asyncio.Event()
        self.origin_payload = bytearray()
        self.gate = None

        async def origin(reader, writer):
            self.origin_writers.add(writer)
            try:
                while chunk := await reader.read(4096):
                    self.origin_payload.extend(chunk)
                self.origin_eof.set()
            finally:
                writer.close()
                await writer.wait_closed()
                self.origin_writers.discard(writer)
        self.origin = await asyncio.start_server(origin, '127.0.0.1', 0)
        target = self.origin.sockets[0].getsockname()
        self.origin_target = target

        async def lifecycle(event):
            (data,) = event.args()
            if event.name == 'next_layer':
                data.layer = TCPLayer(data.context, ignore=True)
                return
            if event.name == 'client_connected' and self.gate is not None:
                self.gate[0].set()
                await self.gate[1].wait()
            callback = getattr(self.lens, event.name, None)
            if callback is not None:
                result = callback(data)
                if inspect.isawaitable(result):
                    await result
        master = SimpleNamespace(addons=SimpleNamespace(handle_lifecycle=lifecycle))

        async def accepted(reader, writer):
            task = asyncio.current_task()
            self.outer_tasks.add(task)
            handler = ProxyConnectionHandler(master, reader, writer, options.Options(), ProxyMode.parse('regular'))
            handler.layer.context.server.address = target
            self.handlers.append(handler)
            self.proxy.connections[handler.client.id] = handler
            try:
                await handler.handle_client()
            finally:
                self.proxy.connections.pop(handler.client.id, None)
                self.outer_tasks.discard(task)
        self.server = await asyncio.start_server(accepted, '127.0.0.1', 0)
        self.proxy.servers.instances = [SimpleNamespace(_servers=[self.server])]

    async def asyncTearDown(self):
        if self.gate is not None:
            self.gate[1].set()
        # Preserve/finish the actual SDK outer task, even against the regression
        # baseline which does not yet have Lens SDK ownership integration.
        for handler in self.handlers:
            for item in list(handler.transports.values()):
                if item.handler is not None:
                    item.handler.cancel('test fixture cleanup')
                if item.writer is not None:
                    item.writer.close()
        for writer in self.clients:
            writer.close()
            await writer.wait_closed()
        if self.outer_tasks:
            await asyncio.wait(self.outer_tasks, timeout=2)
        await self.lens.close()
        self.server.close()
        await self.server.wait_closed()
        for writer in list(self.origin_writers):
            writer.close()
            await writer.wait_closed()
        self.origin.close()
        await self.origin.wait_closed()
        self.output.__exit__(None, None, None)
        self.directory.cleanup()

    async def connect(self):
        reader, writer = await asyncio.open_connection(*self.server.sockets[0].getsockname())
        self.clients.append(writer)
        return reader, writer

    async def ready(self):
        async with asyncio.timeout(2):
            while not self.handlers or len(self.handlers[0].transports) < 2:
                await asyncio.sleep(0)
            while any(item.writer is None for item in self.handlers[0].transports.values()):
                await asyncio.sleep(0)

    async def test_stop_joins_real_sdk_outer_and_upstream_not_only_listener(self):
        reader, writer = await self.connect()
        await self.ready()
        owner = next(iter(self.outer_tasks))
        self.assertFalse(owner.done())
        await self.lens.command({'command': 'stop_capture'})
        self.assertFalse(self.proxy.connections, 'listener Stop alone leaves real SDK handlers alive')
        self.assertTrue(owner.done())
        self.assertFalse(owner.cancelled(), 'cancel inner reader; let actual outer SDK cleanup finish')
        await asyncio.wait_for(self.origin_eof.wait(), 1)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        status = await self.lens.command({'command': 'network_status'})
        self.assertTrue(status['sdk']['admission_closed'])
        for key in ('active_handlers', 'registry_connections', 'pending_cleanup', 'retained_owners', 'retained_writers', 'pending_listeners'):
            self.assertEqual(status['sdk'][key], 0, key)

    async def test_normal_eof_retires_owner_with_actual_sdk_eager_factory(self):
        _, writer = await self.connect()
        await self.ready()
        outer = next(iter(self.outer_tasks))
        observed = next(iter(self.lens.sdk_connections.connections))
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(asyncio.shield(outer), 2)
        # The actual outer task's done callbacks own finalizer admission. Join
        # those tasks directly: no Stop, polling, or fixture cleanup can retire
        # a leaked normally-completed owner on the implementation's behalf.
        await asyncio.shield(observed.outer_ended)
        self.assertIsNotNone(observed.cleanup)
        await observed.cleanup
        sdk = self.lens.sdk_connections.status(self.proxy)
        for key in ('active_handlers', 'registry_connections', 'pending_cleanup', 'retained_owners', 'retained_writers'):
            self.assertEqual(sdk[key], 0, key)

    async def test_late_client_handshake_is_refused_and_joined_after_listener_stop(self):
        self.gate = (asyncio.Event(), asyncio.Event())
        reader, _ = await self.connect()
        await self.gate[0].wait()
        stopping = asyncio.create_task(self.lens.command({'command': 'stop_capture'}))
        await asyncio.sleep(0)
        self.gate[1].set()
        await asyncio.wait_for(stopping, 3)
        self.assertFalse(self.proxy.connections or self.outer_tasks)
        self.assertIn('stopped', self.handlers[0].client.error.lower())
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')

    async def test_connect_deadline_cancels_exact_sdk_dial_and_keeps_its_selected_generation(self):
        entered = asyncio.Event()
        original = asyncio.open_connection
        async def held(*address, **options):
            if address == self.origin_target:
                entered.set()
                await asyncio.Event().wait()
            return await original(*address, **options)
        self.lens.network.configure({'connect_timeout_seconds': 1})
        with patch('asyncio.open_connection', held):
            reader, _ = await self.connect()
            await asyncio.wait_for(entered.wait(), 1)
            self.lens.network.configure({'connect_timeout_seconds': 5})
            self.assertEqual(self.lens.sdk_connections.status(self.proxy)['pending_connects'], 1)
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        self.assertIn('timed out after 1 s', self.handlers[0].layer.context.server.error)
        self.assertEqual(self.lens.sdk_connections.status(self.proxy)['pending_connects'], 0)

    async def test_established_connections_outlive_connect_deadline(self):
        self.lens.network.configure({'connect_timeout_seconds': 1})
        _, writer = await self.connect()
        await self.ready()
        self.assertEqual(self.lens.sdk_connections.status(self.proxy)['pending_connects'], 0)
        await asyncio.sleep(1.05)
        writer.write(b'established connection remains usable')
        await writer.drain()
        async with asyncio.timeout(1):
            while not self.origin_payload:
                await asyncio.sleep(0)
        self.assertEqual(self.origin_payload, b'established connection remains usable')

    async def test_stop_cancels_pending_deadline_without_reporting_a_timeout(self):
        entered = asyncio.Event()
        original = asyncio.open_connection
        async def held(*address, **options):
            if address == self.origin_target:
                entered.set()
                await asyncio.Event().wait()
            return await original(*address, **options)
        self.lens.network.configure({'connect_timeout_seconds': 1})
        with patch('asyncio.open_connection', held):
            reader, _ = await self.connect()
            await asyncio.wait_for(entered.wait(), 1)
            await self.lens.command({'command': 'stop_capture'})
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        self.assertEqual(self.lens.sdk_connections.status(self.proxy)['pending_connects'], 0)
        self.assertNotIn('timed out', self.handlers[0].layer.context.server.error)

    async def test_late_dial_after_timeout_is_closed_without_forwarding(self):
        original = asyncio.open_connection
        async def late(*address, **options):
            if address == self.origin_target:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    pass  # inject a transport completing after cancellation
            return await original(*address, **options)
        self.lens.network.configure({'connect_timeout_seconds': 1})
        with patch('asyncio.open_connection', late):
            reader, writer = await self.connect()
            writer.write(b'must not reach late origin')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b'')
        await asyncio.wait_for(self.origin_eof.wait(), 1)
        self.assertEqual(self.origin_payload, b'')
        self.assertEqual(self.lens.sdk_connections.status(self.proxy)['pending_connects'], 0)


class Writer:
    def __init__(self, *, fail=False, held=False):
        self.fail = fail
        self.closed = False
        self.waiting = asyncio.Event()
        self.release = asyncio.Event()
        if not held:
            self.release.set()
        self.transport = SimpleNamespace(abort=lambda: None)

    def close(self):
        if self.fail:
            raise OSError('injected SDK stream close failure')
        self.closed = True

    async def wait_closed(self):
        self.waiting.set()
        await self.release.wait()


class SDKCleanupOutcomes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        eager = set_eager_task_factory()
        eager.__enter__()
        self.addCleanup(eager.__exit__, None, None, None)
        self.streams = ProxyRelays()
        self.owner = SDKConnections(self.streams)
        self.proxy = SimpleNamespace(connections={}, servers=ListenerOwners())
        self.tasks = []
        self.writers = []
        self.addCleanup(patch.stopall)
        patch('sdk_connections.JOIN_SECONDS', .05).start()
        patch('network.CLOSE_TIMEOUT', .05).start()

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.fail = False
            writer.release.set()
        await self.owner.close(self.proxy)
        await self.streams.close()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def accepted(self, writer, final_gate=None):
        self.writers.append(writer)
        ready = asyncio.Event()
        client = SimpleNamespace(id=str(len(self.tasks)), error=None)
        # SDK connections are identity-hashable; a namespace is not.
        client = type('Client', (), dict(id=client.id, error=None))()
        async def outer():
            handler = SimpleNamespace(client=client, transports={client: SimpleNamespace(handler=None, writer=writer)})
            self.proxy.connections[client.id] = handler
            self.owner.client_connected(self.proxy, client)
            inner = asyncio.create_task(asyncio.Event().wait())
            handler.transports[client].handler = inner
            ready.set()
            try:
                await asyncio.wait({inner})
            finally:
                if final_gate is not None:
                    await final_gate.wait()
                self.proxy.connections.pop(client.id, None)
        task = asyncio.create_task(outer())
        self.tasks.append(task)
        await ready.wait()
        return task

    async def test_mixed_stream_failure_preserves_failed_owner_and_retries(self):
        good, bad = Writer(), Writer(fail=True)
        await self.accepted(good)
        await self.accepted(bad)
        with self.assertLogs('network', level='WARNING'):
            with self.assertRaisesRegex(RuntimeError, 'retains SDK'):
                await self.owner.close(self.proxy)
        self.assertTrue(good.closed)
        self.assertEqual(len(self.owner.connections), 1)
        self.assertIn(bad, self.streams.closing)
        bad.fail = False
        await self.owner.close(self.proxy)
        self.assertFalse(self.owner.connections or self.streams.closing or self.streams.close_waiters)

    async def test_stop_cancellation_keeps_same_shielded_cleanup_and_writer_waiter(self):
        writer = Writer(held=True)
        await self.accepted(writer)
        stopping = asyncio.create_task(self.owner.close(self.proxy))
        await writer.waiting.wait()
        cleanup = self.owner.cleanup
        waiter = self.streams.close_waiters[writer]
        stopping.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await stopping
        self.assertFalse(cleanup.cancelled() or waiter.cancelled())
        self.assertTrue(self.owner.connections)
        writer.release.set()
        await self.owner.close(self.proxy)
        self.assertTrue(cleanup.done() and waiter.done())
        self.assertFalse(self.owner.connections or self.streams.closing)

    async def test_unknown_owned_writer_is_refused_before_drift_is_reported(self):
        client = type('Client', (), {'id': 'malformed', 'error': None})()
        writer = Writer()
        self.writers.append(writer)
        handler = SimpleNamespace(client=client, transports={client: SimpleNamespace(handler=None, writer=writer)})
        async def actual_outer():
            self.proxy.connections[client.id] = handler
            try:
                with patch.object(writer, 'wait_closed', None):
                    with self.assertRaisesRegex(RuntimeError, 'cleanup contract'):
                        self.owner.client_connected(self.proxy, client)
            finally:
                self.proxy.connections.pop(client.id, None)
        task = asyncio.create_task(actual_outer())
        self.tasks.append(task)
        await task
        self.assertIsNotNone(client.error)
        self.assertTrue(writer.closed)
        await self.owner.close(self.proxy)

    async def test_late_outer_finalization_timeout_retains_identity_for_retry(self):
        gate = asyncio.Event()
        task = await self.accepted(Writer(), gate)
        with self.assertRaisesRegex(RuntimeError, 'registry owner'):
            await self.owner.close(self.proxy)
        self.assertFalse(task.done() or task.cancelled())
        self.assertEqual(len(self.owner.connections), 1)
        gate.set()
        await self.owner.close(self.proxy)
        self.assertTrue(task.done())
        self.assertFalse(self.owner.connections or self.proxy.connections)

    async def held_listener(self):
        accepted, release = asyncio.Event(), asyncio.Event()
        writers, tasks = [], set()
        async def receive(reader, writer):
            task = asyncio.current_task()
            tasks.add(task); writers.append(writer); accepted.set()
            try:
                await release.wait()
            finally:
                writer.close(); await writer.wait_closed(); tasks.discard(task)
        server = await asyncio.start_server(receive, '127.0.0.1', 0)
        self.proxy.servers.instances = [SimpleNamespace(_servers=[server])]
        _, client = await asyncio.open_connection(*server.sockets[0].getsockname())
        await accepted.wait()
        async def finish():
            release.set(); client.close(); await client.wait_closed()
            if tasks:
                await asyncio.gather(*tasks)
            server.close(); await server.wait_closed()
        self.addAsyncCleanup(finish)
        return server, release

    async def test_listener_timeout_retains_exact_server_and_waiter_for_retry(self):
        server, release = await self.held_listener()
        with self.assertRaisesRegex(RuntimeError, 'listener'):
            await self.owner.close(self.proxy)
        waiter = self.owner.listener_waiters[id(server)]
        self.assertFalse(waiter.done() or waiter.cancelled())
        self.assertIs(self.owner.listeners[id(server)], server)
        release.set()
        await self.owner.close(self.proxy)
        self.assertTrue(waiter.done())
        self.assertFalse(self.owner.listeners or self.owner.listener_waiters)

    async def test_cancellation_during_listener_wait_keeps_its_original_waiter(self):
        server, release = await self.held_listener()
        stopping = asyncio.create_task(self.owner.close(self.proxy))
        async with asyncio.timeout(1):
            while id(server) not in self.owner.listener_waiters:
                await asyncio.sleep(0)
        waiter = self.owner.listener_waiters[id(server)]
        stopping.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await stopping
        self.assertFalse(waiter.cancelled())
        release.set()
        await self.owner.close(self.proxy)
        self.assertTrue(waiter.done())
        self.assertFalse(self.owner.listeners or self.owner.listener_waiters)

    async def test_unknown_server_writer_is_closed_before_shape_failure_is_reported(self):
        task = await self.accepted(Writer())
        observed = next(iter(self.owner.connections))
        server = object()
        writer = Writer()
        self.writers.append(writer)
        observed.handler.transports[server] = SimpleNamespace(handler=None, writer=writer)
        data = SimpleNamespace(client=observed.client, server=SimpleNamespace(error=None))
        # Connection object is also the identity lookup key.
        data.server = type('Server', (), {'error': None})()
        observed.handler.transports[data.server] = observed.handler.transports.pop(server)
        with patch.object(writer, 'wait_closed', None):
            with self.assertRaisesRegex(RuntimeError, 'cleanup contract'):
                self.owner.server_connected(data)
        self.assertTrue(writer.closed)
        self.assertIn('refused', data.server.error)
        self.assertFalse(task.done())
        await self.owner.close(self.proxy)

    async def test_retained_malformed_listener_source_survives_manager_removal_until_repair(self):
        good = await asyncio.start_server(lambda reader, writer: writer.close(), '127.0.0.1', 0)
        malformed = SimpleNamespace(_servers=None)
        self.proxy.servers.instances = [SimpleNamespace(_servers=[good]), malformed]
        with self.assertRaisesRegex(RuntimeError, 'listener ownership'):
            await self.owner.close(self.proxy)
        self.assertFalse(good.is_serving(), 'known sibling still closes despite malformed source')
        self.assertIs(self.owner.listener_sources[id(malformed)], malformed)
        self.proxy.servers.instances = []
        with self.assertRaisesRegex(RuntimeError, 'listener ownership'):
            await self.owner.close(self.proxy)
        self.assertEqual(self.owner.status(self.proxy)['unknown_listener_sources'], 1)
        malformed._servers = []
        await self.owner.close(self.proxy)
        self.assertFalse(self.owner.listener_sources or self.owner.unknown_listener_sources)

    async def test_missing_outer_owner_physically_refuses_proven_streams_but_cannot_claim_stop(self):
        client = type('Client', (), {'id': 'late-unknown', 'error': None})()
        class Server:
            error = None
            def __hash__(self): return 1
            def __eq__(self, other): return isinstance(other, Server)
        server = Server()
        client_writer, server_writer = Writer(), Writer()
        self.writers.extend((client_writer, server_writer))
        handler = SimpleNamespace(client=client, transports={
            client: SimpleNamespace(handler=None, writer=client_writer),
            server: SimpleNamespace(handler=None, writer=server_writer)})
        ready, observe = asyncio.Event(), asyncio.Event()
        async def actual_outer():
            self.proxy.connections[client.id] = handler
            ready.set()
            try:
                await observe.wait()
                self.owner.client_connected(self.proxy, client)
            finally:
                self.proxy.connections.pop(client.id, None)
        task = asyncio.create_task(actual_outer())
        self.tasks.append(task)
        await ready.wait()
        with self.assertRaisesRegex(RuntimeError, 'prove'):
            self.owner.server_connected(SimpleNamespace(client=client, server=Server()), self.proxy)
        self.assertFalse(client_writer.closed or server_writer.closed, 'equal identity is not proof of ownership')
        data = SimpleNamespace(client=client, server=server)
        with self.assertRaisesRegex(RuntimeError, 'prove'):
            self.owner.server_connected(data, self.proxy)
        self.assertTrue(client_writer.closed and server_writer.closed)
        self.assertEqual(len(self.owner.connections), 0, 'server callback task must not masquerade as outer owner')
        with self.assertRaisesRegex(RuntimeError, 'remain unknown'):
            await self.owner.close(self.proxy)
        self.assertEqual(self.owner.status(self.proxy)['unobserved_connections'], 1)
        observe.set()
        await task
        await self.owner.close(self.proxy)
        self.assertFalse(self.owner.unobserved or self.owner.connections or self.owner.refused_writers)


if __name__ == '__main__':
    unittest.main()
