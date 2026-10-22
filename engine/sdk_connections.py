"""Own pinned mitmproxy TCP handlers through their real outer-task completion.

The SDK's listener Stop does not join accepted connections, and cancelling its
outer handle_client coroutine skips cleanup. Cancel its inner I/O tasks instead,
retain the observed outer task, and drain the actual writers with Lens's shared
stream cleanup owner. No vendor classes or global callbacks are replaced.
"""
import asyncio
from dataclasses import dataclass, field
import logging
from mitmproxy_rs.udp import UdpServer

logger = logging.getLogger(__name__)
JOIN_SECONDS = 2


@dataclass(frozen=True)
class SDKListeners:
    tcp: tuple
    udp: tuple


def listener_servers(instance):
    """Parse the one pinned SDK listener representation for all consumers."""
    servers = getattr(instance, '_servers', None)
    if not isinstance(servers, list) or any(not isinstance(server, (asyncio.Server, UdpServer)) for server in servers):
        raise RuntimeError('Unknown mitmproxy listener ownership')
    return SDKListeners(tuple(server for server in servers if isinstance(server, asyncio.Server)),
                        tuple(server for server in servers if isinstance(server, UdpServer)))


@dataclass(eq=False)
class SDKConnection:
    client: object
    handler: object
    task: asyncio.Task
    writers: dict = field(default_factory=dict)
    cancelled: set = field(default_factory=set)
    cleanup: asyncio.Task | None = None
    outer_ended: asyncio.Future = field(default_factory=lambda: asyncio.get_running_loop().create_future())
    connecting: dict = field(default_factory=dict)


@dataclass
class SDKConnectAttempt:
    server: object
    task: asyncio.Task
    seconds: int
    timer: asyncio.TimerHandle | None = None
    error: str | None = None


class SDKConnections:
    def __init__(self, streams):
        self.streams = streams
        self.connections = set()
        self.by_client = {}
        self.listeners = {}
        self.listener_waiters = {}
        self.listener_sources = {}
        self.unknown_listener_sources = set()
        self.closed = False
        self.cleanup = None
        self.unobserved = {}
        self.refused_writers = {}
        self.refused_cleanup = None

    @staticmethod
    def _mapping(proxy):
        mapping = getattr(proxy, 'connections', None)
        if not isinstance(mapping, dict):
            raise RuntimeError('Unknown mitmproxy connection registry; capture is refused')
        return mapping

    @staticmethod
    def _identity_value(mapping, connection):
        # SDK Connection equality compares its ID, but cleanup authority belongs
        # to the actual observed object, never a same-ID copy.
        return next((value for key, value in mapping.items() if key is connection), None)

    @staticmethod
    def _writer(owner, connection):
        transports = getattr(owner.handler, 'transports', None)
        if not isinstance(transports, dict):
            raise RuntimeError('Unknown mitmproxy transport registry')
        io = SDKConnections._identity_value(transports, connection)
        if io is None:
            raise RuntimeError('Missing owned mitmproxy transport')
        writer = getattr(io, 'writer', None)
        # Identity is established by the instance-owned handler map above. Keep
        # even a malformed owned writer: readiness must not discard ownership.
        if writer is not None:
            owner.writers[connection] = writer
        if not callable(getattr(writer, 'close', None)) or not callable(getattr(writer, 'wait_closed', None)):
            raise RuntimeError('Unknown mitmproxy stream cleanup contract')
        return writer

    def client_connected(self, proxy, client):
        if self.closed:
            client.error = 'Lens stopped before the SDK connection handshake completed'
        try:
            handler = self._mapping(proxy).get(client.id)
            task = asyncio.current_task()
            if getattr(handler, 'client', None) is not client or task is None:
                raise RuntimeError('Unknown mitmproxy accepted-connection owner')
            previous = self.by_client.get(client.id)
            if previous is not None:
                raise RuntimeError('Duplicate mitmproxy accepted-connection identity')
            owner = SDKConnection(client, handler, task)
            self.connections.add(owner)
            self.by_client[client.id] = owner
            unknown = self.unobserved.get(client.id)
            if unknown is not None and unknown[0] is client and (unknown[1] is None or unknown[1] is handler):
                del self.unobserved[client.id]
            task.add_done_callback(lambda _: self._ended(owner))
            self._writer(owner, client)
        except Exception as exc:
            client.error = f'Lens refused an SDK connection: {exc}'
            # SDK addon exceptions are swallowed. Refuse before reporting drift.
            if 'owner' in locals():
                for writer in owner.writers.values():
                    try:
                        writer.close()
                    except Exception:
                        pass  # retain the owner; Stop retries the actual stream
            raise

    async def server_connect(self, data, seconds):
        if data.server.transport_protocol != 'tcp':
            return
        owner = self.by_client.get(data.client.id)
        if owner is None or owner.client is not data.client:
            data.server.error = 'Lens could not prove the SDK connection attempt owner'
            return
        task = asyncio.current_task()
        transports = getattr(owner.handler, 'transports', None)
        if not isinstance(transports, dict):
            data.server.error = 'Lens could not prove the SDK connection attempt registry'
            return
        io = self._identity_value(transports, data.server)
        if io is None:
            # The pinned SDK creates eager tasks before assigning their transport
            # registry entry. Let that producing owner finish its handshake.
            await asyncio.sleep(0)
            io = self._identity_value(transports, data.server)
        if task is None or getattr(io, 'handler', None) is not task:
            data.server.error = 'Lens could not prove the SDK connection attempt task'
            return
        if self.closed or owner.task.done():
            data.server.error = 'Lens stopped before the upstream connection attempt'
            return
        if id(data.server) in owner.connecting:
            data.server.error = 'Lens refused a duplicate SDK connection attempt'
            return
        attempt = SDKConnectAttempt(data.server, task, seconds)
        owner.connecting[id(data.server)] = attempt
        attempt.timer = asyncio.get_running_loop().call_later(seconds, self._connect_expired, owner, attempt)
        task.add_done_callback(lambda _: self._finish_connect(owner, attempt.server, attempt.task))

    def _finish_connect(self, owner, server, task=None):
        attempt = owner.connecting.get(id(server))
        if attempt is None or attempt.server is not server or (task is not None and attempt.task is not task):
            return None
        del owner.connecting[id(server)]
        if attempt.timer is not None:
            attempt.timer.cancel()
        return attempt

    def _connect_expired(self, owner, attempt):
        if owner.connecting.get(id(attempt.server)) is not attempt:
            return
        attempt.timer = None
        if self.closed or attempt.task.done():
            self._finish_connect(owner, attempt.server, attempt.task)
            return
        # Task object identity was proven at admission and retained here. Cancel
        # that exact inner dial, never the SDK's outer client/finalization task.
        attempt.error = f'Upstream DNS/TCP connection timed out after {attempt.seconds} s.'
        attempt.server.error = attempt.error
        attempt.task.cancel(attempt.error)

    def server_connect_error(self, data):
        owner = self.by_client.get(data.client.id)
        if owner is not None and owner.client is data.client:
            self._finish_connect(owner, data.server, asyncio.current_task())

    def server_connected(self, data, proxy=None):
        owner = self.by_client.get(data.client.id)
        if owner is None or owner.client is not data.client:
            data.server.error = 'Lens could not prove the SDK server connection owner'
            self._refuse_unobserved(data, proxy)
            raise RuntimeError(data.server.error)
        try:
            writer = self._writer(owner, data.server)
            attempt = self._finish_connect(owner, data.server, asyncio.current_task())
            if self.closed or (attempt is not None and attempt.error):
                data.server.error = attempt.error if attempt is not None and attempt.error else 'Lens stopped while the SDK target was connecting'
                writer.close()
        except Exception as exc:
            data.server.error = f'Lens refused an SDK target connection: {exc}'
            writer = self._identity_value(owner.writers, data.server)
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            raise

    def _refuse_unobserved(self, data, proxy):
        # A missed outer handshake must never promote the current server I/O
        # task into an invented outer owner. Retain that explicit unknown until
        # an actual client hook supplies proof. Still close streams whose exact
        # identity the instance-owned registry proves, before SDK swallows the
        # hook error and attempts to forward on the newly connected socket.
        handler = None
        self.unobserved[data.client.id] = (data.client, None)
        try:
            candidate = self._mapping(proxy).get(data.client.id)
            if getattr(candidate, 'client', None) is not data.client:
                return
            handler = candidate
            self.unobserved[data.client.id] = (data.client, handler)
            transports = getattr(handler, 'transports', None)
            if not isinstance(transports, dict) or self._identity_value(transports, data.server) is None:
                return
            for connection in (data.client, data.server):
                io = self._identity_value(transports, connection)
                writer = getattr(io, 'writer', None)
                if writer is None:
                    continue
                self.refused_writers[id(writer)] = writer
                try:
                    self.streams.closing.add(writer)
                    writer.close()
                except Exception:
                    pass  # retain malformed or failed owned streams for retry
            data.client.error = data.server.error
            if self.refused_cleanup is None or self.refused_cleanup.done():
                self.refused_cleanup = asyncio.create_task(self._drain_refused())
                self.refused_cleanup.add_done_callback(self._consume)
        except Exception:
            return  # no identity proof grants no authority over another stream

    async def _drain_refused(self):
        await self.streams.close_streams(self.refused_writers.values())
        for identity, writer in list(self.refused_writers.items()):
            if writer not in self.streams.closing:
                del self.refused_writers[identity]

    async def disconnected(self, client, server=None):
        owner = self.by_client.get(client.id)
        if owner is None or owner.client is not client:
            return
        connection = server if server is not None else client
        writer = self._identity_value(owner.writers, connection)
        if writer is not None:
            await self.streams.close_streams([writer])
            if writer not in self.streams.closing:
                owner.writers.pop(connection, None)

    def _ended(self, owner):
        for attempt in list(owner.connecting.values()):
            self._finish_connect(owner, attempt.server, attempt.task)
        # The outer task only finishes after register_connection's finally.
        # Publish that lifecycle fact before create_task: the SDK's eager task
        # factory may run the entire finalizer before cleanup can be assigned.
        # A suspended finalizer still has its separately retained join owner.
        owner.outer_ended.set_result(None)
        owner.cleanup = asyncio.create_task(self._finish(owner))
        owner.cleanup.add_done_callback(self._consume)

    @staticmethod
    def _consume(task):
        if not task.cancelled() and task.exception() is not None:
            logger.warning('Lens retains SDK connection cleanup after failure: %s', task.exception())

    async def _finish(self, owner):
        await self.streams.close_streams(owner.writers.values())
        for connection, writer in list(owner.writers.items()):
            if writer not in self.streams.closing:
                if owner.writers.get(connection) is writer:
                    del owner.writers[connection]
        if owner.task.done() and owner.outer_ended.done() and not owner.writers:
            self.connections.discard(owner)
            if self.by_client.get(owner.client.id) is owner:
                del self.by_client[owner.client.id]

    def status(self, proxy=None):
        registry = getattr(proxy, 'connections', {}) if proxy is not None else {}
        return {'active_handlers': sum(not owner.task.done() for owner in self.connections),
                'pending_connects': sum(len(owner.connecting) for owner in self.connections),
                'registry_connections': len(registry) if isinstance(registry, dict) else None,
                'pending_cleanup': sum(self.closed or owner.task.done() or any(writer in self.streams.closing for writer in owner.writers.values()) for owner in self.connections),
                'retained_owners': len(self.connections),
                'retained_writers': sum(len(owner.writers) for owner in self.connections) + len(self.refused_writers),
                'unobserved_connections': len(self.unobserved),
                'pending_listeners': len(self.listeners),
                'retained_listener_sources': len(self.listener_sources),
                'unknown_listener_sources': len(self.unknown_listener_sources), 'admission_closed': self.closed}

    async def close(self, proxy):
        self.closed = True
        for owner in self.connections:
            for attempt in list(owner.connecting.values()):
                self._finish_connect(owner, attempt.server, attempt.task)
        # A cancelled Stop must not cancel the actual SDK finalization owner.
        if self.cleanup is None or self.cleanup.done():
            self.cleanup = asyncio.create_task(self._close(proxy))
            self.cleanup.add_done_callback(self._consume)
        await asyncio.shield(self.cleanup)

    async def _close(self, proxy):
        issues = []
        if proxy is not None:
            valid_listeners = True
            try:
                for instance in proxy.servers:
                    self.listener_sources[id(instance)] = instance
                for identity, instance in self.listener_sources.items():
                    try:
                        parsed = listener_servers(instance)
                    except RuntimeError as exc:
                        self.unknown_listener_sources.add(identity)
                        issues.append(str(exc))
                        valid_listeners = False
                        continue
                    self.unknown_listener_sources.discard(identity)
                    for server in (*parsed.tcp, *parsed.udp):
                        self.listeners[id(server)] = server
                if valid_listeners and not await proxy.servers.update([]):
                    issues.append('SDK listener Stop failed')
            except Exception as exc:
                issues.append(str(exc))
        # Keep listener references even though the SDK clears its own list.
        failed_listeners = set()
        for server in self.listeners.values():
            try:
                server.close()
            except Exception as exc:
                failed_listeners.add(id(server))
                issues.append(str(exc))

        # Client hooks may arrive late after a listener closes. They observe
        # admission_closed and register their real owner before being refused.
        deadline = asyncio.get_running_loop().time() + JOIN_SECONDS
        while True:
            for owner in list(self.connections):
                owner.client.error = 'Lens stopped'
                transports = getattr(owner.handler, 'transports', None)
                if not isinstance(transports, dict):
                    issues.append('Unknown mitmproxy transport cleanup shape')
                    continue
                for connection, io in list(transports.items()):
                    writer = getattr(io, 'writer', None)
                    if writer is not None:
                        owner.writers[connection] = writer
                    task = getattr(io, 'handler', None)
                    if task is None:
                        continue  # initial handshake; outer owner remains live
                    if not isinstance(task, asyncio.Task) or task is owner.task:
                        issues.append('Unknown mitmproxy inner I/O task')
                        continue
                    if not task.done() and task not in owner.cancelled:
                        owner.cancelled.add(task)
                        task.cancel('Lens stopped')
            results = await asyncio.gather(*(self._finish(owner) for owner in list(self.connections)), return_exceptions=True)
            issues.extend(str(result) for result in results if isinstance(result, BaseException))
            pending = {owner.task for owner in self.connections if not owner.task.done()}
            remaining = max(0, deadline - asyncio.get_running_loop().time())
            if pending and remaining:
                await asyncio.wait(pending, timeout=remaining)
                continue
            break

        # Await callbacks scheduled by actual task completion; no snapshot may
        # forget a finalizer that was admitted during the preceding join.
        # Awaiting an already-done eager outer task need not yield to its done
        # callbacks. Their owned publication barrier must precede task lookup.
        completed = [owner for owner in self.connections if owner.task.done()]
        if completed:
            await asyncio.gather(*(asyncio.shield(owner.outer_ended) for owner in completed))
        finalizers = [owner.cleanup for owner in self.connections if owner.cleanup is not None]
        if finalizers:
            await asyncio.gather(*(asyncio.shield(task) for task in finalizers), return_exceptions=True)
        if self.refused_cleanup is not None:
            await asyncio.gather(asyncio.shield(self.refused_cleanup), return_exceptions=True)
        try:
            await self._drain_refused()
        except Exception as exc:
            issues.append(str(exc))
        results = await asyncio.gather(*(self._finish(owner) for owner in list(self.connections)), return_exceptions=True)
        issues.extend(str(result) for result in results if isinstance(result, BaseException))
        for identity, server in list(self.listeners.items()):
            if identity in failed_listeners:
                continue
            if isinstance(server, asyncio.Server):
                wait_closed = server.wait_closed
                waiter = self.listener_waiters.get(identity)
                if waiter is None:
                    waiter = asyncio.create_task(wait_closed())
                    self.listener_waiters[identity] = waiter
                done, _ = await asyncio.wait({waiter}, timeout=JOIN_SECONDS)
                if not done:
                    # Preserve the same waiter through timeout and Stop retry.
                    issues.append('SDK listener is awaiting active transport cleanup')
                    continue
                if waiter.cancelled():
                    issues.append('SDK listener close waiter was cancelled')
                    continue
                if waiter.exception() is not None:
                    issues.append(str(waiter.exception()))
                    continue
            del self.listeners[identity]
            self.listener_waiters.pop(identity, None)
        if proxy is not None:
            mapping = self._mapping(proxy)
            if mapping:
                issues.append(f'{len(mapping)} SDK connection registry owner(s) remain')
        if self.unobserved:
            issues.append(f'{len(self.unobserved)} SDK connection outer owner(s) remain unknown')
        if self.connections or self.listeners or self.refused_writers or issues:
            raise RuntimeError('Lens retains SDK connection cleanup; retry Stop: ' + '; '.join(issues or ['owned handlers or streams remain']))
        self.listener_sources.clear()
