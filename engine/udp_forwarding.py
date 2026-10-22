"""Owned loopback UDP associations. Datagram boundaries are never stream chunks."""
import asyncio
from dataclasses import dataclass, field
import logging
import socket
import time

from endpoints import socket_endpoint
from network import CHUNK_SIZE

MAX_ASSOCIATIONS = 256
MAX_QUEUED_DATAGRAMS = 1024
MAX_QUEUED_BYTES = 4 * 1024 * 1024
ASSOCIATION_QUEUE = 32
IDLE_SECONDS = 30
RESOLVE_SECONDS = 10
DATAGRAM_BYTES = 65535
# macOS defaults to a 9216-byte UDP send high-water mark. Give each owned
# socket room for a full supported datagram without changing system sysctls.
SOCKET_BUFFER_BYTES = 128 * 1024
logger = logging.getLogger(__name__)


def prepare_socket(endpoint):
    endpoint.setblocking(False)
    endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_BYTES)
    endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_BYTES)


async def pace(budget, length):
    # Share the existing directional budget fairly with TCP, but send a UDP
    # datagram only once after admission. Never split it into TCP-sized packets.
    for offset in range(0, length, CHUNK_SIZE):
        await budget.admit(min(CHUNK_SIZE, length - offset))


async def send_connected(endpoint, data):
    """One connected datagram, including b'' and a would-block retry.

    macOS rejects sendto(address) on connected UDP. sock_sendall is a stream
    primitive and treats a would-block empty send as completed. Keep the socket
    object alive until its single owned writer registration is removed.
    """
    loop = asyncio.get_running_loop()
    while True:
        try:
            return endpoint.send(data)
        except (BlockingIOError, InterruptedError):
            writable = loop.create_future()
            def ready():
                if not writable.done():
                    writable.set_result(None)
            descriptor = endpoint.fileno()
            loop.add_writer(descriptor, ready)
            try:
                await writable
            finally:
                loop.remove_writer(descriptor)


@dataclass
class Listener:
    forward: object
    socket: object
    task: object = None
    error: str | None = None
    send_lock: object = field(default_factory=asyncio.Lock)


class Association:
    def __init__(self, owner, listener, client):
        self.owner, self.listener, self.client = owner, listener, client
        self.key = (listener.forward.listen_port, client)
        self.queue = asyncio.Queue()
        self.activity = asyncio.Event()
        self.last_activity = time.monotonic()
        self.socket, self.task, self.finalizer = None, None, None
        self.resolution = None
        self.children = set()
        self.client_pending = self.upstream_pending = None
        self.capture = owner.observe(listener.forward, client, listener.socket.getsockname()) if owner.observe else None
        self.terminal = None

    def touch(self):
        self.last_activity = time.monotonic()
        self.activity.set()

    def drop(self, direction, data):
        self.owner.drop(direction, data, self.capture)

    def enqueue(self, data):
        if (self.queue.qsize() >= ASSOCIATION_QUEUE or self.owner.queued_datagrams >= MAX_QUEUED_DATAGRAMS
                or self.owner.queued_bytes + len(data) > MAX_QUEUED_BYTES):
            self.drop("send", data)
            return
        self.queue.put_nowait(data)
        self.owner.queued_datagrams += 1
        self.owner.queued_bytes += len(data)
        self.touch()

    def dequeue(self, data):
        self.owner.queued_datagrams -= 1
        self.owner.queued_bytes -= len(data)

    async def connect(self):
        loop = asyncio.get_running_loop()
        forward = self.listener.forward
        async with asyncio.timeout(RESOLVE_SECONDS):
            self.resolution = asyncio.create_task(loop.getaddrinfo(forward.dial_host, forward.target_port, type=socket.SOCK_DGRAM))
            self.resolution.add_done_callback(lambda task: None if task.cancelled() else task.exception())
            candidates = await asyncio.shield(self.resolution)
            if self.owner.closed:
                raise ConnectionAbortedError("UDP forwarding stopped during resolution")
            if not candidates or len(candidates) > 64:
                raise OSError("UDP target has no usable bounded address set")
            if any(socket_endpoint(address) in self.owner.own_addresses for _, _, _, _, address in candidates):
                raise OSError("UDP target resolves to Lens's own listener")
            failure = None
            for family, kind, protocol, _, address in candidates:
                if self.owner.closed:
                    raise ConnectionAbortedError("UDP forwarding stopped before target selection")
                self.socket = socket.socket(family, kind, protocol)
                prepare_socket(self.socket)
                try:
                    await loop.sock_connect(self.socket, address)
                    return address
                except OSError as exc:
                    failure = exc
                    self.socket.close()
                    self.socket = None
            raise failure

    async def send(self):
        while True:
            data = await self.queue.get()
            self.dequeue(data)
            self.client_pending = data
            await pace(self.owner.upload, len(data))
            # The high-level asyncio datagram transport ignores b"". A raw
            # socket sendto preserves the valid zero-length UDP datagram.
            length = await send_connected(self.socket, data)
            if length != len(data):
                raise OSError("UDP target did not accept a complete datagram")
            self.client_pending = None
            self.touch()
            if self.capture is not None:
                self.capture.data("send", data)

    async def receive(self):
        loop = asyncio.get_running_loop()
        while True:
            # Connected UDP filters replies to the selected remote address.
            # A zero-length read is a datagram, never EOF.
            data = await loop.sock_recv(self.socket, DATAGRAM_BYTES)
            self.upstream_pending = data
            self.touch()
            await pace(self.owner.download, len(data))
            # Multiple peers share this one listener descriptor. Only one
            # pending writable registration may own it at a time.
            async with self.listener.send_lock:
                length = await loop.sock_sendto(self.listener.socket, data, self.client)
            if length != len(data):
                raise OSError("UDP client did not accept a complete datagram")
            self.upstream_pending = None
            self.touch()
            if self.capture is not None:
                self.capture.data("receive", data)

    async def idle(self):
        while True:
            self.activity.clear()
            remaining = max(.001, IDLE_SECONDS - (time.monotonic() - self.last_activity))
            try:
                await asyncio.wait_for(self.activity.wait(), remaining)
            except asyncio.TimeoutError:
                if self.queue.empty() and self.client_pending is None and self.upstream_pending is None:
                    return
                # Pacing a queued datagram is active work, not an idle peer.
                await self.activity.wait()

    async def run(self):
        state, error = "idle", None
        try:
            await self.connect()
            if self.capture is not None:
                self.capture.connected(self.socket.getpeername())
            self.children = {asyncio.create_task(self.send()), asyncio.create_task(self.receive()), asyncio.create_task(self.idle())}
            done, _ = await asyncio.wait(self.children, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except asyncio.CancelledError:
            state, error = "cancelled", "UDP forwarding stopped"
            raise
        except (OSError, asyncio.TimeoutError) as exc:
            state, error = "error", f"{type(exc).__name__}: {exc}"
        except BaseException as exc:
            state, error = "error", f"{type(exc).__name__}: {exc}"
            raise
        finally:
            await asyncio.shield(self.begin_close(state, error))

    def begin_close(self, state, error):
        if self.terminal is None:
            self.terminal = (state, error)
        if self.finalizer is None or (self.finalizer.done() and (self.finalizer.cancelled() or self.finalizer.exception() is not None)):
            self.finalizer = asyncio.create_task(self.finalize())
            self.finalizer.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        return self.finalizer

    async def finalize(self):
        for child in self.children:
            child.cancel()
        await asyncio.gather(*self.children, return_exceptions=True)
        self.children.clear()
        while not self.queue.empty():
            data = self.queue.get_nowait()
            self.dequeue(data)
            self.drop("send", data)
        for attribute, direction in (("client_pending", "send"), ("upstream_pending", "receive")):
            data = getattr(self, attribute)
            if data is not None:
                self.drop(direction, data)
                setattr(self, attribute, None)
        if self.socket is not None:
            # The socket object, not a reused numeric FD, is the cleanup owner.
            self.socket.close()
            if self.socket.fileno() != -1:
                raise RuntimeError("UDP socket cleanup remains pending; retry Stop")
            self.socket = None
        if self.capture is not None:
            self.capture.finish(*self.terminal)
        if self.resolution is not None:
            try:
                # getaddrinfo can outlive cancellation inside the loop's system
                # resolver. Keep its owned task until the actual work completes.
                await asyncio.wait_for(asyncio.shield(self.resolution), 1)
            except asyncio.TimeoutError:
                raise RuntimeError("UDP resolution cleanup remains pending; retry Stop") from None
            except Exception:
                pass
            self.resolution = None
        if self.owner.associations.get(self.key) is self:
            del self.owner.associations[self.key]


class UDPRelays:
    def __init__(self, upload, download):
        self.upload, self.download = upload, download
        self.listeners, self.associations = {}, {}
        self.closed, self.observe = False, None
        self.own_addresses = set()
        self.queued_bytes = self.queued_datagrams = 0
        self.dropped = {f"dropped_{side}_{unit}": 0 for side in ("client", "upstream") for unit in ("datagrams", "bytes")}

    async def start(self, forwards, observe=None, blocked_addresses=()):
        if self.closed or self.listeners:
            raise RuntimeError("UDP forwarding owner cannot be started twice")
        self.observe = observe
        self.own_addresses.update(socket_endpoint(address) for address in blocked_addresses)
        try:
            for forward in forwards:
                endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Own immediately, including a failed bind. No SO_REUSEPORT:
                # another process must never silently share this listener.
                listener = Listener(forward, endpoint)
                self.listeners[forward.listen_port] = listener
                prepare_socket(endpoint)
                endpoint.bind(("127.0.0.1", forward.listen_port))
                self.own_addresses.add(socket_endpoint(endpoint.getsockname()))
            for listener in self.listeners.values():
                listener.task = asyncio.create_task(self.listen(listener))
        except BaseException:
            await self.close()
            raise

    def drop(self, direction, data, capture=None):
        side = "client" if direction == "send" else "upstream"
        self.dropped[f"dropped_{side}_datagrams"] += 1
        self.dropped[f"dropped_{side}_bytes"] += len(data)
        if capture is not None:
            capture.dropped(direction, 1, len(data))

    def accept(self, listener, data, client):
        if self.closed:
            self.drop("send", data)
            return
        key = (listener.forward.listen_port, client)
        association = self.associations.get(key)
        if association is not None and association.finalizer is not None:
            # Do not reuse a still-owned socket tuple until cleanup succeeds.
            self.drop("send", data, association.capture)
            return
        if association is None:
            if (len(self.associations) >= MAX_ASSOCIATIONS or self.queued_datagrams >= MAX_QUEUED_DATAGRAMS
                    or self.queued_bytes + len(data) > MAX_QUEUED_BYTES):
                self.drop("send", data)
                return
            association = Association(self, listener, client)
            self.associations[key] = association
            try:
                association.task = asyncio.create_task(association.run())
            except BaseException:
                association.begin_close("error", "UDP association startup failed")
                raise
            def finished(task):
                # Cancellation before run() starts has no coroutine finally.
                if association.finalizer is None:
                    association.begin_close("cancelled" if task.cancelled() else "error", "UDP association ended before finalization")
                if not task.cancelled() and task.exception() is not None:
                    logger.warning("Lens UDP association cleanup remains owned: %s", task.exception())
            association.task.add_done_callback(finished)
        association.enqueue(data)

    async def listen(self, listener):
        try:
            while not self.closed:
                data, client = await asyncio.get_running_loop().sock_recvfrom(listener.socket, DATAGRAM_BYTES)
                self.accept(listener, data, client)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            listener.error = f"{type(exc).__name__}: {exc}"
            logger.error("Lens UDP listener stopped receiving: %s", listener.error)

    def status(self):
        return {"active_associations": len(self.associations), "max_associations": MAX_ASSOCIATIONS,
                "queued_datagrams": self.queued_datagrams, "queued_bytes": self.queued_bytes, **self.dropped,
                "pending_cleanup": sum(association.finalizer is not None for association in self.associations.values()),
                "listeners": [{"listen_port": port, "address": listener.socket.getsockname(),
                               "receiving": listener.task is not None and not listener.task.done(), "error": listener.error}
                              for port, listener in self.listeners.items() if listener.socket.fileno() >= 0]}

    async def close(self):
        self.closed = True
        listeners = list(self.listeners.values())
        tasks = [listener.task for listener in listeners if listener.task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        associations = list(self.associations.values())
        for association in associations:
            if association.task is not None:
                association.task.cancel()
        await asyncio.gather(*(association.task for association in associations if association.task is not None), return_exceptions=True)
        results = await asyncio.gather(*(asyncio.shield(association.begin_close("cancelled", "UDP forwarding stopped"))
                                         for association in list(self.associations.values())), return_exceptions=True)
        failed = []
        for port, listener in list(self.listeners.items()):
            try:
                listener.socket.close()
                if listener.socket.fileno() != -1:
                    raise RuntimeError("UDP listener cleanup remains pending")
                del self.listeners[port]
            except Exception as exc:
                failed.append(exc)
        if self.associations or failed:
            raise RuntimeError("UDP forwarding cleanup remains pending; retry Stop")
        for result in results:
            if isinstance(result, BaseException):
                raise result
