"""Owned loopback TCP relays with shared asynchronous directional bandwidth budgets."""
import asyncio
import math
import logging
import ipaddress
import socket
import time
from dataclasses import dataclass, replace
from endpoints import socket_endpoint
from client_connection import ClientConnection, LISTENERS

CHUNK_SIZE = 4096
MAX_CONNECTIONS = 256
CLOSE_TIMEOUT = 1
DEFAULT_CONNECT_TIMEOUT = 10
MAX_CONNECT_TIMEOUT = 600
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LANAccess:
    address: str

    @classmethod
    def parse(cls, address):
        if not address:
            return None
        local = ipaddress.IPv4Address(address)
        ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
        if not any(local in ipaddress.IPv4Network(value) for value in ranges):
            raise ValueError("LAN bind address must be a specific private or link-local IPv4 address")
        return cls(str(local))


def network_settings(value, *, connect_timeout=DEFAULT_CONNECT_TIMEOUT):
    if not isinstance(value, dict):
        raise ValueError("network must be an object")
    result = {}
    for name in ("upload_kbps", "download_kbps"):
        rate = value.get(name, 0)
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate < 0:
            raise ValueError(f"{name} must be a finite nonnegative number (kB/s)")
        if not math.isfinite(rate * 1000):
            raise ValueError(f"{name} exceeds the finite wire-byte rate range")
        result[name] = rate
    seconds = value.get("connect_timeout_seconds", connect_timeout)
    if type(seconds) is not int or not 1 <= seconds <= MAX_CONNECT_TIMEOUT:
        raise ValueError("connect_timeout_seconds must be an integer between 1 and 600")
    result["connect_timeout_seconds"] = seconds
    return result


class DirectionBudget:
    """Pace small chunks fairly across connections; there is no initial burst allowance."""
    def __init__(self):
        self.bytes_per_second = 0
        self.lock = asyncio.Lock()
        self.changed = asyncio.Event()

    def configure(self, kbps):
        self.bytes_per_second = kbps * 1000
        self.changed.set()
        self.changed = asyncio.Event()

    async def admit(self, size):
        async with self.lock:
            remaining = float(size)
            while remaining > 0:
                rate = self.bytes_per_second
                if not rate:
                    return
                changed = self.changed
                started = asyncio.get_running_loop().time()
                try:
                    await asyncio.wait_for(changed.wait(), timeout=remaining / rate)
                except asyncio.TimeoutError:
                    return
                remaining -= (asyncio.get_running_loop().time() - started) * rate


class ProxyRelays:
    def __init__(self):
        self.upload = DirectionBudget()
        self.download = DirectionBudget()
        self.settings = network_settings({})
        self.servers = {}
        self.tasks = set()
        self.connections = {}
        self.rejected_connections = 0
        self.closed = False
        self.closing = set()
        self.close_waiters = {}
        self.own_addresses = set()
        self.client_bindings = {}
        self.sdk_clients = {}
        self.peer_processes = None

    def configure(self, value):
        rates = network_settings(value, connect_timeout=self.settings["connect_timeout_seconds"])
        self.upload.configure(rates["upload_kbps"])
        self.download.configure(rates["download_kbps"])
        self.settings = rates

    async def start(self, listeners, lan=None, forwards=(), observe=None):
        """listeners is [(name, public_port, (internal_host, actual_internal_port))]."""
        if self.servers:
            raise RuntimeError("Proxy relays already started")
        try:
            for name, port, destination in listeners:
                self.own_addresses.add(socket_endpoint(destination))
                def accepted(reader, writer, target=destination, listener=name):
                    self.accept(reader, writer, target, listener=listener)
                self.servers[name] = await asyncio.start_server(accepted, "127.0.0.1", port, limit=64 * 1024, start_serving=False)
                if lan is not None and name == "proxy_port":
                    def lan_accepted(reader, writer, target=destination):
                        self.accept(reader, writer, target, listener="lan_proxy_port")
                    self.servers["lan_proxy_port"] = await asyncio.start_server(lan_accepted, lan.address, port, limit=64 * 1024, start_serving=False)
            for forward in forwards:
                def accepted(reader, writer, selected=forward):
                    factory = (lambda: observe(selected)) if observe else None
                    self.accept(reader, writer, (selected.dial_host, selected.target_port), capture_factory=factory)
                self.servers[f"tcp_{forward.listen_port}"] = await asyncio.start_server(
                    accepted, "127.0.0.1", forward.listen_port, limit=64 * 1024, start_serving=False)
            self.own_addresses.update(socket_endpoint(sock.getsockname()) for server in self.servers.values() for sock in (server.sockets or ()))
            for server in self.servers.values():
                await server.start_serving()
            return {name: server.sockets[0].getsockname()[1] for name, server in self.servers.items()}
        except BaseException:
            await self.close()
            raise

    async def pump(self, reader, writer, budget, capture=None, direction=None):
        while chunk := await reader.read(CHUNK_SIZE):
            await budget.admit(len(chunk))
            writer.write(chunk)
            await writer.drain()
            if capture is not None:
                capture.data(direction, chunk)
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()

    def status(self):
        return {"active_connections": len(self.connections), "max_connections": MAX_CONNECTIONS,
                "rejected_connections": self.rejected_connections,
                "pending_cleanup": len(self.closing), "client_bindings": len(self.client_bindings),
                "client_observations": len(self.sdk_clients),
                "process_lookup_children": len(self.peer_processes.commands.children) if self.peer_processes is not None else 0}

    def observe_client(self, identity, peer, local):
        # Called at ClientConnected, before any protocol input may change the
        # SDK's mutable connection fields. The relay binding can arrive later,
        # when its outgoing connect completes; request lookup uses this snapshot.
        if self.closed:
            return
        if identity in self.sdk_clients:
            self.sdk_clients[identity] = None
            return
        if len(self.sdk_clients) >= MAX_CONNECTIONS:
            return
        try:
            self.sdk_clients[identity] = (socket_endpoint(peer), socket_endpoint(local)) if peer and local else None
        except (ValueError, TypeError, IndexError):
            self.sdk_clients[identity] = None

    def forget_client(self, identity):
        self.sdk_clients.pop(identity, None)

    def client_source(self, identity):
        key = self.sdk_clients.get(identity)
        source = self.client_bindings.get(key)
        return source.public() if source is not None else None

    def accept(self, reader, writer, destination, capture_factory=None, listener=None):
        # Reserve synchronously at the accepting owner. A semaphore inside each
        # coroutine would merely replace unbounded connections with queued tasks.
        if self.closed or len(self.connections) >= MAX_CONNECTIONS:
            writer.close()
            self.rejected_connections += 1
            count = self.rejected_connections
            if count & (count - 1) == 0:
                logger.warning("Lens relay rejected connection; active=%d limit=%d cumulative_rejected=%d",
                               len(self.connections), MAX_CONNECTIONS, count)
            return
        token = object()
        self.connections[token] = writer
        try:
            capture = capture_factory() if capture_factory else None
            source = None
            if listener in LISTENERS:
                try:
                    source = ClientConnection.observed(listener, writer.get_extra_info("peername"),
                        writer.get_extra_info("sockname"), time.time())
                except (ValueError, TypeError) as exc:
                    logger.warning("Lens cannot observe accepted client endpoint: %s", exc)
            task = asyncio.create_task(self.connection(reader, writer, destination, token, capture,
                                                       raw_tcp=capture_factory is not None, source=source))
        except BaseException:
            self.closing.add(writer)
            writer.close()
            raise  # retain the admission/stream owner until close() confirms cleanup
        self.tasks.add(task)
        def finished(value):
            self.tasks.discard(value)
            pending = self.connections.pop(token, None)
            if pending:
                self.closing.add(pending)
                pending.close()  # also handles cancellation before coroutine start
                if capture is not None:
                    capture.finish("cancelled", "Proxy stopped before connection cleanup completed")
            if not value.cancelled() and value.exception() is not None:
                logger.error("Lens relay task failed: %s", value.exception())
        task.add_done_callback(finished)

    async def dial(self, destination, raw_tcp):
        if not raw_tcp:
            return await asyncio.wait_for(asyncio.open_connection(*destination), timeout=10)
        seconds = self.settings["connect_timeout_seconds"]
        deadline = asyncio.timeout(seconds)
        reason = f'TCP DNS/connection timed out after {seconds} s.'
        try:
            async with deadline:
                result = await self._dial_tcp(destination)
        except TimeoutError as exc:
            if deadline.expired():
                raise TimeoutError(reason) from exc
            raise
        if deadline.expired():
            # An adapter may complete after suppressing cancellation. Its late
            # writer is still ours and cannot become an accepted connection.
            await self.close_streams([result[1]])
            raise TimeoutError(reason)
        return result

    async def _dial_tcp(self, destination):
        candidates = await asyncio.get_running_loop().getaddrinfo(*destination, type=socket.SOCK_STREAM)
        if self.closed:
            raise ConnectionAbortedError("Proxy stopped during target resolution")
        if not candidates or len(candidates) > 64:
            raise OSError("TCP target has no usable bounded address set")
        # Check resolved candidates and dial numeric addresses without a second
        # lookup. One deadline covers resolution and every candidate attempt.
        if any(socket_endpoint(address) in self.own_addresses
               for _, _, _, _, address in candidates):
            raise OSError("TCP target resolves to Lens's own listener")
        failure = None
        for family, _, _, _, address in candidates:
            if self.closed:
                raise ConnectionAbortedError("Proxy stopped before target connection")
            try:
                return await asyncio.open_connection(address[0], address[1], family=family, flags=socket.AI_NUMERICHOST)
            except OSError as exc:
                failure = exc
        raise failure

    async def close_streams(self, streams):
        streams = set(streams) - {None}
        self.closing.update(streams)
        failed = set()
        for stream in streams:
            try:
                stream.close()
            except Exception as exc:
                logger.warning("Lens retains relay stream after close failure: %s", exc)
                failed.add(stream)
        async def wait(stream):
            waiter = self.close_waiters.get(stream)
            if waiter is None:
                waiter = asyncio.create_task(stream.wait_closed())
                self.close_waiters[stream] = waiter
            try:
                # StreamWriter shares its protocol close Future. Cancellation
                # or wait_for timeout must not poison it for a later Stop retry.
                await asyncio.wait_for(asyncio.shield(waiter), timeout=CLOSE_TIMEOUT)
            except asyncio.TimeoutError:
                if not waiter.done():
                    try:
                        stream.transport.abort()
                    except Exception as exc:
                        logger.warning("Lens retains relay stream after abort failure: %s", exc)
                        return
                    try:
                        await asyncio.wait_for(asyncio.shield(waiter), timeout=CLOSE_TIMEOUT)
                    except asyncio.TimeoutError:
                        if not waiter.done():
                            return  # retain both stream and waiter for retry
                    except (ConnectionError, OSError):
                        pass
                    except asyncio.CancelledError:
                        if asyncio.current_task().cancelling():
                            raise
                        logger.warning("Lens retains relay stream with an unexpectedly cancelled close waiter")
                        return
                    except Exception as exc:
                        logger.warning("Lens retains relay stream after cleanup failure: %s", exc)
                        return
            except asyncio.CancelledError:
                if asyncio.current_task().cancelling():
                    raise  # owned waiter stays shielded and retained
                logger.warning("Lens retains relay stream with an unexpectedly cancelled close waiter")
                return
            except (ConnectionError, OSError):
                pass
            except Exception as exc:
                logger.warning("Lens retains relay stream after cleanup failure: %s", exc)
                return
            self.closing.discard(stream)
            self.close_waiters.pop(stream, None)
        await asyncio.gather(*(wait(stream) for stream in streams - failed))

    async def connection(self, reader, writer, destination, token, capture=None, raw_tcp=False, source=None):
        upstream_writer = None
        binding = None
        pumps = []
        state, reason = "closed", None
        try:
            if self.closed:
                state, reason = "cancelled", "Proxy stopped before connecting"
                return
            if source is not None and self.peer_processes is not None:
                process = await self.peer_processes.observe(source, writer.get_extra_info("socket").fileno())
                source = replace(source, process=process)
                if self.closed:
                    state, reason = "cancelled", "Proxy stopped while observing client process"
                    return
            upstream_reader, upstream_writer = await self.dial(destination, raw_tcp)
            if self.closed:
                state, reason = "cancelled", "Proxy stopped while connecting"
                return
            if source is not None:
                binding = (socket_endpoint(upstream_writer.get_extra_info("sockname")),
                           socket_endpoint(upstream_writer.get_extra_info("peername")))
                if binding in self.client_bindings:
                    raise RuntimeError("Owned relay socket identity collision")
                self.client_bindings[binding] = source
            if capture is not None:
                capture.connected(upstream_writer.get_extra_info("peername"))
            pumps = [asyncio.create_task(self.pump(reader, upstream_writer, self.upload, capture, "send")),
                     asyncio.create_task(self.pump(upstream_reader, writer, self.download, capture, "receive"))]
            await asyncio.gather(*pumps)
        except asyncio.CancelledError:
            state, reason = "cancelled", "Proxy stopped"
            raise
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            state, reason = ("cancelled", "Proxy stopped") if self.closed else ("error", f"{type(exc).__name__}: {exc}")
        except BaseException as exc:
            state, reason = "error", f"{type(exc).__name__}: {exc}"
            raise
        finally:
            if binding is not None and self.client_bindings.get(binding) is source:
                del self.client_bindings[binding]
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            await self.close_streams((writer, upstream_writer))
            self.connections.pop(token, None)
            if capture is not None:
                if state == "closed" and any(stream in self.closing for stream in (writer, upstream_writer)):
                    state, reason = "error", "Transfer ended; local stream cleanup remains pending"
                capture.finish(state, reason)

    async def close(self):
        self.closed = True
        servers = list(self.servers.values())
        for server in servers:
            server.close()
        # Python 3.13 Server.wait_closed also waits for active transports. Stop
        # owned connection tasks before waiting, or throttled readers deadlock
        # shutdown behind the very transfer that shutdown must cancel.
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.peer_processes is not None:
            await self.peer_processes.close()
        await self.close_streams(self.closing | set(self.connections.values()))
        for token, writer in list(self.connections.items()):
            if writer not in self.closing:
                del self.connections[token]
        if self.closing:
            raise RuntimeError(f"Lens retains {len(self.closing)} relay stream(s) awaiting cleanup; retry Stop")
        await asyncio.gather(*(server.wait_closed() for server in servers))
        self.servers.clear()
        self.sdk_clients.clear()
