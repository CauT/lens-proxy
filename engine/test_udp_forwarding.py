"""UDP queue admission, socket writer identity and cancellation/finalization."""
import asyncio
import socket
import unittest
from unittest.mock import patch

from forwarding import parse_forwards
from network import DirectionBudget
from udp_capture import UDPRecorder
from udp_forwarding import Association, Listener, UDPRelays, send_connected


def endpoint():
    value = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    value.setblocking(False); value.bind(("127.0.0.1", 0))
    return value


def forward(port=12345, target=12346):
    return parse_forwards([{"listen_port": port, "target_host": "127.0.0.1", "target_port": target}], [], transport="UDP")[0]


async def eventually(predicate):
    for _ in range(1000):
        if predicate(): return
        await asyncio.sleep(.001)
    raise AssertionError("UDP owner did not reach expected state")


class UDPResourceOwnership(unittest.IsolatedAsyncioTestCase):
    def owner(self):
        return UDPRelays(DirectionBudget(), DirectionBudget())

    async def test_queue_admission_includes_empty_packets_and_cancel_before_start_drains_once(self):
        owner, sock = self.owner(), endpoint()
        capture = UDPRecorder(lambda *_args, **_kwargs: None)
        owner.observe = lambda chosen, client, local: capture.begin(chosen, client, local)
        listener = Listener(forward(sock.getsockname()[1]), sock)
        owner.listeners[listener.forward.listen_port] = listener
        try:
            with patch("udp_forwarding.ASSOCIATION_QUEUE", 2), patch("udp_forwarding.MAX_ASSOCIATIONS", 1):
                owner.accept(listener, b"", ("127.0.0.1", 10001))
                owner.accept(listener, b"one", ("127.0.0.1", 10001))
                owner.accept(listener, b"full", ("127.0.0.1", 10001))
                owner.accept(listener, b"other", ("127.0.0.1", 10002))
            self.assertEqual((owner.queued_datagrams, owner.queued_bytes), (2, 3))
            self.assertEqual(owner.status()["dropped_client_datagrams"], 2)
            association = next(iter(owner.associations.values()))
            # No await occurred: close must own the never-started coroutine too.
            await owner.close()
            self.assertFalse(owner.associations or owner.listeners)
            self.assertEqual((owner.queued_datagrams, owner.queued_bytes), (0, 0))
            self.assertEqual(owner.status()["dropped_client_datagrams"], 4)
            self.assertEqual(association.capture.value["dropped_client_datagrams"], 3)
            self.assertEqual(association.capture.value["state"], "cancelled")
            await owner.close()
            self.assertEqual(owner.status()["dropped_client_datagrams"], 4)
        finally: await owner.close()

    async def test_global_queue_count_and_byte_bounds_cover_zero_and_nonzero_datagrams(self):
        owner, sock = self.owner(), endpoint()
        listener = Listener(forward(sock.getsockname()[1]), sock)
        owner.listeners[listener.forward.listen_port] = listener
        try:
            with patch("udp_forwarding.MAX_QUEUED_BYTES", 3), patch("udp_forwarding.MAX_QUEUED_DATAGRAMS", 2):
                owner.accept(listener, b"abc", ("127.0.0.1", 10001))
                owner.accept(listener, b"x", ("127.0.0.1", 10002))
                owner.accept(listener, b"", ("127.0.0.1", 10002))
                owner.accept(listener, b"", ("127.0.0.1", 10003))
            self.assertEqual(len(owner.associations), 2)
            self.assertEqual((owner.queued_datagrams, owner.queued_bytes), (2, 3))
            self.assertEqual(owner.status()["dropped_client_datagrams"], 2)
        finally: await owner.close()

    async def test_late_resolution_remains_owned_after_stop_timeout_then_retry_does_not_dial(self):
        owner, sock, release, started = self.owner(), endpoint(), asyncio.Event(), asyncio.Event()
        listener = Listener(forward(sock.getsockname()[1]), sock)
        owner.listeners[listener.forward.listen_port] = listener
        async def late(*_args, **_kwargs):
            started.set(); await release.wait()
            return [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("127.0.0.1", 10003))]
        loop = asyncio.get_running_loop()
        try:
            with patch.object(loop, "getaddrinfo", late):
                owner.accept(listener, b"late", ("127.0.0.1", 10001))
                await started.wait()
                association = next(iter(owner.associations.values()))
                with self.assertRaisesRegex(RuntimeError, "retry Stop"):
                    await owner.close()
                self.assertIn(association, owner.associations.values())
                self.assertFalse(association.resolution.cancelled())
                self.assertIsNone(association.socket)
                self.assertEqual(owner.queued_datagrams, 0)
                release.set()
                await owner.close()
                self.assertFalse(owner.associations)
                self.assertIsNone(association.socket, "A late DNS result must not open a socket after Stop")
        finally:
            release.set(); await owner.close()

    async def test_mixed_socket_close_outcomes_keep_only_failed_owner_until_retry(self):
        owner, listen = self.owner(), endpoint()
        listener = Listener(forward(listen.getsockname()[1]), listen)
        owner.listeners[listener.forward.listen_port] = listener
        sockets = [endpoint(), endpoint()]
        class FailOnce:
            fail = True
            def close(self):
                if self.fail:
                    self.fail = False; raise OSError("fixture held socket close failed")
                sockets[0].close()
            def fileno(self): return sockets[0].fileno()
        bad, good = Association(owner, listener, ("127.0.0.1", 10001)), Association(owner, listener, ("127.0.0.1", 10002))
        bad.socket, good.socket = FailOnce(), sockets[1]
        owner.associations.update({value.key: value for value in (bad, good)})
        try:
            with self.assertRaisesRegex(RuntimeError, "retry Stop"):
                await owner.close()
            self.assertEqual(list(owner.associations.values()), [bad])
            self.assertEqual(sockets[1].fileno(), -1)
            self.assertGreaterEqual(sockets[0].fileno(), 0)
            await owner.close()
            self.assertFalse(owner.associations)
            self.assertEqual(sockets[0].fileno(), -1)
        finally: await owner.close()

    async def test_parent_cancellation_during_finalizer_keeps_child_join_owned(self):
        owner, sock, release, joined = self.owner(), endpoint(), asyncio.Event(), asyncio.Event()
        listener = Listener(forward(sock.getsockname()[1]), sock)
        owner.listeners[listener.forward.listen_port] = listener
        association = Association(owner, listener, ("127.0.0.1", 10001))
        owner.associations[association.key] = association
        async def stubborn():
            try: await asyncio.Event().wait()
            except asyncio.CancelledError:
                joined.set(); await release.wait()
        association.children.add(asyncio.create_task(stubborn()))
        await asyncio.sleep(0)
        close = asyncio.create_task(owner.close())
        await joined.wait(); close.cancel()
        with self.assertRaises(asyncio.CancelledError): await close
        self.assertIn(association, owner.associations.values())
        self.assertFalse(association.finalizer.cancelled())
        release.set(); await owner.close()
        self.assertFalse(owner.associations)

    async def test_connected_empty_would_block_retries_and_unregisters_writable_owner(self):
        with endpoint() as sock:
            attempts, registrations, removals = [], [], []
            class Socket:
                def send(self, data):
                    attempts.append(data)
                    if len(attempts) == 1: raise BlockingIOError()
                    return 0
                def fileno(self): return sock.fileno()
            loop = asyncio.get_running_loop()
            add, remove = loop.add_writer, loop.remove_writer
            def register(fd, callback):
                registrations.append(fd); add(fd, callback)
            def unregister(fd):
                removals.append(fd); remove(fd)
            with patch.object(loop, "add_writer", register), patch.object(loop, "remove_writer", unregister):
                self.assertEqual(await send_connected(Socket(), b""), 0)
            self.assertEqual(attempts, [b"", b""])
            self.assertEqual(registrations, removals)

    async def test_real_idle_reclaims_socket_and_same_tuple_creates_fresh_association(self):
        owner, origin, client = self.owner(), endpoint(), endpoint()
        capture = UDPRecorder(lambda *_args, **_kwargs: None)
        with endpoint() as reserve: local = reserve.getsockname()[1]
        loop = asyncio.get_running_loop()
        async def echo():
            while True:
                data, peer = await loop.sock_recvfrom(origin, 65535)
                await loop.sock_sendto(origin, data, peer)
        worker = asyncio.create_task(echo())
        try:
            with patch("udp_forwarding.IDLE_SECONDS", .03):
                await owner.start([forward(local, origin.getsockname()[1])], observe=capture.begin)
                ids = []
                for payload in (b"", b"later"):
                    await loop.sock_sendto(client, payload, ("127.0.0.1", local))
                    reply, _ = await asyncio.wait_for(loop.sock_recvfrom(client, 65535), 2)
                    self.assertEqual(reply, payload)
                    await eventually(lambda: not owner.associations)
                    ids.append(next(reversed(capture.associations)))
                self.assertNotEqual(*ids)
                self.assertTrue(all(value.value["state"] == "idle" for value in capture.associations.values()))
        finally:
            await owner.close(); worker.cancel(); await asyncio.gather(worker, return_exceptions=True)
            origin.close(); client.close()


if __name__ == "__main__": unittest.main()
