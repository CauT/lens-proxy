"""Actual explicit HTTP CONNECT, excluded from decryption; no raw-forward listener.

Fixtures own loopback listeners and sockets. No host proxy/trust settings change.
SDK tcp_timeout defaults to 600s and Lens exposes no override, so these tests do
not pretend a short fixture socket timeout verifies the engine inactivity timer.
"""
import socket
import os
import errno
import tempfile
import threading
import time
from pathlib import Path
import unittest

from test_e2e import EngineHarness, certificate_fixture


PAYLOAD = b"\x16\x03\x01\x00\x07not TLS" + bytes(range(256)) * 257 + b"\0\xff\r\nlast client bytes"
REPLY = b"\0\xffserver reply\r\n" + bytes(reversed(range(256))) * 193


def exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.recv(min(16384, count - len(chunks)))
        if not part:
            raise AssertionError(f"EOF after {len(chunks)} of {count} expected bytes")
        chunks.extend(part)
    return bytes(chunks)


def until_eof(stream):
    pieces = []
    while part := stream.recv(16384):
        pieces.append(part)
    return b"".join(pieces)


class Origin:
    """One accepted peer, retained until joined; stop interrupts blocked I/O."""
    def __init__(self, handler):
        self.handler = handler
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.accepted = threading.Event()
        self.done = threading.Event()
        self.stop = threading.Event()
        self.events = {}
        self.received = None
        self.peer = None
        self.failure = None
        self.worker = threading.Thread(target=self.run, name="Lens CONNECT owned origin")
        self.worker.start()

    def event(self, name):
        return self.events.setdefault(name, threading.Event())

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    peer, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            self.peer = peer
            peer.settimeout(5)
            self.accepted.set()
            with peer:
                self.handler(peer, self)
        except BaseException as exc:
            if not self.stop.is_set():
                self.failure = exc
        finally:
            self.done.set()

    def joined(self, test):
        test.assertTrue(self.done.wait(5), "Origin did not observe terminal connection state")
        self.worker.join(timeout=1)
        test.assertFalse(self.worker.is_alive(), "Owned origin worker remains live")
        if self.failure is not None:
            raise self.failure

    def close(self):
        self.stop.set()
        for event in self.events.values():
            event.set()
        if self.peer is not None:
            try:
                self.peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.peer.close()
        self.worker.join(timeout=6)
        self.listener.close()
        if self.worker.is_alive():
            raise AssertionError("Origin cleanup failed to join its owned worker")


class ConnectTunnelAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-connect-tunnel-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        ca, _, _ = certificate_fixture(self.directory, "unused-upstream")
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)
        evidence = os.environ.get("LENS_CONNECT_EVIDENCE_DIR")
        if evidence:
            def retain_stderr():
                self.engine.stderr.flush(); self.engine.stderr.seek(0)
                destination = Path(evidence); destination.mkdir(parents=True, exist_ok=True)
                (destination / (self.id().rsplit(".", 1)[-1] + ".log")).write_text(self.engine.stderr.read())
            self.addCleanup(retain_stderr)
        # The actual explicit CONNECT destination is excluded. Binary payloads
        # deliberately resemble TLS records, proving this is not HTTP decoding.
        self.engine.command("configure", rules=[], ssl_hosts="")

    def origin(self, handler):
        result = Origin(handler)
        self.addCleanup(result.close)
        return result

    def connect(self, port, status=200, protocol="HTTP/1.1"):
        stream = socket.create_connection(("127.0.0.1", self.engine.port), timeout=5)
        self.addCleanup(stream.close)
        authority = f"127.0.0.1:{port}"
        stream.sendall((f"CONNECT {authority} {protocol}\r\nHost: {authority}\r\n\r\n").encode("ascii"))
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            part = stream.recv(1)
            self.assertTrue(part, "CONNECT closed before a complete response header")
            head.extend(part)
            self.assertLessEqual(len(head), 65536, "Oversized CONNECT response header")
        self.last_connect_head = bytes(head)
        self.assertEqual(int(bytes(head).split(b"\r\n", 1)[0].split(b" ")[1]), status)
        return stream

    def idle_state(self):
        deadline = time.monotonic() + 5
        while True:
            status = self.engine.command("network_status")[1]
            fields = ("active_connections", "pending_cleanup", "client_bindings", "client_observations", "process_lookup_children")
            sdk = status.get("sdk", {})
            sdk_fields = ("active_handlers", "registry_connections", "pending_cleanup", "retained_owners", "retained_writers", "pending_listeners")
            if all(status[key] == 0 for key in fields) and all(sdk.get(key) == 0 for key in sdk_fields):
                return status
            if time.monotonic() >= deadline:
                self.fail(f"Owned CONNECT resources were not released: {status}")
            time.sleep(.02)

    def assert_opaque(self):
        self.assertEqual(self.engine.command("export_har")[1]["log"]["entries"], [],
                         "Opaque CONNECT bytes must not become fabricated decrypted HTTP flows")

    def assert_closed(self, stream):
        try:
            self.assertEqual(until_eof(stream), b"")
        except (ConnectionResetError, BrokenPipeError):
            pass  # A delivered reset is terminal; a socket timeout is a failure.

    def assert_no_listeners(self, status, addresses):
        self.assertEqual(status["public_listeners"], [])
        self.assertEqual(status["internal_listeners"], [])
        self.assertTrue(status["sdk"]["admission_closed"])
        for address in addresses:
            with self.subTest(address=address), self.assertRaises(OSError):
                socket.create_connection(tuple(address[:2]), timeout=.2)

    def listener_addresses(self):
        status = self.engine.command("network_status")[1]
        return ([item["address"] for item in status["public_listeners"]]
                + [address for item in status["internal_listeners"] for address in item["addresses"]])

    def test_exact_bidirectional_binary_uses_actual_connect_and_no_http_capture(self):
        def serve(peer, origin):
            origin.received = exact(peer, len(PAYLOAD))
            peer.sendall(REPLY)
            peer.shutdown(socket.SHUT_WR)
            self.assertEqual(until_eof(peer), b"")
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(PAYLOAD)
        stream.shutdown(socket.SHUT_WR)
        self.assertEqual(until_eof(stream), REPLY)
        origin.joined(self)
        self.assertEqual(origin.received, PAYLOAD)
        stream.close()
        self.idle_state(); self.assert_opaque()

    def test_http10_connect_preserves_binary_reply_after_client_half_close(self):
        def serve(peer, origin):
            origin.received = until_eof(peer)
            peer.sendall(REPLY)
        origin = self.origin(serve)
        stream = self.connect(origin.port, protocol="HTTP/1.0")
        stream.sendall(PAYLOAD); stream.shutdown(socket.SHUT_WR)
        self.assertEqual(until_eof(stream), REPLY)
        origin.joined(self)
        self.assertEqual(origin.received, PAYLOAD)
        stream.close(); self.idle_state(); self.assert_opaque()

    def test_server_first_greeting_after_separate_connect_headers(self):
        def serve(peer, origin):
            peer.sendall(REPLY)
            peer.shutdown(socket.SHUT_WR)
            origin.received = until_eof(peer)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        # No client payload is coalesced into or sent after CONNECT headers.
        self.assertEqual(exact(stream, len(REPLY)), REPLY)
        self.assertEqual(stream.recv(1), b"")
        stream.sendall(PAYLOAD); stream.shutdown(socket.SHUT_WR)
        origin.joined(self)
        self.assertEqual(origin.received, PAYLOAD)
        stream.close(); self.idle_state(); self.assert_opaque()

    def test_zero_payload_client_half_close_still_dials_and_reads_server_reply(self):
        def serve(peer, origin):
            origin.received = until_eof(peer)
            origin.event("empty client EOF").set()
            peer.sendall(REPLY)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.shutdown(socket.SHUT_WR)
        self.assertTrue(origin.event("empty client EOF").wait(4), "An empty CONNECT half-close did not reach origin")
        self.assertEqual(until_eof(stream), REPLY)
        origin.joined(self)
        self.assertEqual(origin.received, b"")
        stream.close(); self.idle_state(); self.assert_opaque()

    def test_client_half_close_keeps_delayed_server_bytes_readable(self):
        def serve(peer, origin):
            origin.received = until_eof(peer)
            origin.event("client EOF").set()
            if not origin.event("release reply").wait(4):
                raise AssertionError("Test did not release the delayed reply")
            peer.sendall(REPLY)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(PAYLOAD)
        stream.shutdown(socket.SHUT_WR)
        self.assertTrue(origin.event("client EOF").wait(4), "Client half-close did not propagate through CONNECT")
        self.assertEqual(origin.received, PAYLOAD)
        origin.event("release reply").set()
        self.assertEqual(until_eof(stream), REPLY)
        origin.joined(self)
        stream.close(); self.idle_state(); self.assert_opaque()

    def test_server_half_close_keeps_later_client_bytes_writable(self):
        seed = b"open opaque tunnel\0\xff"
        def serve(peer, origin):
            self.assertEqual(exact(peer, len(seed)), seed)
            peer.sendall(REPLY)
            peer.shutdown(socket.SHUT_WR)
            origin.received = until_eof(peer)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(seed)
        self.assertEqual(until_eof(stream), REPLY)
        stream.sendall(PAYLOAD)
        stream.shutdown(socket.SHUT_WR)
        origin.joined(self)
        self.assertEqual(origin.received, PAYLOAD)
        stream.close(); self.idle_state(); self.assert_opaque()

    def test_excluded_connect_upstream_refusal_returns_real_502_and_releases_owner(self):
        # macOS keeps a merely bound/non-listening TCP port in a SYN timeout
        # state. Release it and first verify actual OS refusal, rather than
        # mistaking a test socket timeout for a completed origin connection.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=.5)
        stream = self.connect(port, status=502)
        fields = dict(line.split(b":", 1) for line in self.last_connect_head.split(b"\r\n")[1:] if b":" in line)
        length = next(int(value) for name, value in fields.items() if name.lower() == b"content-length")
        reason = exact(stream, length)
        self.assertIn(b"Cannot connect excluded CONNECT destination", reason)
        self.assertIn(f"[Errno {errno.ECONNREFUSED}]".encode(), reason)
        stream.close()
        self.idle_state(); self.assert_opaque()

    def test_client_early_full_close_reaches_origin_and_releases_both_sides(self):
        seed = b"cancel this opaque tunnel"
        def serve(peer, origin):
            origin.received = until_eof(peer)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(seed)
        self.assertTrue(origin.accepted.wait(4))
        stream.close()
        origin.joined(self)
        self.assertEqual(origin.received, seed)
        self.idle_state(); self.assert_opaque()

    def test_cancel_during_incomplete_connect_and_before_tunnel_payload(self):
        origin = self.origin(lambda peer, owner: until_eof(peer))
        incomplete = socket.create_connection(("127.0.0.1", self.engine.port), timeout=5)
        incomplete.sendall(f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\nHost: ".encode())
        incomplete.close()
        self.idle_state()
        connected = self.connect(origin.port)
        connected.close()
        self.idle_state(); self.assert_opaque()

    def prepare_idle(self):
        seed = b"owned idle CONNECT\0\xff"
        def serve(peer, origin):
            self.assertEqual(exact(peer, len(seed)), seed)
            origin.event("ready").set()
            origin.received = until_eof(peer)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(seed)
        self.assertTrue(origin.event("ready").wait(4))
        self.assertEqual(self.engine.command("network_status")[1]["active_connections"], 1)
        return origin, stream

    def test_stop_releases_actual_idle_tunnel_and_public_internal_listeners(self):
        origin, stream = self.prepare_idle()
        addresses = self.listener_addresses()
        self.engine.command("stop_capture")
        self.assert_closed(stream)
        origin.joined(self)
        self.assertEqual(origin.received, b"")
        self.assert_no_listeners(self.idle_state(), addresses)
        self.assertIsNone(self.engine.process.poll(), "Stop must retain the inspection/control engine")
        self.assert_opaque()
        self.engine.command("shutdown")
        self.engine.process.wait(timeout=5)
        self.assertEqual(self.engine.process.returncode, 0)

    def test_shutdown_exits_engine_and_closes_actual_idle_tunnel(self):
        origin, stream = self.prepare_idle()
        addresses = self.listener_addresses()
        self.engine.command("shutdown")
        self.engine.process.wait(timeout=5)
        self.assertEqual(self.engine.process.returncode, 0)
        self.assert_closed(stream)
        origin.joined(self)
        for address in addresses:
            with self.subTest(address=address), self.assertRaises(OSError):
                socket.create_connection(tuple(address[:2]), timeout=.2)
        self.engine.stderr.flush(); self.engine.stderr.seek(0)
        log = self.engine.stderr.read()
        for warning in ("Task was destroyed", "exception was never retrieved", "Traceback"):
            self.assertNotIn(warning, log)

    def stop_held_half(self, side, command):
        seed = b"held half close"
        greeting = b"server FIN without client FIN"
        def serve(peer, origin):
            self.assertEqual(exact(peer, len(seed)), seed)
            if side == "client":
                self.assertEqual(until_eof(peer), b"")
                origin.event("half closed").set()
                if not origin.event("release fixture").wait(5):
                    raise AssertionError("Fixture not released after Stop")
            else:
                peer.sendall(greeting)
                peer.shutdown(socket.SHUT_WR)
                origin.event("half closed").set()
                origin.received = until_eof(peer)
        origin = self.origin(serve)
        stream = self.connect(origin.port)
        stream.sendall(seed)
        if side == "client":
            stream.shutdown(socket.SHUT_WR)
        else:
            self.assertEqual(exact(stream, len(greeting)), greeting)
            self.assertEqual(stream.recv(1), b"")
        self.assertTrue(origin.event("half closed").wait(4))
        self.assertEqual(self.engine.command("network_status")[1]["sdk"]["active_handlers"], 1)
        addresses = self.listener_addresses()
        self.engine.command(command)
        if command == "stop_capture":
            self.assert_no_listeners(self.idle_state(), addresses)
            self.assertIsNone(self.engine.process.poll())
            self.assert_opaque()
        else:
            self.engine.process.wait(timeout=5)
            self.assertEqual(self.engine.process.returncode, 0)
            for address in addresses:
                with self.assertRaises(OSError):
                    socket.create_connection(tuple(address[:2]), timeout=.2)
        # The SDK owner must already be terminal while this fixture's original
        # half-open peer remains retained; fixture close must not fix engine Stop.
        origin.event("release fixture").set()
        if side == "client":
            self.assert_closed(stream)
        origin.joined(self)
        if side == "server":
            self.assertEqual(origin.received, b"")

    def test_stop_joins_sdk_handler_after_client_half_closed_and_origin_stays_open(self):
        self.stop_held_half("client", "stop_capture")

    def test_stop_joins_sdk_handler_after_server_half_closed_and_client_stays_open(self):
        self.stop_held_half("server", "stop_capture")

    def test_shutdown_exits_after_client_half_closed_and_origin_stays_open(self):
        self.stop_held_half("client", "shutdown")

    def test_shutdown_exits_after_server_half_closed_and_client_stays_open(self):
        self.stop_held_half("server", "shutdown")

    def test_stop_interrupts_active_paced_tunnel_without_waiting_for_entire_payload(self):
        seed = b"paced CONNECT"
        payload = bytes(range(256)) * 1024
        def serve(peer, origin):
            self.assertEqual(exact(peer, len(seed)), seed)
            peer.sendall(payload)
            origin.received = until_eof(peer)
        origin = self.origin(serve)
        self.engine.command("configure", rules=[], ssl_hosts="", network={"download_kbps": 32})
        stream = self.connect(origin.port)
        stream.sendall(seed)
        first = exact(stream, 4096)
        self.assertEqual(first, payload[:4096])
        addresses = self.listener_addresses()
        self.engine.command("stop_capture")
        rest = until_eof(stream)
        self.assertLess(len(first) + len(rest), len(payload))
        self.assertEqual(first + rest, payload[:len(first) + len(rest)])
        origin.joined(self)
        self.assert_no_listeners(self.idle_state(), addresses)
        self.assert_opaque()


if __name__ == "__main__":
    unittest.main(verbosity=2)
