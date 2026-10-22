"""Range configuration through production JSONL and owned TCP/UDP wire peers."""
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from test_e2e import EngineHarness, ROOT, certificate_fixture
from test_tcp_forwarding import receive_all


def reserve_block(count, transports=(socket.SOCK_STREAM, socket.SOCK_DGRAM), automatic_proxy=True):
    """Hold every candidate, in both namespaces, until its next owner is ready."""
    for _ in range(128):
        held, complete = [], False
        try:
            first = socket.socket(socket.AF_INET, transports[0]); held.append(first)
            first.bind(("127.0.0.1", 0)); base = first.getsockname()[1]
            if automatic_proxy:
                # Both the harness and release probes allocate ephemeral client
                # ports after reservations close. Keep every handed-off range
                # below macOS/Linux ephemeral pools, avoiding immediate reuse
                # by unrelated clients or a probe connecting to itself.
                base = 10000 + base % 20000
                first.close()
                first = socket.socket(socket.AF_INET, transports[0]); held[0] = first
                first.bind(("127.0.0.1", base))
            if base + count - 1 > 65535:
                continue
            for kind in transports:
                for offset in range(count):
                    if kind == transports[0] and offset == 0:
                        continue
                    stream = socket.socket(socket.AF_INET, kind); held.append(stream)
                    stream.bind(("127.0.0.1", base + offset))
            complete = True
            return base, held
        except OSError:
            pass
        finally:
            if not complete:
                for stream in held:
                    stream.close()
    raise AssertionError("Could not reserve a contiguous owned loopback block")


class RangeOrigin:
    """One bounded worker handles three TCP and three UDP ports; replies name route."""
    def __init__(self):
        self.base, self.sockets = reserve_block(3)
        self.stopping, self.errors, self.history = threading.Event(), [], []
        self.selector = selectors.DefaultSelector()
        for stream in self.sockets:
            if stream.type == socket.SOCK_STREAM:
                stream.listen(8)
            stream.settimeout(5)
            self.selector.register(stream, selectors.EVENT_READ)
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def run(self):
        try:
            while not self.stopping.is_set():
                for key, _ in self.selector.select(.02):
                    stream = key.fileobj
                    index = stream.getsockname()[1] - self.base
                    if stream.type == socket.SOCK_STREAM:
                        with stream.accept()[0] as client:
                            client.settimeout(5)
                            body = receive_all(client)
                            self.history.append(("TCP", index, body))
                            client.sendall(b"TCP:" + str(index).encode() + b":" + body[::-1])
                    else:
                        body, peer = stream.recvfrom(65535)
                        self.history.append(("UDP", index, body))
                        stream.sendto(b"UDP:" + str(index).encode() + b":" + body[::-1], peer)
        except BaseException as error:
            self.errors.append(error)

    def close(self):
        self.stopping.set(); self.worker.join(timeout=6)
        self.selector.close()
        for stream in self.sockets:
            stream.close()
        if self.worker.is_alive() or self.errors:
            raise AssertionError(f"Owned range fixture failed to finish: {self.errors}")


class ForwardingRangeAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-forward-range-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_three_port_tcp_udp_ranges_route_offsets_preserve_bytes_history_and_stop(self):
        origin = RangeOrigin(); self.addCleanup(origin.close)
        ca, _, _ = certificate_fixture(self.directory, "ranges")
        local, reservations = reserve_block(3, automatic_proxy=True)
        for stream in reservations:
            stream.close()
        config = {"listen_port": local, "listen_port_end": local + 2,
                  "target_host": "127.0.0.1", "target_port": origin.base}
        engine = EngineHarness(self.directory, ca, extra_args=["--initialize-from-stdin"],
                               initial_configuration={"tcp_forwards": [config], "udp_forwards": [config]})
        self.addCleanup(engine.close)
        captured = {}
        # The last port is used first: the old endpoint-only parser fails on wire.
        for index in (2, 0, 1):
            payload = bytes([index, 0, 255]) * 19
            with socket.create_connection(("127.0.0.1", local + index), timeout=5) as stream:
                stream.sendall(payload); stream.shutdown(socket.SHUT_WR)
                reply = b"TCP:" + str(index).encode() + b":" + payload[::-1]
                self.assertEqual(receive_all(stream), reply)
            tcp = engine.wait(lambda event: event.get("event") == "tcp_stream"
                and event["stream"]["listen_port"] == local + index
                and event["stream"]["state"] == "closed", timeout=8)["stream"]
            detail = engine.command("tcp_detail", id=tcp["id"])[1]
            for direction, expected in (("send", payload), ("receive", reply)):
                self.assertEqual(b"".join(base64.b64decode(chunk["base64"], validate=True)
                    for chunk in detail["chunks"] if chunk["direction"] == direction), expected)
            captured[tcp["id"]] = detail["chunks"]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5); client.bind(("127.0.0.1", 0))
                replies = []
                for body in (b"", payload):
                    client.sendto(body, ("127.0.0.1", local + index))
                    response, peer = client.recvfrom(65535)
                    replies.append(response)
                    self.assertEqual(response, b"UDP:" + str(index).encode() + b":" + body[::-1])
                    self.assertEqual(peer, ("127.0.0.1", local + index))
                udp = engine.wait(lambda event: event.get("event") == "udp_association"
                    and event["association"]["listen_port"] == local + index
                    and event["association"]["received_datagrams"] == 2, timeout=8)["association"]
            detail = engine.command("udp_detail", id=udp["id"])[1]
            for direction, expected in (("send", [b"", payload]), ("receive", replies)):
                self.assertEqual([base64.b64decode(packet["base64"], validate=True)
                    for packet in detail["datagrams"] if packet["direction"] == direction], expected)
            captured[udp["id"]] = detail["datagrams"]
            for row in (tcp, udp):
                self.assertEqual((row["listen_port"], row["target_port"], row["peer"]),
                                 (local + index, origin.base + index, ["127.0.0.1", origin.base + index]))
        expected = [(local + index, origin.base + index) for index in range(3)]
        for transport in ("tcp", "udp"):
            ready = engine.ready[f"{transport}_forwards"]
            status = engine.command(f"{transport}_status")[1]
            self.assertEqual([(row["listen_port"], row["target_port"]) for row in ready], expected)
            self.assertEqual(status["forwards"], ready)
        network = engine.command("network_status")[1]
        self.assertEqual({row["listen_port"] for row in network["udp"]["listeners"]},
                         {local, local + 1, local + 2})
        self.assertEqual(len(origin.history), 9)
        self.assertEqual(engine.command("export_har")[1]["log"]["entries"], [])
        engine.command("stop_capture")
        network = engine.command("network_status")[1]
        self.assertEqual(network["public_listeners"], [])
        self.assertEqual(network["udp"]["listeners"], [])
        for transport, plural, body_key in (("tcp", "streams", "chunks"), ("udp", "associations", "datagrams")):
            rows = engine.command(f"{transport}_status")[1][plural]
            self.assertEqual(len(rows), 3)
            for row in rows:
                self.assertEqual(engine.command(f"{transport}_detail", id=row["id"])[1][body_key], captured[row["id"]])
            path = self.directory / f"retained-{transport}.json"
            engine.command(f"save_{transport}", path=str(path))
            self.assertEqual(len(json.loads(path.read_bytes())[plural]), 3)
        self.assert_released(local, 3)

    def assert_released(self, base, count):
        for port in range(base, base + count):
            with socket.socket() as probe:
                probe.settimeout(.3)
                result = probe.connect_ex(("127.0.0.1", port))
                if result == 0:
                    self.fail(f"TCP release probe unexpectedly connected: target=127.0.0.1:{port}, "
                              f"local={probe.getsockname()}, peer={probe.getpeername()}")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError as error:
                    self.fail(f"UDP release probe could not bind 127.0.0.1:{port}: {error}")

    def failed_start(self, configuration, http, socks, suffix):
        path = os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py"))
        result = subprocess.run([sys.executable, "-u", path, "--proxy-port", str(http),
            "--socks-port", str(socks), "--data-dir", str(self.directory / suffix), "--initialize-from-stdin"],
            input=json.dumps({"command": "initialize", "command_id": suffix, **configuration}) + "\n",
            text=True, capture_output=True, timeout=20)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(event.get("event") == "ready" for event in events), events)
        fatal = [event["message"] for event in events if event.get("event") == "fatal"]
        self.assertTrue(fatal, (events, result.stderr))
        return " ".join(fatal)

    def test_invalid_ranges_are_rejected_before_even_occupied_proxy_listeners(self):
        base, held = reserve_block(35)
        with ExitStack() as stack:
            for stream in held:
                stack.callback(stream.close)
            valid = {"listen_port": base, "listen_port_end": base + 2,
                     "target_host": "127.0.0.1", "target_port": 10000}
            variants = {
                "reversed": [{**valid, "listen_port_end": base - 1}],
                "remote-overflow": [{**valid, "target_port": 65534}],
                "local-overflow": [{**valid, "listen_port_end": 65536}],
                "overlap": [valid, {**valid, "listen_port": base + 2, "listen_port_end": base + 3}],
                "expanded-capacity": [{**valid, "listen_port_end": base + 32}],
                "aggregate-capacity": [{**valid, "listen_port_end": base + 30},
                    {**valid, "listen_port": base + 31, "listen_port_end": base + 32}],
            }
            for transport in ("tcp", "udp"):
                for name, values in variants.items():
                    with self.subTest(transport=transport, invalid=name):
                        message = self.failed_start({f"{transport}_forwards": values}, base + 33, base + 34,
                                                    f"{transport}-{name}")
                        self.assertNotRegex(message.lower(), "address already in use|errno 48|bind.*fail")
                        self.assertRegex(message.lower(), "port|range|forward|endpoint")
        self.assert_released(base, 35)

    def occupied_range_rolls_back(self, transport):
        base, held = reserve_block(8)
        occupied = next(stream for stream in held if stream.getsockname()[1] == base + 5
                        and stream.type == (socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM))
        for stream in held:
            if stream is not occupied:
                stream.close()
        self.addCleanup(occupied.close)
        if transport == "tcp":
            occupied.listen(1)
        occupied.settimeout(5)
        config = lambda start: {"listen_port": start, "listen_port_end": start + 2,
                               "target_host": "127.0.0.1", "target_port": 10000}
        message = self.failed_start({"tcp_forwards": [config(base + (3 if transport == "tcp" else 0))],
                                    "udp_forwards": [config(base + 3)]}, base + 6, base + 7, f"occupied-{transport}")
        self.assertRegex(message.lower(), "address already in use|errno 48|bind")
        # Prove ownership rollback did not close or replace our independently held socket.
        if transport == "tcp":
            with socket.create_connection(("127.0.0.1", base + 5), timeout=5) as client:
                with occupied.accept()[0] as accepted:
                    accepted.settimeout(5); client.sendall(b"external TCP owner")
                    self.assertEqual(accepted.recv(128), b"external TCP owner")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"external UDP owner", ("127.0.0.1", base + 5))
                self.assertEqual(occupied.recvfrom(128)[0], b"external UDP owner")
        occupied.close()
        self.assert_released(base, 8)

    def test_later_tcp_range_bind_failure_releases_prior_listeners_and_preserves_external_owner(self):
        self.occupied_range_rolls_back("tcp")

    def test_later_udp_range_bind_failure_releases_tcp_and_prior_udp_and_preserves_external_owner(self):
        self.occupied_range_rolls_back("udp")


if __name__ == "__main__":
    unittest.main()
