"""Actual UDP sockets -> JSONL engine -> datagram fixtures/files, never HTTP guesses."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from test_e2e import EngineHarness, ROOT, certificate_fixture, start_fixture
from test_tcp_forwarding import unused_port


def udp_socket():
    stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
    stream.settimeout(8); stream.bind(("127.0.0.1", 0))
    return stream


def udp_port():
    with udp_socket() as stream: return stream.getsockname()[1]


class UDPOrigin(socketserver.UDPServer):
    max_packet_size = 65535
    def __init__(self, address=("127.0.0.1", 0)):
        self.history, self.lock = [], threading.Lock()
        super().__init__(address, UDPHandler)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, stream = self.request
        with self.server.lock: self.server.history.append((data, self.client_address))
        stream.sendto(data[::-1], self.client_address)


class UDPForwardingAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-udp-network-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.ca, _, _ = certificate_fixture(self.directory, "udp")
        self.origin = self.origin_server()

    def origin_server(self, family=socket.AF_INET):
        class Origin(UDPOrigin): address_family = family
        server = Origin(("::1", 0) if family == socket.AF_INET6 else ("127.0.0.1", 0))
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def engine(self, host="127.0.0.1", origin=None, configuration=None):
        local = udp_port()
        selected = origin or self.origin
        forward = {"listen_port": local, "target_host": host, "target_port": selected.server_address[1]}
        engine = EngineHarness(self.directory, self.ca, extra_args=["--initialize-from-stdin"],
            initial_configuration={"udp_forwards": [forward], **(configuration or {})})
        self.addCleanup(engine.close)
        return engine, local

    def exchange(self, client, port, data):
        client.sendto(data, ("127.0.0.1", port))
        actual, peer = client.recvfrom(65535)
        self.assertEqual(actual, data[::-1]); self.assertEqual(peer, ("127.0.0.1", port))

    def associations(self, engine, predicate=lambda rows: bool(rows)):
        deadline = time.monotonic() + 8
        while True:
            rows = engine.command("udp_status")[1]["associations"]
            if predicate(rows): return rows
            if time.monotonic() > deadline: self.fail(f"UDP observations did not settle: {rows}")
            time.sleep(.01)

    def test_empty_maximum_ipv4_and_binary_datagrams_preserve_boundaries_and_pages(self):
        engine, port = self.engine()
        payloads = [b"", bytes(range(256)) * 255 + bytes(range(227))] + [bytes([index, 0, 255]) * index for index in range(1, 20)]
        self.assertEqual(len(payloads[1]), 65507)
        with udp_socket() as client:
            for data in payloads: self.exchange(client, port, data)
            row = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == len(payloads))[0]
            self.assertEqual(row["client"], list(client.getsockname()))
        observed = []
        for offset in (0, 32): observed.extend(engine.command("udp_detail", id=row["id"], offset=offset)[1]["datagrams"])
        self.assertEqual(len(observed), 2 * len(payloads))
        for direction in ("send", "receive"):
            bodies = [base64.b64decode(value["base64"]) for value in observed if value["direction"] == direction]
            self.assertEqual(bodies, payloads if direction == "send" else [data[::-1] for data in payloads])
        self.assertEqual(row["observed_datagrams"], 42)
        self.assertFalse(row["truncated"])
        self.assertEqual(row["dropped_client_datagrams"] + row["dropped_upstream_datagrams"], 0)
        self.assertEqual(engine.command("export_har")[1]["log"]["entries"], [], "UDP must not become fabricated HTTP flows")

    def test_eight_clients_keep_independent_remote_sockets_and_original_peers(self):
        engine, port = self.engine()
        barrier = threading.Barrier(8)
        def exchange(index):
            with udp_socket() as client:
                peer = client.getsockname(); barrier.wait(timeout=5)
                for number in range(3): self.exchange(client, port, f"client-{index}-packet-{number}".encode())
                return peer
        with ThreadPoolExecutor(max_workers=8) as workers: clients = list(workers.map(exchange, range(8)))
        rows = self.associations(engine, lambda rows: len(rows) == 8 and all(row["received_datagrams"] == 3 for row in rows))
        self.assertEqual({tuple(row["client"]) for row in rows}, set(clients))
        self.assertEqual(len({row["id"] for row in rows}), 8)
        with self.origin.lock: upstream = {peer for _data, peer in self.origin.history}
        self.assertEqual(len(upstream), 8)
        engine.command("stop_capture")
        network = engine.command("network_status")[1]
        self.assertEqual(network["udp"]["active_associations"], 0)
        self.assertEqual(network["udp"]["queued_datagrams"], 0)
        self.assertEqual(network["udp"]["listeners"], [])

    def test_connected_upstream_rejects_unsolicited_reply_from_another_socket(self):
        engine, port = self.engine()
        with udp_socket() as client, udp_socket() as stranger:
            self.exchange(client, port, b"first")
            with self.origin.lock: remote = self.origin.history[-1][1]
            stranger.sendto(b"forged", remote)
            client.settimeout(.15)
            with self.assertRaises(socket.timeout): client.recvfrom(65535)
            client.settimeout(8)
            self.exchange(client, port, b"legitimate")
        row = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 2)[0]
        datagrams = engine.command("udp_detail", id=row["id"])[1]["datagrams"]
        self.assertNotIn(base64.b64encode(b"forged").decode(), [value["base64"] for value in datagrams])

    def test_recording_is_association_scoped_and_clear_does_not_recapture_old_owner(self):
        engine, port = self.engine(configuration={"recording": False})
        with udp_socket() as old, udp_socket() as recorded, udp_socket() as fresh:
            self.exchange(old, port, b"off")
            engine.command("recording", enabled=True)
            self.exchange(old, port, b"same association remains off")
            self.assertEqual(engine.command("udp_status")[1]["associations"], [])
            self.exchange(recorded, port, b"recorded")
            self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 1)
            engine.command("clear_udp")
            self.exchange(recorded, port, b"cleared owner stays cleared")
            self.assertEqual(engine.command("udp_status")[1]["associations"], [])
            self.exchange(fresh, port, b"fresh")
            rows = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 1)
            self.assertEqual(rows[0]["client"], list(fresh.getsockname()))

    def test_stop_cancels_paced_datagram_and_accounts_known_drop_then_releases_ports(self):
        engine, port = self.engine(configuration={"network": {"upload_kbps": 1, "download_kbps": 0}})
        payload = b"pending" * 4096
        with udp_socket() as client:
            client.sendto(payload, ("127.0.0.1", port))
            row = self.associations(engine, lambda rows: rows and rows[0]["state"] == "open")[0]
            start = time.monotonic(); engine.command("stop_capture")
            self.assertLess(time.monotonic() - start, 3)
        row = engine.command("udp_detail", id=row["id"])[1]["association"]
        self.assertEqual((row["state"], row["sent_datagrams"], row["dropped_client_datagrams"], row["dropped_client_bytes"]),
                         ("cancelled", 0, 1, len(payload)))
        with self.origin.lock: self.assertEqual(self.origin.history, [])
        state = engine.command("network_status")[1]
        self.assertEqual(state["udp"]["active_associations"], 0)
        self.assertEqual(state["udp"]["queued_bytes"], 0)
        self.assertEqual(state["public_listeners"], [])
        self.assertEqual(state["internal_listeners"], [])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe: probe.bind(("127.0.0.1", port))

    def test_save_open_snapshot_atomic_later_failure_and_fresh_inspection_without_ca(self):
        engine, port = self.engine()
        with udp_socket() as client:
            for data in (b"", b"\x00\xffopen source"): self.exchange(client, port, data)
            row = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 2)[0]
            path = self.directory / "source.lens-udp.json"
            engine.command("save_udp", path=str(path))
        document = json.loads(path.read_bytes())
        self.assertEqual(document["associations"][0]["state"], "open")
        engine.command("stop_capture"); engine.command("load_udp", path=str(path))
        before = engine.command("udp_detail", id=row["id"])[1]
        self.assertEqual(before["association"]["state"], "incomplete")
        self.assertEqual(before["association"]["source_state"], "open")
        bad = copy.deepcopy(document)
        bad["associations"].append(copy.deepcopy(bad["associations"][0]))
        bad["associations"][-1]["id"] = "a" * 32
        bad["associations"][-1]["datagrams"][-1]["base64"] = "bad"
        malformed = self.directory / "bad.json"; malformed.write_text(json.dumps(bad))
        with self.assertRaises(AssertionError): engine.command("load_udp", path=str(malformed))
        self.assertEqual(engine.command("udp_detail", id=row["id"])[1], before)
        inspection_folder = self.directory / "fresh-inspector"; inspection_folder.mkdir()
        inspection = EngineHarness(inspection_folder, None, inspect_udp=path)
        self.addCleanup(inspection.close)
        self.assertEqual(inspection.command("udp_detail", id=row["id"])[1]["datagrams"], before["datagrams"])
        status = inspection.command("network_status")[1]
        self.assertEqual(status["public_listeners"], []); self.assertEqual(status["internal_listeners"], [])
        self.assertEqual(status["udp"]["listeners"], [])
        self.assertEqual(list((inspection_folder / "engine-state").iterdir()), [])
        with self.assertRaisesRegex(AssertionError, "Inspection-only"): inspection.command("configure", rules=[])
        inspection.close(); self.assertEqual(inspection.process.returncode, 0)

    def test_ipv6_upstream_preserves_numeric_peer_scope_and_whole_datagrams(self):
        origin = self.origin_server(socket.AF_INET6)
        engine, port = self.engine(host="::1", origin=origin)
        with udp_socket() as client:
            for data in (b"", b"ipv6\x00\xff"): self.exchange(client, port, data)
        row = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 2)[0]
        self.assertEqual(row["peer"], ["::1", origin.server_address[1]])
        self.assertEqual((row["peer_scope"], row["peer_flowinfo"]), (0, 0))

    def test_capture_cap_keeps_forwarding_whole_datagrams_and_marks_retention_loss(self):
        engine, port = self.engine()
        payload = bytes(range(256)) * 255 + bytes(range(227))
        with udp_socket() as client:
            for _ in range(80): self.exchange(client, port, payload)
        row = self.associations(engine, lambda rows: rows and rows[0]["received_datagrams"] == 80)[0]
        self.assertTrue(row["truncated"])
        self.assertEqual(row["observed_datagrams"], 160)
        self.assertEqual(row["sent_bytes"], len(payload) * 80)
        self.assertLessEqual(row["retained_bytes"], 4 * 1024 * 1024)
        retained = []
        for offset in range(0, row["retained_datagrams"], 32):
            retained.extend(engine.command("udp_detail", id=row["id"], offset=offset)[1]["datagrams"])
        self.assertTrue(all(value["observed_bytes"] == len(payload) and len(base64.b64decode(value["base64"])) == len(payload) for value in retained))
        self.assertEqual(row["dropped_client_datagrams"] + row["dropped_upstream_datagrams"], 0)

    def test_udp_and_http_share_direction_budget_without_splitting_datagram_or_starving_http(self):
        server, _ = start_fixture("UDP shared budget HTTP")
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        engine, port = self.engine(configuration={"network": {"upload_kbps": 16, "download_kbps": 0}})
        def datagram():
            with udp_socket() as client: self.exchange(client, port, b"x" * 65507)
            return time.monotonic()
        def http_request():
            with closing(http.client.HTTPConnection("127.0.0.1", engine.port, timeout=10)) as client:
                client.request("POST", f"http://127.0.0.1:{server.server_port}/shared-upload", body=b"h" * 8192)
                response = client.getresponse(); body = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(base64.b64decode(body["body"]), b"h" * 8192)
            return time.monotonic()
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            udp = pool.submit(datagram); tcp = pool.submit(http_request)
            tcp_end, udp_end = tcp.result(), udp.result()
        self.assertLess(tcp_end, udp_end)
        self.assertGreater(udp_end - start, 4.3)
        self.assertLess(udp_end - start, 9)

    def test_failed_udp_bind_rolls_back_tcp_socks_raw_tcp_and_prior_udp_listener(self):
        http, socks, raw_tcp, first = unused_port(), unused_port(), unused_port(), udp_port()
        engine_path = os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py"))
        with udp_socket() as occupied:
            config = {"command": "initialize", "command_id": "bind-proof",
                "tcp_forwards": [{"listen_port": raw_tcp, "target_host": "127.0.0.1", "target_port": 1}],
                "udp_forwards": [{"listen_port": value, "target_host": "127.0.0.1", "target_port": 1}
                                 for value in (first, occupied.getsockname()[1])]}
            result = subprocess.run([sys.executable, engine_path, "--proxy-port", str(http), "--socks-port", str(socks),
                "--data-dir", str(self.directory / "failed-bind"), "--initialize-from-stdin"], input=json.dumps(config) + "\n",
                text=True, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            events = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertFalse(any(event["event"] == "ready" for event in events))
            self.assertTrue(any(event["event"] == "fatal" for event in events), result.stderr)
            for port in (http, socks, raw_tcp):
                with socket.socket() as probe:
                    self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe: probe.bind(("127.0.0.1", first))
            self.assertGreaterEqual(occupied.fileno(), 0)


if __name__ == "__main__": unittest.main()
