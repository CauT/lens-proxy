"""Real control/stream/file workflows for protocol-neutral TCP forwarding."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import socket
import socketserver
import ssl
import tempfile
import threading
import time
import unittest
import uuid

from test_e2e import EngineHarness
from test_network_features import certificates
from test_client_certificates import client_identity, MutualTLSServer, MutualTLSHandler

def unused_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def receive_all(stream):
    value = bytearray()
    while chunk := stream.recv(16384):
        value.extend(chunk)
    return bytes(value)


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ForwardingAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-tcp-origins-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.ca, cls.leaves = certificates(Path(cls.temporary.name))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-tcp-acceptance-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def server(self, handler, ipv6=False):
        if ipv6:
            class IPv6Server(TCPServer):
                address_family = socket.AF_INET6
            server = IPv6Server(("::1", 0), handler)
        else:
            server = TCPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def engine(self, servers, **configuration):
        selected = [{"listen_port": unused_port(), "target_host": server.server_address[0],
                     "target_port": server.server_address[1]} for server in servers]
        engine = EngineHarness(self.directory, self.ca, extra_args=["--initialize-from-stdin"],
            initial_configuration={"tcp_forwards": selected, **configuration})
        self.addCleanup(engine.close)
        self.assertEqual([item["listen_port"] for item in engine.ready["tcp_forwards"]], [item["listen_port"] for item in selected])
        return engine, selected

    def wait_stream(self, engine, state="closed", after=0):
        return engine.wait(lambda event: event.get("event") == "tcp_stream" and event["stream"]["state"] == state,
                           after=after)["stream"]

    def bytes(self, engine, identity):
        result, chunks, offset = {"send": bytearray(), "receive": bytearray()}, [], 0
        while True:
            _, page = engine.command("tcp_detail", id=identity, offset=offset)
            chunks.extend(page["chunks"])
            for chunk in page["chunks"]:
                result[chunk["direction"]].extend(base64.b64decode(chunk["base64"], validate=True))
            offset += len(page["chunks"])
            if offset >= page["total"]:
                break
        return {key: bytes(value) for key, value in result.items()}, chunks, page["stream"]

    def test_binary_client_half_close_roundtrip_and_stopped_file_restore_without_http_fabrication(self):
        payload, greeting = bytes(range(256)) * 37, b"\x00server banner\xff"
        origin = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                self.request.sendall(greeting)
                data = receive_all(self.request)
                origin.append(data)
                self.request.sendall(data[::-1])
        server = self.server(Handler)
        engine, forwards = self.engine([server])
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as stream:
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_all(stream), greeting + payload[::-1])
        summary = self.wait_stream(engine)
        captured, _, info = self.bytes(engine, summary["id"])
        self.assertEqual(origin, [payload])
        self.assertEqual(captured, {"send": payload, "receive": greeting + payload[::-1]})
        self.assertEqual(info["peer"], list(server.server_address))
        self.assertFalse(info["truncated"])
        _, har = engine.command("export_har")
        self.assertEqual(har["log"]["entries"], [])
        path = self.directory / "full.lens-tcp.json"
        engine.command("save_tcp", path=str(path))
        engine.command("stop_capture")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=.3)
        self.assertEqual(self.bytes(engine, summary["id"])[0], captured)
        engine.command("clear_tcp")
        engine.command("load_tcp", path=str(path))
        after, _, imported = self.bytes(engine, summary["id"])
        self.assertEqual(after, captured)
        self.assertTrue(imported["imported"])
        engine.command("save_tcp", path=str(self.directory / "again.json"))
        first, second = json.loads(path.read_bytes()), json.loads((self.directory / "again.json").read_bytes())
        first["streams"][0]["imported"] = True
        self.assertEqual(first, second)

    def test_server_half_close_does_not_discard_later_client_bytes_and_ipv6_peer_facts_survive(self):
        origin, finished = [], threading.Event()
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                self.request.sendall(b"server first")
                self.request.shutdown(socket.SHUT_WR)
                origin.append(receive_all(self.request))
                finished.set()
        server = self.server(Handler, ipv6=True)
        engine, forwards = self.engine([server])
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as stream:
            self.assertEqual(receive_all(stream), b"server first")
            stream.sendall(b"client after server EOF\x00\xff")
            stream.shutdown(socket.SHUT_WR)
        self.assertTrue(finished.wait(5))
        summary = self.wait_stream(engine)
        captured, _, info = self.bytes(engine, summary["id"])
        self.assertEqual(captured["send"], origin[0])
        self.assertEqual(info["peer"], ["::1", server.server_address[1]])
        self.assertEqual(info["peer_scope"], 0)
        self.assertEqual(info["peer_flowinfo"], 0)

    def test_capture_cap_does_not_truncate_forwarding_or_claim_complete_bytes(self):
        payload = bytes(range(256)) * 20481
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(10)
                digest, total = hashlib.sha256(), 0
                while chunk := self.request.recv(16384):
                    digest.update(chunk); total += len(chunk)
                self.request.sendall(f"{total}:{digest.hexdigest()}".encode())
        server = self.server(Handler)
        engine, forwards = self.engine([server])
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=10) as stream:
            stream.sendall(payload); stream.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_all(stream), f"{len(payload)}:{hashlib.sha256(payload).hexdigest()}".encode())
        summary = self.wait_stream(engine)
        captured, chunks, info = self.bytes(engine, summary["id"])
        self.assertTrue(info["truncated"])
        self.assertEqual(info["sent_bytes"], len(payload))
        self.assertLessEqual(info["retained_bytes"], 4 * 1024 * 1024)
        self.assertLessEqual(len(chunks), 1024)
        self.assertEqual(captured["send"], payload[:len(captured["send"])])

    def test_pause_recording_keeps_forwarding_and_selects_new_connections_only(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(receive_all(self.request))
        server = self.server(Handler)
        engine, forwards = self.engine([server], recording=False)
        def send(value):
            with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as stream:
                stream.sendall(value); stream.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_all(stream), value)
        send(b"not recorded")
        _, status = engine.command("tcp_status")
        self.assertEqual(status["streams"], [])
        engine.command("recording", enabled=True)
        start = len(engine.events)
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as stream:
            info = self.wait_stream(engine, "open", after=start)
            engine.command("recording", enabled=False)
            stream.sendall(b"already admitted"); stream.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_all(stream), b"already admitted")
        self.wait_stream(engine, after=start)
        self.assertEqual(self.bytes(engine, info["id"])[0]["send"], b"already admitted")
        send(b"new omitted")
        _, status = engine.command("tcp_status")
        self.assertEqual(len(status["streams"]), 1)

    def test_stop_cancels_idle_and_throttled_streams_and_keeps_final_reason(self):
        ended = threading.Event()
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(5)
                    receive_all(self.request)
                finally:
                    ended.set()
        server = self.server(Handler)
        engine, forwards = self.engine([server], network={"upload_kbps": .01, "download_kbps": 0})
        stream = socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5)
        self.addCleanup(stream.close)
        info = self.wait_stream(engine, "open")
        stream.sendall(b"delayed" * 1000)
        began = time.monotonic()
        engine.command("stop_capture")
        self.assertLess(time.monotonic() - began, 3)
        final = self.wait_stream(engine, "cancelled")
        self.assertEqual(final["id"], info["id"])
        self.assertIn("stopped", final["error"])
        self.assertTrue(ended.wait(3))
        _, network = engine.command("network_status")
        self.assertEqual(network["active_connections"], 0)
        self.assertEqual(network["pending_cleanup"], 0)

    def test_tcp_and_http_uploads_share_one_real_aggregate_budget(self):
        from test_e2e import start_fixture
        import httpx
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                digest = hashlib.sha256(receive_all(self.request)).hexdigest().encode()
                self.request.sendall(digest)
        server = self.server(Handler)
        http, _ = start_fixture("shared HTTP budget")
        self.addCleanup(http.server_close); self.addCleanup(http.shutdown)
        engine, forwards = self.engine([server, server], network={"upload_kbps": 256, "download_kbps": 0})
        payload = bytes(range(256)) * 512
        barrier = threading.Barrier(3)
        def raw(port):
            with socket.create_connection(("127.0.0.1", port), timeout=8) as stream:
                barrier.wait(timeout=5)
                stream.sendall(payload); stream.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_all(stream), hashlib.sha256(payload).hexdigest().encode())
        def request():
            with httpx.Client(proxy=engine.proxy, trust_env=False, timeout=8) as client:
                barrier.wait(timeout=5)
                response = client.post(f"http://127.0.0.1:{http.server_port}/shared", content=payload)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(base64.b64decode(response.json()["body"]), payload)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=3) as workers:
            jobs = [workers.submit(raw, forward["listen_port"]) for forward in forwards]
            jobs.append(workers.submit(request))
            for job in jobs:
                job.result(timeout=10)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, .75 * len(payload) * 3 / 256000)
        self.assertLess(elapsed, 8)

    def test_failed_target_and_resolved_self_loop_are_visible_and_retry_is_independent(self):
        dead, own = unused_port(), unused_port()
        engine = EngineHarness(self.directory, self.ca, extra_args=["--initialize-from-stdin"],
            initial_configuration={"tcp_forwards": [{"listen_port": own, "target_host": "localhost", "target_port": own},
                {"listen_port": unused_port(), "target_host": "127.0.0.1", "target_port": dead}]})
        self.addCleanup(engine.close)
        for index, forward in enumerate(engine.ready["tcp_forwards"]):
            start = len(engine.events)
            with socket.create_connection(("127.0.0.1", forward["listen_port"]), timeout=5) as stream:
                self.assertEqual(stream.recv(1), b"")
            info = self.wait_stream(engine, "error", after=start)
            self.assertIsNone(info["peer"])
            if index == 0:
                self.assertIn("own listener", info["error"])
            else:
                self.assertIn("ConnectionRefusedError", info["error"])

    def test_tls_and_client_auth_remain_end_to_end_without_interception(self):
        root, _, pem, password, fingerprint, _ = client_identity(self.directory)
        server = MutualTLSServer(("127.0.0.1", 0), MutualTLSHandler)
        server.history, server.history_lock = [], threading.Lock()
        server.fixture_name = "opaque TLS"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self.leaves[0]); context.load_verify_locations(root)
        context.verify_mode = ssl.CERT_REQUIRED; server.tls_context = context
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        engine, forwards = self.engine([server])
        client = ssl.create_default_context(cafile=str(self.ca))
        client.load_cert_chain(pem, password=password)
        token = uuid.uuid4().hex.encode()
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as raw:
            with client.wrap_socket(raw, server_hostname="original.test") as stream:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                expected = x509.load_pem_x509_certificate(Path(self.leaves[0][0]).read_bytes()).fingerprint(hashes.SHA256()).hex()
                self.assertEqual(hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest(), expected)
                stream.sendall(b"GET /" + token + b" HTTP/1.1\r\nHost: original.test\r\nConnection: close\r\n\r\n")
                response = receive_all(stream)
                self.assertIn(fingerprint.encode(), response)
                self.assertIn(b"200", response.split(b"\r\n")[0])
        # SSL close may be observed as a reset on platforms without a clean TLS
        # close_notify. Either terminal state must finish promptly, without HTTP.
        info = engine.wait(lambda event: event.get("event") == "tcp_stream" and event["stream"]["state"] in ("closed", "error"))["stream"]
        observed, _, _ = self.bytes(engine, info["id"])
        self.assertNotIn(token, observed["send"])
        self.assertNotIn(fingerprint.encode(), observed["receive"])
        self.assertEqual(engine.command("export_har")[1]["log"]["entries"], [])

    def test_inspection_only_open_has_no_listener_and_preserves_historical_incompleteness(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"retained")
        server = self.server(Handler)
        engine, forwards = self.engine([server])
        with socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=5) as stream:
            stream.shutdown(socket.SHUT_WR); self.assertEqual(receive_all(stream), b"retained")
        info = self.wait_stream(engine)
        path = self.directory / "session.json"
        engine.command("save_tcp", path=str(path)); engine.close()
        value = json.loads(path.read_bytes()); value["streams"][0].update(state="open", ended=None)
        path.write_text(json.dumps(value))
        directory = self.directory / "inspection-owner"
        directory.mkdir()
        inspection = EngineHarness(directory, None, inspect_tcp=path)
        self.addCleanup(inspection.close)
        self.assertTrue(inspection.ready["capture_stopped"])
        row = inspection.wait(lambda event: event.get("event") == "tcp_stream" and event["stream"]["id"] == info["id"])["stream"]
        self.assertEqual(row["state"], "incomplete")
        self.assertEqual(row["source_state"], "open")
        self.assertIsNone(row["ended"])
        status = inspection.command("network_status")[1]
        self.assertEqual(status["public_listeners"], [])
        self.assertEqual(status["internal_listeners"], [])
        self.assertEqual(list((directory / "engine-state").iterdir()), [], "TCP file inspection must not create a CA or protocol state")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", forwards[0]["listen_port"]), timeout=.2)
        inspection.close()
        self.assertEqual(inspection.process.returncode, 0)

    def test_bind_failure_and_invalid_initial_endpoints_never_report_ready_or_leave_listeners(self):
        free = unused_port()
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0)); occupied.listen()
            configurations = [
                [{"listen_port": free, "target_host": "127.0.0.1", "target_port": 1},
                 {"listen_port": occupied.getsockname()[1], "target_host": "127.0.0.1", "target_port": 1}],
                [{"listen_port": True, "target_host": "127.0.0.1", "target_port": 1}],
                [{"listen_port": free, "target_host": "https://example.test", "target_port": 443}],
            ]
            for index, configuration in enumerate(configurations):
                directory = self.directory / str(index); directory.mkdir()
                with self.assertRaises(AssertionError):
                    EngineHarness(directory, self.ca, extra_args=["--initialize-from-stdin"],
                        initial_configuration={"tcp_forwards": configuration})
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", free), timeout=.2)


if __name__ == "__main__":
    unittest.main()
