#!/usr/bin/env python3
"""Real loopback acceptance: JSONL engine, HTTP/TLS fixtures and WebSocket wire frames.

Run with the bundled runtime, without changing macOS proxy or certificate trust:
  mac-charles/.runtime/bin/python -m unittest discover -s mac-charles/tests -p test_e2e.py -v
Every capture, certificate and log belongs to a TemporaryDirectory.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
BINARY_BODY = bytes(range(256)) + b"\x00\xff\r\nLens binary fixture"


def certificate_fixture(directory, prefix):
    """A private test CA and a SAN-bound localhost server certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Lens test {prefix} CA")])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    ca_path, cert_path, key_path = [directory / f"{prefix}-{suffix}.pem"
                                     for suffix in ("ca", "server", "key")]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_path, cert_path, key_path


def read_exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.read(count - len(result))
        if not part:
            raise EOFError("WebSocket closed before complete frame")
        result += part
    return result


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            return self.websocket()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        record = {"method": self.command, "path": self.path,
                  "headers": list(self.headers.raw_items()),
                  "body": base64.b64encode(body).decode()}
        with self.server.history_lock:
            self.server.history.append(record)
        if self.path.startswith("/binary"):
            payload, mime = BINARY_BODY, "application/octet-stream"
        elif self.path.startswith("/text"):
            payload, mime = b"original response body", "text/plain"
        else:
            payload, mime = json.dumps(record).encode(), "application/json"
        streaming_zstd = self.path.startswith("/zstd-streaming")
        if streaming_zstd:
            import zstandard
            encoded = zstandard.ZstdCompressor(write_content_size=False).compress(payload)
            # Valid streaming frame with a 4 MiB declared window. A tiny
            # content-size-bearing fixture does not exercise this admission.
            assert encoded[4] == 0
            payload = encoded[:5] + b"\x60" + encoded[6:]
        self.send_response(200)
        self.send_header("Content-Type", mime)
        if streaming_zstd:
            self.send_header("Content-Encoding", "zstd")
        self.send_header("X-Fixture", self.server.fixture_name)
        self.send_header("Set-Cookie", "first=1")
        self.send_header("Set-Cookie", "second=2")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def websocket(self):
        key = self.headers["Sec-WebSocket-Key"]
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        try:
            head = read_exact(self.rfile, 2)
            length = head[1] & 127
            if length == 126:
                length = struct.unpack("!H", read_exact(self.rfile, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", read_exact(self.rfile, 8))[0]
            if length > 65536:
                raise ValueError("oversized test message")
            mask = read_exact(self.rfile, 4) if head[1] & 128 else b"\0" * 4
            encoded = read_exact(self.rfile, length)
            payload = bytes(value ^ mask[i % 4] for i, value in enumerate(encoded))
            answer = b"echo:" + payload
            self.wfile.write(bytes([0x81, len(answer)]) + answer)
            self.wfile.flush()
            # A normal close is observable by both proxy and client.
            self.wfile.write(b"\x88\x02\x03\xe8")
            self.wfile.flush()
        except (EOFError, OSError):
            pass
        self.close_connection = True


def start_fixture(name, cert=None, key=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.daemon_threads = True
    server.fixture_name, server.history, server.history_lock = name, [], threading.Lock()
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, worker


class EngineHarness:
    def __init__(self, directory, upstream_ca, extra_args=(), initial_configuration=None, inspect_tcp=None, inspect_udp=None, inspect_workspace=None):
        if sum(value is not None for value in (inspect_tcp, inspect_udp, inspect_workspace)) > 1:
            raise ValueError("Select one session file to inspect")
        inspecting = any(value is not None for value in (inspect_tcp, inspect_udp, inspect_workspace))
        if inspecting and (upstream_ca is not None or extra_args or initial_configuration is not None):
            raise ValueError("Inspection-only harness must not configure listener/TLS initialization")
        self.condition = threading.Condition()
        self.events, self.flows = [], {}
        self.failure = None
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.stderr = (directory / "engine-stderr.log").open("w+")
        arguments = [
            sys.executable, "-u", os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py")),
            "--proxy-port", str(self.port), "--data-dir", str(directory / "engine-state"),
        ]
        arguments += (["--inspect-workspace", str(inspect_workspace)] if inspect_workspace is not None else
                      ["--inspect-tcp" if inspect_tcp is not None else "--inspect-udp", str(inspect_tcp if inspect_tcp is not None else inspect_udp)] if inspecting
                      else ["--upstream-ca", str(upstream_ca), *extra_args])
        self.process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, bufsize=1,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.reader = threading.Thread(target=self.read_events, daemon=True)
        self.reader.start()
        try:
            if initial_configuration is not None:
                self.process.stdin.write(json.dumps({"command": "initialize", "command_id": uuid.uuid4().hex,
                                                    **initial_configuration}) + "\n")
                self.process.stdin.flush()
            self.ready = self.wait(lambda event: event.get("event") == "ready", timeout=30)
            self.proxy = f"http://127.0.0.1:{self.port}"
            if inspecting:
                if not self.ready.get("capture_stopped"):
                    raise AssertionError("Inspection-only engine did not report stopped capture")
                return
            # ready is a lifecycle callback; also verify the listening socket itself.
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
        except BaseException:
            self.close()
            raise

    def read_events(self):
        try:
            for line in self.process.stdout:
                event = json.loads(line)
                with self.condition:
                    self.events.append(event)
                    if event.get("event") == "flow":
                        self.flows[event["flow"]["id"]] = event["flow"]
                    if event.get("event") == "removed":
                        self.flows.pop(event["id"], None)
                    if event.get("event") == "fatal":
                        self.failure = "fatal: " + event.get("message", "Proxy failed")
                    self.condition.notify_all()
        except Exception as exc:
            with self.condition:
                self.failure = str(exc)
                self.condition.notify_all()
        finally:
            with self.condition:
                if self.failure is None:
                    self.failure = "Control stream closed"
                self.condition.notify_all()

    def wait(self, predicate, timeout=15, after=0):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for event in self.events[after:]:
                    if predicate(event):
                        return event
                if self.failure or self.process.poll() is not None:
                    self.stderr.flush()
                    self.stderr.seek(0)
                    raise AssertionError(f"Engine stopped: {self.failure}; {self.stderr.read()}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"Timed out waiting for engine; last events: {self.events[-5:]}")
                self.condition.wait(remaining)

    def command(self, operation, **fields):
        identifier = uuid.uuid4().hex
        start = len(self.events)
        self.process.stdin.write(json.dumps({"command": operation, "command_id": identifier, **fields}) + "\n")
        self.process.stdin.flush()
        event = self.wait(lambda e: e.get("command_id") == identifier
                          and e.get("event") in ("result", "error"), after=start)
        if event["event"] == "error":
            raise AssertionError(f"Command {operation} failed: {event['message']}")
        return identifier, event.get("value")

    def configure(self, rules):
        return self.command("configure", rules=rules, ssl_hosts="*")

    def flow(self, url, state="complete", after=0):
        return self.wait(lambda e: e.get("event") == "flow" and e["flow"]["url"] == url
                         and e["flow"]["state"] == state, after=after)["flow"]

    def close(self):
        if self.process.poll() is None:
            try:
                self.command("shutdown")
            except (AssertionError, BrokenPipeError):
                pass
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        for pipe in (self.process.stdin, self.process.stdout):
            try:
                pipe.close()
            except BrokenPipeError:
                pass
        self.stderr.close()


class RealProxyAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-e2e-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, cert, key = certificate_fixture(cls.directory, "trusted")
        _, rogue_cert, rogue_key = certificate_fixture(cls.directory, "untrusted")
        cls.servers = []
        for name, cert_path, key_path in [("http", None, None), ("https", cert, key),
                                          ("untrusted", rogue_cert, rogue_key)]:
            server, worker = start_fixture(name, cert_path, key_path)
            cls.servers.append((server, worker))
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
        cls.http = f"http://127.0.0.1:{cls.servers[0][0].server_port}"
        cls.https = f"https://localhost:{cls.servers[1][0].server_port}"
        cls.untrusted = f"https://localhost:{cls.servers[2][0].server_port}"
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)
        cls.context = ssl.create_default_context(cafile=cls.engine.ready["ca_cert"])

    def setUp(self):
        self.engine.configure([])
        self.engine.command("recording", enabled=True)
        self.engine.command("clear")

    def client(self):
        return httpx.Client(proxy=self.engine.proxy, verify=self.context,
                            trust_env=False, timeout=10)

    def rule(self, kind, match=None, **fields):
        return {"kind": kind, "match": match or self.http + "/*", **fields}

    def test_http_binary_headers_and_har_roundtrip(self):
        url = self.http + "/binary?empty=&item=1&item=2"
        request_body = b"\x00\xffrequest\x80"
        with self.client() as client:
            response = client.post(url, content=request_body,
                headers=[("X-Duplicate", "one"), ("X-Duplicate", "two")])
        self.assertEqual(response.content, BINARY_BODY)
        self.assertEqual(response.headers.get_list("Set-Cookie"), ["first=1", "second=2"])
        captured = self.engine.flow(url)
        _, data = self.engine.command("detail", id=captured["id"])
        self.assertEqual([v for k, v in data["request_headers"] if k.lower() == "x-duplicate"], ["one", "two"])
        _, har = self.engine.command("export_har")
        self.assertEqual(len(har["log"]["entries"]), 1)
        entry = har["log"]["entries"][0]
        self.assertEqual(base64.b64decode(entry["request"]["postData"]["text"]), request_body)
        self.assertEqual(base64.b64decode(entry["response"]["content"]["text"]), BINARY_BODY)
        self.engine.command("clear")
        _, imported = self.engine.command("import_har", har=har)
        self.assertEqual(imported["imported"], 1)
        _, exported = self.engine.command("export_har")
        self.assertEqual(exported["log"]["entries"][0], entry)

    def test_https_connect_decrypts_with_explicit_ca_trust(self):
        url = self.https + "/echo?secure=yes"
        with self.client() as client:
            response = client.post(url, content=b"inside TLS")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(base64.b64decode(response.json()["body"]), b"inside TLS")
        flow = self.engine.flow(url)
        _, data = self.engine.command("detail", id=flow["id"])
        self.assertEqual(data["request_body"], "inside TLS")
        self.assertEqual(flow["scheme"], "https")

    def test_upstream_tls_verification_is_not_disabled(self):
        url = self.untrusted + "/echo"
        with self.client() as client:
            response = client.get(url)
        self.assertEqual(response.status_code, 502)
        self.assertIn("certificate", response.text.lower())
        self.assertEqual(self.servers[2][0].history, [])

    def test_paused_recording_still_forwards(self):
        self.engine.command("recording", enabled=False)
        with self.client() as client:
            response = client.post(self.http + "/unrecorded", content=b"still forwarded")
        self.assertEqual(base64.b64decode(response.json()["body"]), b"still forwarded")
        _, har = self.engine.command("export_har")
        self.assertEqual(har["log"]["entries"], [])
        self.engine.command("recording", enabled=True)
        with self.client() as client:
            client.get(self.http + "/recorded-again")
        self.engine.flow(self.http + "/recorded-again")

    def test_rewrite_request_and_response(self):
        self.engine.configure([
            self.rule("rewrite_request_header", name="X-Added", value="on request"),
            self.rule("rewrite_request_body", name="before", value="after"),
            self.rule("rewrite_response_header", name="X-Added", value="on response"),
            self.rule("rewrite_response_body", name="original", value="rewritten")])
        with self.client() as client:
            echo = client.post(self.http + "/echo", content=b"before")
            text = client.get(self.http + "/text")
        self.assertEqual(base64.b64decode(echo.json()["body"]), b"after")
        self.assertIn(["X-Added", "on request"], echo.json()["headers"])
        self.assertEqual(text.headers["X-Added"], "on response")
        self.assertEqual(text.content, b"rewritten response body")

    def test_map_remote_and_local(self):
        mapped = self.https + "/base"
        self.engine.configure([self.rule("map_remote", value=mapped)])
        with self.client() as client:
            response = client.get(self.http + "/echo?kept=1")
        self.assertEqual(response.headers["X-Fixture"], "https")
        self.assertEqual(response.json()["path"], "/base/echo?kept=1")
        local = self.directory / "map.txt"
        local.write_bytes(b"local fixture response")
        self.engine.configure([self.rule("map_local", value=str(local))])
        with self.client() as client:
            response = client.get(self.http + "/mapped-local")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, local.read_bytes())

    def test_block_and_delay(self):
        self.engine.configure([self.rule("block", match=self.http + "/blocked")])
        with self.client() as client:
            response = client.get(self.http + "/blocked")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(any(item["path"] == "/blocked" for item in self.servers[0][0].history))
        self.engine.configure([self.rule("delay", value="180")])
        started = time.monotonic()
        with self.client() as client:
            response = client.get(self.http + "/delayed")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(time.monotonic() - started, 0.16)

    def test_request_and_response_breakpoint_edits(self):
        for side in ("request", "response"):
            with self.subTest(side=side):
                url = self.http + f"/echo?pause={side}"
                self.engine.configure([self.rule("breakpoint_" + side)])
                after = len(self.engine.events)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    def request():
                        with self.client() as client:
                            return client.post(url, content=b"before pause")
                    future = pool.submit(request)
                    paused = self.engine.flow(url, state="paused", after=after)
                    self.assertFalse(future.done(), "breakpoint must hold the actual client request")
                    self.engine.command("resume", id=paused["id"], action="continue",
                                        **{side + "_body": "edited by breakpoint"})
                    response = future.result(timeout=10)
                if side == "request":
                    self.assertEqual(base64.b64decode(response.json()["body"]), b"edited by breakpoint")
                else:
                    self.assertEqual(response.content, b"edited by breakpoint")

    def test_breakpoint_abort_releases_client(self):
        for side in ("request", "response"):
            with self.subTest(side=side):
                url = self.http + "/abort-" + side
                self.engine.configure([self.rule("breakpoint_" + side)])
                after = len(self.engine.events)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    def request():
                        with self.client() as client:
                            return client.get(url)
                    future = pool.submit(request)
                    paused = self.engine.flow(url, state="paused", after=after)
                    self.assertFalse(future.done())
                    self.engine.command("resume", id=paused["id"], action="abort")
                    # A client timeout is not successful abort delivery. The proxy must
                    # actually terminate this connection promptly in either stage.
                    with self.assertRaises((httpx.NetworkError, httpx.RemoteProtocolError)):
                        future.result(timeout=3)
                self.engine.flow(url, state="error", after=after)
        self.assertFalse(any(item["path"] == "/abort-request" for item in self.servers[0][0].history))

    def test_compose_and_replay_are_new_proxy_captures(self):
        url = self.https + "/composed"
        after = len(self.engine.events)
        command_id, queued = self.engine.command("compose", method="POST", url=url,
            headers=[["Content-Type", "text/plain"], ["X-Composed", "yes"]], body="composed body")
        self.assertTrue(queued["queued"])
        self.engine.wait(lambda e: e.get("event") == "request_finished" and e.get("command_id") == command_id,
                         after=after)
        first = self.engine.flow(url, after=after)
        self.assertTrue(first["replayed"])
        _, detail = self.engine.command("detail", id=first["id"])
        self.assertEqual(detail["request_body"], "composed body")
        self.assertFalse(any(k.lower() == "x-lens-internal-replay" for k, _ in detail["request_headers"]))
        after = len(self.engine.events)
        command_id, queued = self.engine.command("replay", id=first["id"])
        self.engine.wait(lambda e: e.get("event") == "request_finished" and e.get("command_id") == command_id,
                         after=after)
        second = self.engine.flow(url, after=after)
        self.assertNotEqual(first["id"], second["id"])
        self.assertTrue(second["replayed"])
        recorded = [item for item in self.servers[1][0].history if item["path"] == "/composed"]
        self.assertEqual(len(recorded), 2)
        self.assertTrue(all(base64.b64decode(item["body"]) == b"composed body" for item in recorded))

    def test_websocket_upgrade_and_bidirectional_messages(self):
        url = self.http + "/ws"
        key = base64.b64encode(b"0123456789abcdef").decode()
        after = len(self.engine.events)
        with socket.create_connection(("127.0.0.1", self.engine.port), timeout=10) as sock:
            sock.sendall((f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{self.servers[0][0].server_port}\r\n"
                          "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                          f"Sec-WebSocket-Key: {key}\r\n\r\n").encode())
            stream = sock.makefile("rb")
            self.addCleanup(stream.close)
            self.assertIn(b" 101 ", stream.readline())
            while True:
                line = stream.readline()
                if line == b"\r\n":
                    break
                self.assertTrue(line, "WebSocket upgrade ended before its header terminator")
            payload, mask = b"hello Lens", b"abcd"
            masked = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
            sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
            header = read_exact(stream, 2)
            self.assertEqual(header[0] & 15, 1)
            self.assertEqual(read_exact(stream, header[1] & 127), b"echo:hello Lens")
            sock.sendall(b"\x88\x82abcd" + bytes(value ^ b"abcd"[i % 4]
                         for i, value in enumerate(b"\x03\xe8")))
        flow = self.engine.flow(url, after=after)
        deadline = time.monotonic() + 5
        while True:
            _, data = self.engine.command("detail", id=flow["id"])
            if len(data["messages"]) >= 2:
                break
            if time.monotonic() > deadline:
                self.fail("WebSocket messages were not captured")
            time.sleep(0.02)
        self.assertEqual([(m["direction"], m["text"]) for m in data["messages"]],
                         [("send", "hello Lens"), ("receive", "echo:hello Lens")])
        _, har = self.engine.command("export_har")
        self.assertEqual(len(har["log"]["entries"][0]["_webSocketMessages"]), 2)

    def test_clear_does_not_resurrect_paused_old_flow(self):
        url = self.http + "/clear-inflight"
        self.engine.configure([self.rule("breakpoint_request")])
        after = len(self.engine.events)
        with ThreadPoolExecutor(max_workers=1) as pool:
            def request():
                with self.client() as client:
                    return client.get(url)
            future = pool.submit(request)
            self.engine.flow(url, state="paused", after=after)
            self.engine.command("clear")
            self.assertEqual(future.result(timeout=10).status_code, 200)
        _, har = self.engine.command("export_har")
        self.assertEqual(har["log"]["entries"], [], "late response must not recreate a cleared capture")


class StreamingBodyAcceptance(unittest.TestCase):
    def test_https_zstd_details_export_and_stopped_workspace_reopen(self):
        import zstandard
        with tempfile.TemporaryDirectory(prefix="lens-zstd-e2e-") as directory:
            directory = Path(directory)
            ca, cert, key = certificate_fixture(directory, "streaming")
            server, worker = start_fixture("zstd", cert, key)
            engine = inspector = None
            try:
                engine = EngineHarness(directory, ca)
                context = ssl.create_default_context(cafile=engine.ready["ca_cert"])
                url = f"https://localhost:{server.server_port}/zstd-streaming-{uuid.uuid4().hex}"
                request = b'{"source":"real HTTPS streaming zstd"}'
                with httpx.Client(proxy=engine.proxy, verify=context, trust_env=False, timeout=10) as client:
                    response = client.post(url, content=request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(base64.b64decode(response.json()["body"]), request)
                flow = engine.flow(url)
                _, detail = engine.command("detail", id=flow["id"])
                self.assertEqual(base64.b64decode(detail["request_body_base64"]), request)
                self.assertEqual(base64.b64decode(detail["response_body_base64"]), response.content)
                _, har = engine.command("export_har")
                entry = har["log"]["entries"][0]
                raw = base64.b64decode(entry["_lensRawResponseBody"])
                self.assertEqual(zstandard.get_frame_parameters(raw).window_size, 4 * 1024 * 1024)
                self.assertEqual(entry["response"]["content"]["text"].encode(), response.content)
                engine.command("stop_capture")
                stopped_har = engine.command("export_har")[1]
                # Stop legitimately completes live connection timestamps. Bind
                # reopen identity to that final snapshot, while proving that no
                # captured request/response representation changed during Stop.
                stopped_entry = stopped_har["log"]["entries"][0]
                for field in ("request", "response", "_lensRawResponseBody", "_lensRawRequestBody"):
                    self.assertEqual(stopped_entry.get(field), entry.get(field))
                path = directory / "stopped.lens.json"
                engine.command("save_workspace", path=str(path))
                stopped = engine.command("detail", id=flow["id"])[1]
                self.assertEqual(stopped, detail)
                inspection = directory / "inspection"
                inspection.mkdir()
                inspector = EngineHarness(inspection, None, inspect_workspace=path)
                restored = inspector.flow(url)
                reopened = inspector.command("detail", id=restored["id"])[1]
                self.assertEqual(base64.b64decode(reopened["response_body_base64"]), response.content)
                self.assertEqual(inspector.command("export_har")[1], stopped_har)
            finally:
                if inspector is not None:
                    inspector.close()
                if engine is not None:
                    engine.close()
                server.shutdown(); server.server_close(); worker.join(3)
                self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
