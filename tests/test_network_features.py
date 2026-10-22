"""Wire-level acceptance for shared rate limits, SOCKS/reverse and DNS overrides.

Only local, owned fixtures are used; all CAs, keys and engine state are temporary.
Run: mac-charles/.runtime/bin/python -m unittest discover -s mac-charles/tests -p test_network_features.py -v
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit
import uuid

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from test_e2e import EngineHarness


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def certificates(directory):
    authority = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lens network fixture CA")])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(authority.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1)))
    ca = (builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(authority.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
          .sign(authority, hashes.SHA256()))
    ca_path = directory / "origin-ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaves = []
    for label, names in [("good", ["original.test", "localhost"]), ("wrong-san", ["wrong.test"])]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sans = [x509.DNSName(name) for name in names]
        if label == "good":
            sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, names[0])])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName(sans), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(authority, hashes.SHA256()))
        cert_path, key_path = directory / f"{label}-cert.pem", directory / f"{label}-key.pem"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        leaves.append((cert_path, key_path))
    return ca_path, leaves


def payload(size):
    return (bytes(range(256)) * (size // 256 + 1))[:size]


class NetworkOrigin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2 * 1024 * 1024:
            raise ValueError("fixture request too large")
        body = b""
        while len(body) < length:
            chunk = self.rfile.read(min(8192, length - len(body)))
            if not chunk:
                break
            body += chunk
            with self.server.progress_condition:
                self.server.progress.setdefault(self.path, []).append((len(body), time.monotonic()))
                self.server.progress_condition.notify_all()
        record = {"path": self.path, "host": self.headers.get("Host"),
                  "sni": getattr(self.connection, "fixture_sni", None),
                  "body_size": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                  "progress": self.server.progress.get(self.path, [])}
        with self.server.history_lock:
            self.server.history.append(record)
        if urlsplit(self.path).path == "/download":
            size = int(parse_qs(urlsplit(self.path).query).get("size", ["65536"])[0])
            if not 0 <= size <= 2 * 1024 * 1024:
                raise ValueError("fixture response too large")
            response, mime = payload(size), "application/octet-stream"
        else:
            response, mime = json.dumps(record).encode(), "application/json"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        try:
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            pass


def fixture(cert=None, key=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), NetworkOrigin)
    server.daemon_threads = True
    server.history, server.history_lock = [], threading.Lock()
    server.progress, server.progress_condition = {}, threading.Condition()
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        def observe_sni(connection, server_name, _context):
            connection.fixture_sni = server_name

        context.set_servername_callback(observe_sni)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def read_exact(sock, length):
    chunks = b""
    while len(chunks) < length:
        received = sock.recv(length - len(chunks))
        if not received:
            raise EOFError("short SOCKS reply")
        chunks += received
    return chunks


def socks_connect(proxy_port, target_port):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
    try:
        sock.sendall(b"\x05\x01\x00")
        if read_exact(sock, 2) != b"\x05\x00":
            raise AssertionError("SOCKS5 no-auth method rejected")
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        version, status, _reserved, atyp = read_exact(sock, 4)
        if version != 5 or status != 0:
            raise AssertionError(f"SOCKS5 CONNECT failed: {version=}, {status=}")
        if atyp == 1:
            read_exact(sock, 4)
        elif atyp == 4:
            read_exact(sock, 16)
        elif atyp == 3:
            read_exact(sock, read_exact(sock, 1)[0])
        else:
            raise AssertionError(f"Invalid SOCKS address type {atyp}")
        read_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


class NetworkFeaturesAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-network-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.ca, leaves = certificates(cls.directory)
        cls.http_origin = fixture()
        cls.tls_origin = fixture(*leaves[0])
        cls.wrong_san_origin = fixture(*leaves[1])
        for server in (cls.http_origin, cls.tls_origin, cls.wrong_san_origin):
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
        cls.http = f"http://127.0.0.1:{cls.http_origin.server_port}"
        cls.https = f"https://localhost:{cls.tls_origin.server_port}"

    def setUp(self):
        directory = self.directory / uuid.uuid4().hex
        directory.mkdir()
        self.socks_port, self.reverse_port = free_port(), free_port()
        self.engine = EngineHarness(directory, self.ca, extra_args=[
            "--socks-port", str(self.socks_port), "--reverse-port", str(self.reverse_port),
            "--reverse-url", self.http])
        self.addCleanup(self.engine.close)
        self.lens_context = ssl.create_default_context(cafile=self.engine.ready["ca_cert"])

    def configure(self, upload=0, download=0, rules=None, ssl_hosts="*"):
        return self.engine.command("configure", rules=rules or [], ssl_hosts=ssl_hosts,
                                   network={"upload_kbps": upload, "download_kbps": download})

    def client(self, context=None):
        return httpx.Client(proxy=self.engine.proxy, verify=context or self.lens_context,
                            timeout=20, trust_env=False)

    def download(self, size, barrier=None):
        progress = []
        with self.client() as client:
            if barrier:
                barrier.wait(timeout=5)
            with client.stream("GET", self.http + f"/download?size={size}") as response:
                response.raise_for_status()
                body = b""
                for chunk in response.iter_raw(chunk_size=8192):
                    body += chunk
                    progress.append((len(body), time.monotonic()))
        self.assertEqual(body, payload(size))
        return progress

    def test_download_rate_is_sustained_and_progressive(self):
        self.configure(download=128)
        size = 512 * 1024
        started = time.monotonic()
        progress = self.download(size)
        elapsed = progress[-1][1] - started
        self.assertGreaterEqual(elapsed, size / 128000 * 0.75)
        middle = next(timestamp for count, timestamp in progress if count >= size // 2)
        self.assertGreater(middle - progress[0][1], 0.8)
        self.assertGreater(progress[-1][1] - middle, 0.8)

    def test_concurrent_downloads_share_aggregate_budget(self):
        self.configure(download=128)
        size = 128 * 1024
        barrier = threading.Barrier(3)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.download, size, barrier)
            second = pool.submit(self.download, size, barrier)
            started = time.monotonic()
            barrier.wait(timeout=5)
            first_progress, second_progress = first.result(timeout=15), second.result(timeout=15)
        elapsed = max(first_progress[-1][1], second_progress[-1][1]) - started
        self.assertGreaterEqual(elapsed, 2 * size / 128000 * 0.75,
                                "concurrent clients must share a single 128 kB/s download budget")

    def test_upload_arrives_progressively_and_control_remains_responsive(self):
        # TLS passthrough avoids mitmproxy's intentional whole-body buffering hiding
        # wire-level arrival progress from the owned origin; normal certificate checks remain enabled.
        self.configure(upload=128, ssl_hosts="")
        context = ssl.create_default_context(cafile=self.ca)
        body = payload(512 * 1024)
        path = "/upload?test=" + uuid.uuid4().hex
        with ThreadPoolExecutor(max_workers=1) as pool:
            def upload():
                with self.client(context=context) as client:
                    return client.post(self.https + path, content=body)
            started = time.monotonic()
            future = pool.submit(upload)
            with self.tls_origin.progress_condition:
                seen = self.tls_origin.progress_condition.wait_for(
                    lambda: bool(self.tls_origin.progress.get(path)), timeout=8)
            self.assertTrue(seen, "origin must begin receiving the rate-limited upload")
            command_started = time.monotonic()
            self.engine.command("export_har")
            self.assertLess(time.monotonic() - command_started, 0.75)
            self.assertFalse(future.done(), "the upload must still be active during the control command")
            response = future.result(timeout=15)
        self.assertEqual(response.status_code, 200)
        record = response.json()
        self.assertEqual(record["body_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(record["body_size"], len(body))
        progress = record["progress"]
        self.assertGreaterEqual(progress[-1][1] - started, len(body) / 128000 * 0.75)
        middle = next(timestamp for count, timestamp in progress if count >= len(body) // 2)
        self.assertGreater(middle - progress[0][1], 0.8)
        self.assertGreater(progress[-1][1] - middle, 0.8)

    def test_concurrent_uploads_share_aggregate_budget(self):
        self.configure(upload=128, ssl_hosts="")
        context = ssl.create_default_context(cafile=self.ca)
        body = payload(128 * 1024)
        barrier = threading.Barrier(3)

        def upload():
            with self.client(context=context) as client:
                barrier.wait(timeout=5)
                response = client.post(self.https + "/aggregate-upload?test=" + uuid.uuid4().hex,
                                       content=body)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["body_sha256"], hashlib.sha256(body).hexdigest())
            return response.json()["progress"][-1][1]

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(upload), pool.submit(upload)
            started = time.monotonic()
            barrier.wait(timeout=5)
            ended = max(first.result(timeout=15), second.result(timeout=15))
        self.assertGreaterEqual(ended - started, 2 * len(body) / 128000 * 0.75,
                                "concurrent clients must share a single 128 kB/s upload budget")

    def test_socks5_handshake_and_http_https_transfer(self):
        self.configure()
        self.assertEqual(self.engine.ready["socks_port"], self.socks_port)
        for secure in (False, True):
            with self.subTest(secure=secure):
                port = self.tls_origin.server_port if secure else self.http_origin.server_port
                raw = socks_connect(self.socks_port, port)
                connection = self.lens_context.wrap_socket(raw, server_hostname="localhost") if secure else raw
                with connection:
                    host = "localhost" if secure else "127.0.0.1"
                    connection.sendall(f"GET /socks-{'tls' if secure else 'plain'} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    try:
                        self.assertEqual(response.status, 200)
                        data = json.loads(response.read())
                        self.assertEqual(data["host"], f"{host}:{port}")
                    finally:
                        response.close()

    def test_reverse_listener_preserves_request_path_query(self):
        self.configure()
        self.assertEqual(self.engine.ready["reverse_port"], self.reverse_port)
        with httpx.Client(trust_env=False, timeout=10) as client:
            response = client.get(f"http://127.0.0.1:{self.reverse_port}/reverse-path?one=1&two=")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["path"], "/reverse-path?one=1&two=")

    def test_dns_override_preserves_host_sni_and_rejects_wrong_san(self):
        good = f"https://original.test:{self.tls_origin.server_port}/dns-good"
        bad = f"https://original.test:{self.wrong_san_origin.server_port}/dns-wrong-san"
        self.configure(rules=[{"kind": "dns_spoof", "match": "https://original.test:*/*", "value": "127.0.0.1"}])
        with self.client() as client:
            response = client.get(good)
            rejected = client.get(bad)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["host"], f"original.test:{self.tls_origin.server_port}")
        self.assertEqual(response.json()["sni"], "original.test")
        captured = self.engine.flow(good)
        self.assertEqual(captured["host"], "original.test")
        self.assertEqual(captured["url"], good)
        self.assertEqual(rejected.status_code, 502)
        self.assertIn("certificate", rejected.text.lower())
        self.assertFalse(any(item["path"] == "/dns-wrong-san" for item in self.wrong_san_origin.history))

    def test_shutdown_during_limit_closes_all_public_listeners(self):
        self.configure(download=32)
        with ThreadPoolExecutor(max_workers=1) as pool:
            started_reading = threading.Event()

            def interrupted_download():
                count = 0
                try:
                    with self.client() as client:
                        with client.stream("GET", self.http + "/download?size=1048576") as response:
                            for piece in response.iter_raw(chunk_size=8192):
                                count += len(piece)
                                started_reading.set()
                except httpx.TransportError:
                    return count
                return count

            future = pool.submit(interrupted_download)
            self.assertTrue(started_reading.wait(timeout=5))
            started = time.monotonic()
            try:
                self.engine.command("shutdown")
                self.engine.process.wait(timeout=3)
                self.assertLess(time.monotonic() - started, 3)
                self.assertLess(future.result(timeout=3), 1048576)
            except BaseException:
                # Preserve the failed shutdown assertion while bounding fixture cleanup.
                # This is the exact Popen child created by this test, never a PID lookup.
                if self.engine.process.poll() is None:
                    self.engine.process.kill()
                    self.engine.process.wait(timeout=3)
                raise
        for port in (self.engine.port, self.socks_port, self.reverse_port):
            with self.subTest(port=port), self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
