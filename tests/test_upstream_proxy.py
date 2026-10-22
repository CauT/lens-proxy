"""Real independent HTTP upstream, strict HTTPS and CONNECT lifecycle checks."""
import base64
import errno
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import select
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit

import httpx

from test_e2e import EngineHarness, certificate_fixture, start_fixture
from test_connect_tunnel import Origin, exact, until_eof, PAYLOAD, REPLY

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
from upstream_proxy import HTTPUpstreamProxy, require_http_only


class UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle(self):
        with self.server.guard:
            self.server.active.add(self.connection)
        try:
            super().handle()
        finally:
            with self.server.guard:
                self.server.active.discard(self.connection)

    def do_CONNECT(self):
        self.server.records.append(("CONNECT", self.path))
        if self.server.behavior == "stall":
            self.connection.recv(1)
            return
        if self.server.behavior == "headers":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Oversized: " + b"a" * (70 * 1024))
            self.connection.recv(1)
            return
        target = urlsplit("//" + self.path)
        with socket.create_connection((target.hostname, target.port), timeout=5) as upstream:
            with self.server.guard:
                self.server.active.add(upstream)
            try:
                self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                readers = {self.connection: upstream, upstream: self.connection}
                while readers:
                    for source in select.select(list(readers), [], [], 5)[0]:
                        destination = readers[source]
                        data = source.recv(16384)
                        if data:
                            destination.sendall(data)
                        else:
                            try:
                                destination.shutdown(socket.SHUT_WR)
                            except OSError as exc:
                                if exc.errno != errno.ENOTCONN:
                                    raise
                            del readers[source]
            finally:
                with self.server.guard:
                    self.server.active.discard(upstream)

    def do_POST(self):
        target = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.records.append((self.command, self.path))
        upstream = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=5)
        try:
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            upstream.request(self.command, path, body, dict(self.headers))
            response = upstream.getresponse()
            content = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in ("connection", "transfer-encoding", "content-length"):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        finally:
            upstream.close()


class Upstream(ThreadingHTTPServer):
    def __init__(self, behavior="normal"):
        super().__init__(("127.0.0.1", 0), UpstreamHandler)
        self.behavior = behavior
        self.records, self.active, self.guard = [], set(), threading.Lock()
        self.failures, self.stopping = [], False
        self.worker = threading.Thread(target=self.serve_forever)
        self.worker.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def close(self):
        self.stopping = True
        self.shutdown()
        with self.guard:
            streams = list(self.active)
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        self.server_close()
        self.worker.join(3)
        if self.worker.is_alive():
            raise AssertionError("Owned upstream fixture did not exit")
        if self.failures:
            raise AssertionError(f"Owned upstream fixture failed: {self.failures!r}")

    def handle_error(self, request, client_address):
        if not self.stopping:
            self.failures.append(repr(sys.exception()))


class HTTPUpstreamAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-upstream-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ca, self.cert, self.key = certificate_fixture(self.root, "upstream")

    def proxy(self, behavior="normal"):
        upstream = Upstream(behavior)
        self.addCleanup(upstream.close)
        return upstream

    def engine(self, endpoint, configuration=None):
        directory = self.root / ("engine-" + str(time.monotonic_ns()))
        directory.mkdir()
        engine = EngineHarness(directory, self.ca,
            extra_args=("--http-upstream-proxy", endpoint,
                        *(("--initialize-from-stdin",) if configuration is not None else ())),
            initial_configuration=configuration)
        def close():
            engine.close()
            if os.environ.get("LENS_UPSTREAM_EVIDENCE"):
                evidence = Path(os.environ["LENS_UPSTREAM_EVIDENCE"])
                evidence.mkdir(parents=True, exist_ok=True)
                (evidence / (self._testMethodName + "-" + directory.name + ".log")).write_text((directory / "engine-stderr.log").read_text())
        self.addCleanup(close)
        return engine

    def origin(self, tls=False):
        server, thread = start_fixture("upstream-origin", self.cert if tls else None, self.key if tls else None)
        def close():
            server.shutdown(); server.server_close(); thread.join(3)
            self.assertFalse(thread.is_alive())
        self.addCleanup(close)
        return server

    def test_http_https_and_details_use_actual_upstream(self):
        upstream = self.proxy()
        engine = self.engine(upstream.url)
        self.assertEqual(engine.ready["http_upstream_proxy"], upstream.url)
        context = ssl.create_default_context(cafile=engine.ready["ca_cert"])
        with httpx.Client(proxy=engine.proxy, verify=context, trust_env=False, timeout=8) as client:
            for tls in (False, True):
                server = self.origin(tls)
                url = f"{'https' if tls else 'http'}://localhost:{server.server_port}/upstream-proof"
                payload = bytes(range(256)) + b"upstream exact bytes\x00\xff"
                response = client.post(url, content=payload)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(base64.b64decode(response.json()["body"]), payload)
                flow = engine.flow(url)
                detail = engine.command("detail", id=flow["id"])[1]
                self.assertEqual(base64.b64decode(detail["request_body_base64"]), payload)
                self.assertEqual(base64.b64decode(detail["response_body_base64"]), response.content)
                self.assertIn(("CONNECT", f"localhost:{server.server_port}") if tls else ("POST", url), upstream.records)
        engine.command("stop_capture")

    def test_unavailable_upstream_never_falls_back_to_origin(self):
        server = self.origin()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            endpoint = f"http://127.0.0.1:{reservation.getsockname()[1]}"
        engine = self.engine(endpoint)
        url = f"http://127.0.0.1:{server.server_port}/must-not-arrive"
        with httpx.Client(proxy=engine.proxy, trust_env=False, timeout=5) as client:
            response = client.post(url, content=b"do not bypass")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(server.history, [])
        flow = engine.flow(url, state="error")
        self.assertIn("connect", flow["error"].lower())
        engine.command("detail", id=flow["id"])

    def test_dns_override_keeps_original_tls_identity_through_upstream(self):
        from test_network_features import certificates
        self.ca, leaves = certificates(self.root)
        cert, key = leaves[0]
        server, thread = start_fixture("dns-upstream", cert, key)
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(3)))
        observed = []
        server.socket.context.set_servername_callback(lambda connection, name, context: observed.append(name))
        upstream = self.proxy()
        engine = self.engine(upstream.url, {"rules": [{"kind": "dns_spoof", "match": "*://original.test:*/*", "value": "127.0.0.1"}]})
        context = ssl.create_default_context(cafile=engine.ready["ca_cert"])
        with httpx.Client(proxy=engine.proxy, verify=context, trust_env=False, timeout=5) as client:
            for secure, origin in ((False, self.origin()), (True, server)):
                url = f"{'https' if secure else 'http'}://original.test:{origin.server_port}/dns-through-upstream"
                response = client.post(url, content=b"original TLS identity")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["path"], "/dns-through-upstream")
                self.assertIn(("CONNECT", f"127.0.0.1:{origin.server_port}"), upstream.records)
                self.assertEqual(engine.flow(url)["host"], "original.test")
        self.assertEqual(observed, ["original.test"])

    def test_connect_negotiation_deadline_and_header_budget(self):
        for behavior in ("stall", "headers"):
            with self.subTest(behavior=behavior):
                upstream = self.proxy(behavior)
                engine = self.engine(upstream.url, {"network": {"connect_timeout_seconds": 1}})
                server = self.origin(True)
                context = ssl.create_default_context(cafile=engine.ready["ca_cert"])
                start = time.monotonic()
                with httpx.Client(proxy=engine.proxy, verify=context, trust_env=False, timeout=5) as client:
                    try:
                        response = client.post(f"https://localhost:{server.server_port}/must-not-arrive", content=b"blocked")
                        self.assertEqual(response.status_code, 502)
                    except httpx.TransportError:
                        pass
                self.assertLess(time.monotonic() - start, 4)
                self.assertEqual(server.history, [])
                engine.command("stop_capture")

    def test_excluded_connect_keeps_both_half_closes_through_upstream(self):
        def exchange(peer, origin):
            peer.sendall(b"server-first")
            origin.received = until_eof(peer)
            peer.sendall(REPLY)
            peer.shutdown(socket.SHUT_WR)
        origin = Origin(exchange)
        self.addCleanup(origin.close)
        upstream = self.proxy()
        engine = self.engine(upstream.url, {"ssl_hosts": ""})
        with socket.create_connection(("127.0.0.1", engine.port), timeout=5) as client:
            client.sendall(f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode())
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(exact(client, 1))
            self.assertIn(b" 200 ", header)
            self.assertEqual(exact(client, len(b"server-first")), b"server-first")
            client.sendall(PAYLOAD)
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(until_eof(client), REPLY)
        origin.worker.join(3)
        self.assertEqual(origin.received, PAYLOAD)
        self.assertIn(("CONNECT", f"127.0.0.1:{origin.port}"), upstream.records)
        engine.command("stop_capture")

    def test_proxy_configuration_and_unsupported_modes_fail_closed(self):
        self.assertEqual(HTTPUpstreamProxy.parse("http://[::1]:7897").url, "http://[::1]:7897")
        for value in (False, {}, "http://user:secret@localhost:7897", "http://localhost", "https://localhost:443",
                      "http://localhost:7897/path", "http://localhost:7897?", "http://localhost:7897#", "http://a..b:80", " http://localhost:7897"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                HTTPUpstreamProxy.parse(value)
        proxy = HTTPUpstreamProxy.parse("http://localhost:7897")
        for options in ({"socks": 1080}, {"reverse": 8080}, {"tcp": [object()]}, {"udp": [object()]}):
            with self.assertRaisesRegex(ValueError, "HTTP/HTTPS listener only"):
                require_http_only(proxy, **options)


if __name__ == "__main__":
    unittest.main(verbosity=2)
