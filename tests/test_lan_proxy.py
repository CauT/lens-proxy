"""Actual Mac LAN-address proxy boundary. This does not simulate an iOS runtime.

Set LENS_TEST_LAN_ADDRESS to an IPv4 address assigned to the test Mac. Only that
address and temporary loopback origins are used. No host proxy/trust changes.
"""
import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from test_e2e import EngineHarness, certificate_fixture, start_fixture, ROOT


LAN_ADDRESS = os.environ.get("LENS_TEST_LAN_ADDRESS")


@unittest.skipUnless(LAN_ADDRESS, "Set LENS_TEST_LAN_ADDRESS to an assigned test-Mac IPv4 address")
class LANProxyAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="lens-lan-fixture-")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.ca, cert, key = certificate_fixture(Path(cls.fixture.name), "lan")
        _, rogue_cert, rogue_key = certificate_fixture(Path(cls.fixture.name), "rogue")
        cls.http, _ = start_fixture("LAN HTTP")
        cls.https, _ = start_fixture("LAN HTTPS", cert, key)
        cls.rogue, _ = start_fixture("Untrusted LAN origin", rogue_cert, rogue_key)
        for server in (cls.http, cls.https, cls.rogue):
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-lan-engine-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.engine = None

    def start(self):
        self.engine = EngineHarness(self.directory, self.ca,
            extra_args=["--lan-bind", LAN_ADDRESS])
        self.addCleanup(self.engine.close)
        self.assertEqual(self.engine.ready["lan_address"], LAN_ADDRESS)
        self.assertEqual(self.engine.ready["lan_proxy_port"], self.engine.port)
        return f"http://{LAN_ADDRESS}:{self.engine.port}"

    def test_http_https_binary_capture_and_strict_upstream_tls_over_lan_address(self):
        proxy = self.start()
        trust = ssl.create_default_context(cafile=self.engine.ready["ca_cert"])
        with httpx.Client(proxy=proxy, verify=trust, trust_env=False, timeout=8) as client:
            for scheme, server in (("http", self.http), ("https", self.https)):
                url = f"{scheme}://127.0.0.1:{server.server_port}/from-lan?source=device"
                response = client.post(url, content=b"\x00\xffLAN body", headers=[("X-Repeat", "one"), ("X-Repeat", "two")])
                self.assertEqual(response.status_code, 200)
                self.assertEqual(base64.b64decode(response.json()["body"]), b"\x00\xffLAN body")
                flow = self.engine.flow(url)
                _, detail = self.engine.command("detail", id=flow["id"])
                self.assertEqual(base64.b64decode(detail["request_body_base64"]), b"\x00\xffLAN body")
                self.assertEqual([v for k, v in detail["request_headers"] if k.lower() == "x-repeat"], ["one", "two"])

    def test_lan_https_rejects_untrusted_client_ca_and_untrusted_upstream(self):
        proxy = self.start()
        good = f"https://127.0.0.1:{self.https.server_port}/untrusted-lens-client"
        with httpx.Client(proxy=proxy, trust_env=False, timeout=5) as client:
            with self.assertRaises(httpx.ConnectError):
                client.get(good)
        trust = ssl.create_default_context(cafile=self.engine.ready["ca_cert"])
        bad = f"https://127.0.0.1:{self.rogue.server_port}/untrusted-upstream"
        with httpx.Client(proxy=proxy, verify=trust, trust_env=False, timeout=5) as client:
            response = client.get(bad)
        self.assertEqual(response.status_code, 502)
        failure = self.engine.flow(bad, state="error")
        self.assertIn("certificate", failure["error"].lower())

    def test_unregistered_lan_client_and_loopback_remain_usable_while_recording_paused(self):
        proxy = self.start()
        self.engine.command("configure", recording=False)
        for endpoint, suffix in ((proxy, "lan"), (self.engine.proxy, "loopback")):
            url = f"http://127.0.0.1:{self.http.server_port}/unregistered-{suffix}"
            with httpx.Client(proxy=endpoint, trust_env=False, timeout=5) as client:
                self.assertEqual(client.get(url).status_code, 200)
            with self.http.history_lock:
                self.assertTrue(any(item["path"] == f"/unregistered-{suffix}" for item in self.http.history))

    def test_direct_self_proxy_to_lan_listener_fails_without_recursive_forwarding(self):
        proxy = self.start()
        url = proxy + "/must-not-recurse"
        with httpx.Client(proxy=proxy, trust_env=False, timeout=5) as client:
            self.assertEqual(client.get(url).status_code, 502)
        failure = self.engine.flow(url, state="error")
        self.assertIn("own public listeners", failure["error"])
        _, status = self.engine.command("network_status")
        self.assertLessEqual(status["active_connections"], 1)

    def test_certificate_bootstrap_is_public_exact_and_ignores_traffic_rules(self):
        proxy = self.start()
        self.engine.configure([{"id": "rewrite", "kind": "rewrite_response_body", "match": "*", "name": "a", "value": "corrupt"},
                               {"id": "block", "kind": "block", "match": "*"}])
        with httpx.Client(proxy=proxy, trust_env=False, timeout=5) as client:
            response = client.get("http://lens.invalid/certificate.cer")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "application/x-x509-ca-cert")
            certificate = x509.load_der_x509_certificate(response.content)
            expected = x509.load_pem_x509_certificate(Path(self.engine.ready["ca_cert"]).read_bytes())
            self.assertEqual(response.content, expected.public_bytes(serialization.Encoding.DER))
            self.assertEqual(certificate.fingerprint(hashes.SHA256()).hex(), self.engine.ready["ca_sha256"])
            landing = client.get("http://lens.invalid/")
            self.assertEqual(landing.status_code, 200)
            self.assertEqual(landing.headers["cache-control"], "no-store")
            self.assertIn('id="lens-connected"', landing.text)
            self.assertIn('href="/certificate.cer"', landing.text)
            self.assertIn(self.engine.ready["ca_sha256"], landing.text)
            self.assertIn("Connected to Lens", landing.text)
            self.assertNotIn(b"PRIVATE KEY", landing.content)
            for path in ("/unknown", "/mitmproxy-ca.pem", "/../mitmproxy-ca.pem"):
                self.assertEqual(client.get("http://lens.invalid" + path).status_code, 404)
        self.assertNotIn(b"PRIVATE KEY", response.content)

    def test_lan_conflict_fails_startup_and_releases_already_bound_loopback(self):
        with socket.socket() as occupied:
            occupied.bind((LAN_ADDRESS, 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            result = subprocess.run([sys.executable, os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py")),
                "--data-dir", str(self.directory / "conflict"), "--proxy-port", str(port),
                "--lan-bind", LAN_ADDRESS],
                input="", capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(any(event["event"] == "fatal" for event in events), result.stderr)
        self.assertFalse(any(event["event"] == "ready" for event in events))
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=.3)

    def test_shutdown_releases_lan_and_loopback_with_an_incomplete_client_request(self):
        self.start()
        sock = socket.create_connection((LAN_ADDRESS, self.engine.port), timeout=3)
        self.addCleanup(sock.close)
        sock.sendall(b"GET http://example.invalid/ HTTP/1.1\r\n")
        self.engine.close()
        self.assertEqual(self.engine.process.returncode, 0)
        for address in (LAN_ADDRESS, "127.0.0.1"):
            with self.assertRaises(ConnectionRefusedError):
                socket.create_connection((address, self.engine.port), timeout=.3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
