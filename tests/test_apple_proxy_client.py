"""Actual Apple URLSession/Network client -> Lens -> owned HTTP/TLS origins.

This lane runs the macOS entry point; it never labels that process as iOS.
scripts/test-apple-proxy.sh compiles the probe before discovering this file.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from test_e2e import EngineHarness, ROOT, start_fixture
from test_network_features import certificates


PROBE = Path(os.environ.get("LENS_APPLE_PROXY_PROBE", str(ROOT / ".build/apple-proxy-client")))
LAN = os.environ.get("LENS_TEST_LAN_ADDRESS")
PAYLOAD = bytes(range(256)) * 16 + b"\x00\xffApple Foundation"


@unittest.skipUnless(PROBE.is_file(), "Build the native probe with scripts/test-apple-proxy.sh")
class AppleProxyAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="lens-apple-origins-")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.ca, leaves = certificates(Path(cls.fixture.name))
        cls.http, _ = start_fixture("Apple HTTP")
        cls.https, _ = start_fixture("Apple HTTPS", *leaves[0])
        cls.wrong_san, _ = start_fixture("Apple wrong SAN", *leaves[1])
        for server in (cls.http, cls.https, cls.wrong_san):
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-apple-probe-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        extra = ["--lan-bind", LAN] if LAN else []
        self.engine = EngineHarness(self.directory, self.ca, extra_args=extra)
        self.addCleanup(self.engine.close)
        self.engine.configure([{"id": "fixture-route", "kind": "dns_spoof", "match": "*", "value": "127.0.0.1"}])
        self.anchor = x509.load_pem_x509_certificate(Path(self.engine.ready["ca_cert"]).read_bytes()).public_bytes(Encoding.DER)

    def url(self, server, tag, tls=False):
        return f"{'https' if tls else 'http'}://original.test:{server.server_port}/apple-{tag}-{uuid.uuid4().hex}"

    def probe(self, url, anchor=None, proxy_host=None, payload=PAYLOAD, method="POST"):
        value = {"proxyHost": proxy_host or LAN or "127.0.0.1", "proxyPort": self.engine.port,
                 "url": url, "method": method, "bodyBase64": base64.b64encode(payload).decode(),
                 "headers": {"X-Lens-Apple-Probe": uuid.uuid4().hex, "Content-Type": "application/octet-stream"},
                 "anchorDERBase64": base64.b64encode(anchor).decode() if anchor else None}
        path = self.directory / (uuid.uuid4().hex + ".json")
        path.write_text(json.dumps(value))
        result = subprocess.run([str(PROBE), str(path)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        observation = json.loads(result.stdout)
        self.assertEqual(observation["platform"], "macOS", "This lane must not impersonate an iOS process")
        self.assertFalse(observation["proxyFailover"], "A failed proxy cannot silently become a direct request")
        return observation

    def assert_echo_and_capture(self, result, url, payload=PAYLOAD):
        self.assertEqual(result.get("status"), 200, result)
        self.assertNotIn("errorCode", result, result)
        origin = json.loads(base64.b64decode(result["bodyBase64"]))
        self.assertEqual(base64.b64decode(origin["body"]), payload)
        self.assertEqual(origin["path"], "/" + url.split("/", 3)[3])
        flow = self.engine.flow(url)
        _, detail = self.engine.command("detail", id=flow["id"])
        self.assertEqual(base64.b64decode(detail["request_body_base64"]), payload)
        self.assertEqual(json.loads(detail["response_body"]), origin)
        self.assertEqual([value for name, value in detail["response_headers"] if name.lower() == "set-cookie"],
                         ["first=1", "second=2"])
        return flow

    def test_http_connect_proxy_delivers_exact_binary_and_retains_response_duplicates(self):
        url = self.url(self.http, "http")
        result = self.probe(url)
        self.assert_echo_and_capture(result, url)

    def test_public_ca_bootstrap_through_apple_http_connect_proxy(self):
        result = self.probe("http://lens.invalid/certificate.cer", payload=b"", method="GET")
        self.assertEqual(result.get("status"), 200, result)
        self.assertEqual(base64.b64decode(result["bodyBase64"]), self.anchor)
        self.engine.flow("http://lens.invalid/certificate.cer")
        landing = self.probe("http://lens.invalid/", payload=b"", method="GET")
        self.assertEqual(landing.get("status"), 200, landing)
        page = base64.b64decode(landing["bodyBase64"]).decode()
        self.assertIn('id="lens-connected"', page)
        self.assertIn(self.engine.ready["ca_sha256"], page)

    def test_https_without_test_anchor_is_rejected_by_system_trust(self):
        url = self.url(self.https, "untrusted", tls=True)
        result = self.probe(url)
        self.assertNotIn("status", result, result)
        self.assertEqual(result.get("errorDomain"), "NSURLErrorDomain", result)
        self.assertIn(result.get("errorCode"), (-1200, -1202), result)
        self.assertEqual(result["trustMode"], "system-default")
        with self.https.history_lock:
            self.assertFalse(any(item["path"] in url for item in self.https.history))

    def test_https_with_session_only_anchor_preserves_hostname_and_har_bytes(self):
        url = self.url(self.https, "trusted", tls=True)
        result = self.probe(url, anchor=self.anchor)
        self.assert_echo_and_capture(result, url)
        self.assertGreaterEqual(result["acceptedChallenges"], 1)
        self.assertEqual(result["rejectedChallenges"], 0)
        self.assertEqual(len(result["leafSHA256"]), 64)
        path = self.directory / "apple-capture.har"
        self.engine.command("save_har", path=str(path))
        entry = next(entry for entry in json.loads(path.read_text())["log"]["entries"] if entry["request"]["url"] == url)
        self.assertEqual(base64.b64decode(entry["_lensRawRequestBody"]), PAYLOAD)
        self.assertEqual(entry["_lensOriginalUrl"], url)
        self.assertEqual(entry["_lensDnsAddress"], "127.0.0.1")

    def test_unrelated_session_anchor_is_not_blanket_certificate_acceptance(self):
        unrelated = x509.load_pem_x509_certificate(Path(self.ca).read_bytes()).public_bytes(Encoding.DER)
        url = self.url(self.https, "wrong-anchor", tls=True)
        result = self.probe(url, anchor=unrelated)
        self.assertNotIn("status", result, result)
        self.assertGreaterEqual(result["rejectedChallenges"], 1)
        self.assertEqual(result["acceptedChallenges"], 0)
        self.assertNotEqual(result.get("errorCode"), -1001, "A timeout is not proof of trust rejection")

    def test_lens_still_rejects_origin_hostname_mismatch(self):
        url = self.url(self.wrong_san, "origin-wrong-san", tls=True)
        result = self.probe(url, anchor=self.anchor)
        self.assertEqual(result.get("status"), 502, result)
        failure = self.engine.flow(url, state="error")
        self.assertIn("certificate", failure["error"].lower())

    def test_stop_interrupts_apple_request_waiting_at_breakpoint(self):
        url = self.url(self.http, "stop")
        self.engine.configure([{"id": "paused", "kind": "breakpoint_request", "match": url, "timeout_seconds": 30}])
        with ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(self.probe, url)
            self.engine.flow(url, state="paused")
            self.engine.close()
            observed = result.result(timeout=10)
        self.assertNotIn("status", observed, observed)
        self.assertEqual(observed.get("errorDomain"), "NSURLErrorDomain", observed)
        self.assertNotEqual(observed.get("errorCode"), -1001, "A timeout is not successful Stop delivery")

    def test_stopped_proxy_cannot_fall_back_to_direct_origin(self):
        self.engine.command("stop_capture")
        url = self.url(self.http, "stopped")
        result = self.probe(url)
        self.assertNotIn("status", result, result)
        self.assertNotEqual(result.get("errorCode"), -1001, result)
        with self.http.history_lock:
            self.assertFalse(any(item["path"] in url for item in self.http.history))


if __name__ == "__main__":
    unittest.main(verbosity=2)
