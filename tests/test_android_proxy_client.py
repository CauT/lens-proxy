"""Real Android Activity -> assigned Mac LAN proxy -> owned HTTP/TLS origins.

Requires an explicitly selected, already provisioned test emulator. The runner
installs the test-only APK; no macOS proxy or trust setting is changed.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shlex
import subprocess
import ssl
import socket
import tempfile
import threading
import time
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from test_e2e import EngineHarness, start_fixture
from test_network_features import certificates
from test_client_certificates import client_identity, MutualTLSHandler, MutualTLSServer
from test_udp_forwarding import UDPOrigin, udp_port


ADB = os.environ.get("LENS_ANDROID_ADB")
SERIAL = os.environ.get("LENS_ANDROID_SERIAL")
ADB_PORT = os.environ.get("LENS_ANDROID_ADB_PORT", "5038")
LAN = os.environ.get("LENS_TEST_LAN_ADDRESS")
EVIDENCE = Path(os.environ["LENS_ANDROID_EVIDENCE_DIR"]) if os.environ.get("LENS_ANDROID_EVIDENCE_DIR") else None
PACKAGE = "io.lens.proxyprobe"
PAYLOAD = bytes(range(256)) * 16 + b"\x00\xffAndroid framework"


def adb(*arguments, check=True):
    if arguments and arguments[0] == "shell":
        arguments = ("shell", shlex.join(arguments[1:]))
    return subprocess.run([ADB, "-P", ADB_PORT, "-s", SERIAL, *arguments],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=check)


PROXY_KEYS = ("http_proxy", "global_http_proxy_host", "global_http_proxy_port",
              "global_http_proxy_exclusion_list", "global_proxy_pac_url")


def proxy_settings():
    values = dict(line.split("=", 1) for line in
                  adb("shell", "settings", "list", "global").stdout.splitlines() if "=" in line)
    return {key: values.get(key) for key in PROXY_KEYS}


def apply_system_proxy(endpoint):
    # Deleting the deprecated key does not clear ProxyTracker's in-memory proxy.
    # An empty host with port zero does, and also updates the canonical keys.
    host, port = endpoint.rsplit(":", 1)
    adb("shell", "settings", "put", "global", "http_proxy", endpoint)
    deadline = time.monotonic() + 5
    while True:
        state = proxy_settings()
        if state["global_http_proxy_host"] == host and state["global_http_proxy_port"] == port:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Android proxy did not apply: {state!r}")
        time.sleep(.1)


@contextmanager
def system_proxy(endpoint):
    """Restore raw settings and the effective direct proxy, including on failure."""
    if adb("shell", "getprop", "ro.boot.qemu.avd_name").stdout.strip() != "LensProxyAcceptance_20261017":
        raise AssertionError("Refusing proxy changes on a non-owned Android guest")
    previous = proxy_settings()
    if previous["global_http_proxy_exclusion_list"] or previous["global_proxy_pac_url"]:
        raise AssertionError("This test helper cannot restore an existing PAC or exclusion policy")
    old_host = previous["global_http_proxy_host"] or ""
    old_port = previous["global_http_proxy_port"] if old_host else "0"
    if old_host and (not old_port or not old_port.isdecimal() or not 1 <= int(old_port) <= 65535):
        raise AssertionError(f"Unresolved previous Android proxy: {previous!r}")
    if previous["http_proxy"] and previous["http_proxy"] != f"{old_host}:{old_port}":
        raise AssertionError(f"Conflicting legacy Android proxy: {previous!r}")
    try:
        apply_system_proxy(endpoint)
        yield
    finally:
        apply_system_proxy(f"{old_host}:{old_port}")
        # Keep absence distinct from empty strings. Restore the legacy key last,
        # after ProxyTracker has applied the previous effective endpoint.
        for key in (*PROXY_KEYS[1:], PROXY_KEYS[0]):
            value = previous[key]
            if value is None:
                adb("shell", "settings", "delete", "global", key)
            else:
                adb("shell", "settings", "put", "global", key, value)
        restored = proxy_settings()
        if restored != previous:
            raise AssertionError(f"Android system proxy restoration failed: {restored!r} != {previous!r}")


@unittest.skipUnless(ADB and SERIAL and LAN, "Select LENS_ANDROID_ADB/SERIAL and LENS_TEST_LAN_ADDRESS")
class AndroidProxyAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only the explicitly owned emulator is eligible for settings changes.
        name = adb("shell", "getprop", "ro.boot.qemu.avd_name").stdout.strip()
        if name != "LensProxyAcceptance_20261017":
            raise AssertionError(f"Refusing non-owned emulator: {name!r}")
        cls.sdk = int(adb("shell", "getprop", "ro.build.version.sdk").stdout.strip())
        if EVIDENCE:
            EVIDENCE.mkdir(parents=True, exist_ok=True)
        cls.fixture = tempfile.TemporaryDirectory(prefix="lens-android-origins-")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.ca, leaves = certificates(Path(cls.fixture.name))
        cls.server_identity = leaves[0]
        cls.http, _ = start_fixture("Android HTTP")
        cls.https, _ = start_fixture("Android HTTPS", *leaves[0])
        cls.wrong_san, _ = start_fixture("Android wrong SAN", *leaves[1])
        for server in (cls.http, cls.https, cls.wrong_san):
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-android-probe-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.engine = EngineHarness(self.directory, self.ca,
            extra_args=["--lan-bind", LAN])
        self.addCleanup(self.engine.close)
        self.engine.configure([{"id": "fixture-route", "kind": "dns_spoof", "match": "*", "value": "127.0.0.1"}])
        self.anchor = x509.load_pem_x509_certificate(Path(self.engine.ready["ca_cert"]).read_bytes()).public_bytes(Encoding.DER)

    def url(self, server, tag, tls=False):
        # This name cannot resolve directly on the emulator. Only Lens routes it
        # to the owned origin, so a plausible fallback result cannot pass.
        return f"{'https' if tls else 'http'}://original.test:{server.server_port}/android-{tag}-{uuid.uuid4().hex}"

    def probe(self, url, anchor=None, method="POST", payload=PAYLOAD, proxy_mode="explicit", proxy_host=None, proxy_port=None, datagrams=None, transport="http"):
        token = uuid.uuid4().hex
        value = {"token": token, "url": url, "proxyHost": LAN if proxy_host is None else proxy_host,
                 "proxyPort": self.engine.port if proxy_port is None else proxy_port,
                 "method": method, "bodyBase64": base64.b64encode(payload).decode(), "proxyMode": proxy_mode,
                 "transport": transport}
        if anchor is not None:
            value["anchorDERBase64"] = base64.b64encode(anchor).decode()
        if datagrams is not None:
            value.update(transport="udp", datagramsBase64=[base64.b64encode(data).decode() for data in datagrams])
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        launch = adb("shell", "am", "start", "-S", "-W", "-n", PACKAGE + "/.MainActivity", "--es", "config", encoded)
        self.assertNotIn("Error:", launch.stdout + launch.stderr)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            read = adb("shell", "run-as", PACKAGE, "cat", "files/result-" + token + ".json", check=False)
            try:
                result = json.loads(read.stdout) if read.returncode == 0 else None
            except json.JSONDecodeError:
                result = None  # The writer may still be finishing this unique file.
            if result is not None:
                self.assertEqual(result["token"], token)
                self.assertEqual(result["platform"], "Android")
                self.assertEqual(result["sdk"], self.sdk)
                self.assertEqual(result["url"], url)
                if EVIDENCE:
                    (EVIDENCE / (self._testMethodName + "-" + token + ".json")).write_text(json.dumps(result, indent=2))
                adb("shell", "run-as", PACKAGE, "rm", "files/result-" + token + ".json")
                return result
            time.sleep(.1)
        self.fail(f"Android result missing; launch={launch.stdout[-1000:]}; read={read.stderr[-1000:]}")

    def test_system_proxy_restores_effective_selector_after_failure_and_nesting(self):
        def selector():
            return self.probe("http://proxy-state.invalid/", method="GET", payload=b"",
                              transport="proxy-state")["selectedProxies"]

        previous, before = proxy_settings(), selector()
        endpoint = f"{LAN}:{self.engine.port}"
        observations = {"before": before, "before_settings": previous}
        with self.assertRaisesRegex(RuntimeError, "controlled proxy-context failure"):
            with system_proxy(endpoint):
                observations["during"] = selector()
                self.assertIn(endpoint, observations["during"].replace("/<unresolved>", ""))
                with system_proxy("127.0.0.1:1"):
                    self.assertIn("127.0.0.1", selector())
                self.assertEqual(selector(), observations["during"])
                raise RuntimeError("controlled proxy-context failure")
        observations.update(after=selector(), after_settings=proxy_settings())
        self.assertEqual(observations["after"], before)
        self.assertEqual(observations["after_settings"], previous)
        if EVIDENCE:
            (EVIDENCE / "android-proxy-restoration.json").write_text(json.dumps(observations, indent=2))

    def assert_echo_and_capture(self, result, url, server=None, after=0):
        self.assertEqual(result.get("status"), 200, result)
        self.assertNotIn("errorClass", result, result)
        origin = json.loads(base64.b64decode(result["bodyBase64"]))
        path = "/" + url.split("/", 3)[3]
        self.assertEqual(origin["path"], path)
        self.assertEqual(base64.b64decode(origin["body"]), PAYLOAD)
        self.assertIn(["X-Lens-Android-Probe", result["token"]], origin["headers"])
        server = server or (self.https if url.startswith("https:") else self.http)
        with server.history_lock:
            matching = [item for item in server.history if item["path"] == path]
        self.assertEqual(len(matching), 1)
        # The fixture's Python header tuples become JSON arrays on the wire.
        self.assertEqual(json.loads(json.dumps(matching[0])), origin)
        flow = self.engine.flow(url, after=after)
        _, detail = self.engine.command("detail", id=flow["id"])
        self.assertEqual(base64.b64decode(detail["request_body_base64"]), PAYLOAD)
        self.assertEqual(json.loads(detail["response_body"]), origin)
        self.assertEqual([v for k, v in detail["response_headers"] if k.lower() == "set-cookie"], ["first=1", "second=2"])
        source = detail["client_connection"]
        self.assertEqual(source, flow["client_connection"])
        self.assertEqual(source["listener"], "lan_proxy_port")
        self.assertEqual(source["listener_address"], [LAN, self.engine.port])
        self.assertEqual(source["peer"][0], LAN)  # actual allowed host-side NAT source, not an Android PID/device identity
        self.assertTrue(1 <= source["peer"][1] <= 65535)
        if EVIDENCE:
            (EVIDENCE / (self._testMethodName + "-capture.json")).write_text(json.dumps(
                {"android": result, "origin": matching[0], "lens": detail}, indent=2))
        return flow

    def assert_no_origin(self, url, server):
        path = "/" + url.split("/", 3)[3]
        with server.history_lock:
            self.assertFalse(any(item["path"] == path for item in server.history))

    def test_android_access_lists_live_conflict_then_allow_with_tls_and_har(self):
        url = self.url(self.https, "access-list", tls=True)
        route = [{"kind": "dns_spoof", "match": "*", "value": "127.0.0.1"}]
        policy = {"allow_enabled": True, "allow": [url], "block_enabled": True, "block": [url]}
        self.engine.command("configure", access_policy=policy, rules=route, ssl_hosts="*")
        denied = self.probe(url, self.anchor)
        self.assertEqual(denied.get("status"), 403, denied)
        self.assertNotIn("errorClass", denied, denied)
        self.assert_no_origin(url, self.https)
        flow = self.engine.flow(url)
        fact = flow["access_decision"]
        self.assertEqual((fact["reason"], fact["matched_url"], fact["pattern"]), ("block_match", url, url))
        policy["block_enabled"] = False
        self.engine.command("configure", access_policy=policy, rules=route, ssl_hosts="*")
        after = len(self.engine.events)
        self.assert_echo_and_capture(self.probe(url, self.anchor), url, after=after)
        self.engine.command("stop_capture")
        self.assertEqual(self.engine.command("detail", id=flow["id"])[1]["access_decision"], fact)
        har = self.engine.command("export_har")[1]
        entries = har["log"]["entries"]
        self.assertEqual([entry.get("_lensAccessDecision") for entry in entries], [fact, None])
        if EVIDENCE:
            (EVIDENCE / "android-access-lists.json").write_text(json.dumps({"denied_android": denied, "har": har}, indent=2))

    def test_http_binary_and_repeated_headers(self):
        url = self.url(self.http, "http")
        self.assert_echo_and_capture(self.probe(url), url)

    def test_public_ca_bootstrap_is_exact(self):
        url = "http://lens.invalid/certificate.cer"
        result = self.probe(url, method="GET", payload=b"")
        self.assertEqual(result.get("status"), 200, result)
        self.assertNotIn("errorClass", result, result)
        self.assertEqual(base64.b64decode(result["bodyBase64"]), self.anchor)
        self.engine.flow(url)

        landing = self.probe("http://lens.invalid/", method="GET", payload=b"")
        self.assertEqual(landing.get("status"), 200, landing)
        page = base64.b64decode(landing["bodyBase64"]).decode()
        self.assertIn('id="lens-connected"', page)
        self.assertIn(self.engine.ready["ca_sha256"], page)

    def test_default_android_trust_rejects_lens_ca(self):
        url = self.url(self.https, "untrusted", tls=True)
        result = self.probe(url)
        self.assertNotIn("status", result, result)
        self.assertEqual(result.get("errorClass"), "javax.net.ssl.SSLHandshakeException", result)
        self.assertIn("CertPathValidatorException", result["causes"], result)
        self.assert_no_origin(url, self.https)

    def test_unrelated_anchor_rejects_lens_ca(self):
        url = self.url(self.https, "wrong-anchor", tls=True)
        unrelated = x509.load_pem_x509_certificate(Path(self.ca).read_bytes()).public_bytes(Encoding.DER)
        result = self.probe(url, anchor=unrelated)
        self.assertNotIn("status", result, result)
        self.assertEqual(result.get("errorClass"), "javax.net.ssl.SSLHandshakeException", result)
        self.assertIn("CertPathValidatorException", result["causes"], result)
        self.assert_no_origin(url, self.https)

    def test_https_session_ca_and_har_preserve_exact_binary(self):
        url = self.url(self.https, "trusted", tls=True)
        result = self.probe(url, anchor=self.anchor)
        self.assert_echo_and_capture(result, url)
        self.assertEqual(len(result["leafSHA256"]), 64)
        path = self.directory / "android.har"
        self.engine.command("save_har", path=str(path))
        entry = next(e for e in json.loads(path.read_text())["log"]["entries"] if e["request"]["url"] == url)
        self.assertEqual(base64.b64decode(entry["_lensRawRequestBody"]), PAYLOAD)
        self.assertEqual(entry["_lensOriginalUrl"], url)
        self.assertEqual(entry["_lensDnsAddress"], "127.0.0.1")
        if EVIDENCE:
            (EVIDENCE / "android-https.har").write_bytes(path.read_bytes())

    def test_android_https_uses_scoped_upstream_client_identity(self):
        self.engine.close()
        root, p12, _, password, fingerprint, _ = client_identity(self.directory)
        server = MutualTLSServer(("127.0.0.1", 0), MutualTLSHandler)
        server.history, server.history_lock, server.fixture_name = [], threading.Lock(), "Android mutual TLS"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*self.server_identity)
        context.load_verify_locations(root)
        context.verify_mode = ssl.CERT_REQUIRED
        server.tls_context = context
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        directory = self.directory / "mutual-tls-engine"
        directory.mkdir()
        self.engine = EngineHarness(directory, self.ca,
            extra_args=["--lan-bind", LAN, "--initialize-from-stdin"],
            initial_configuration={"client_certificates": [{"host": "original.test", "port": server.server_port,
                "path": str(p12), "password": password}],
                "rules": [{"kind": "dns_spoof", "match": "*", "value": "127.0.0.1"}]})
        self.addCleanup(self.engine.close)
        self.anchor = x509.load_pem_x509_certificate(Path(self.engine.ready["ca_cert"]).read_bytes()).public_bytes(Encoding.DER)
        url = self.url(server, "mutual-tls", tls=True)
        result = self.probe(url, anchor=self.anchor)
        self.assert_echo_and_capture(result, url, server=server)
        observed = {name.lower(): values for name, values in result["responseHeaders"].items()}
        self.assertEqual(observed["x-client-sha256"], [fingerprint])
        self.assertEqual(self.engine.ready["client_certificates"][0]["sha256"], fingerprint)
        if EVIDENCE:
            (EVIDENCE / "android-mutual-tls-identity.json").write_text(json.dumps({
                "expected_client_sha256": fingerprint, "android": result,
                "selected_host": "original.test", "selected_port": server.server_port}, indent=2))

    def test_android_http_bytes_cross_raw_tcp_forward_without_fabricated_har(self):
        self.engine.close()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        directory = self.directory / "tcp-engine"
        directory.mkdir()
        self.engine = EngineHarness(directory, self.ca, extra_args=["--initialize-from-stdin"],
            initial_configuration={"tcp_forwards": [{"listen_port": port,
                "target_host": "127.0.0.1", "target_port": self.http.server_port}]})
        self.addCleanup(self.engine.close)
        url = self.url(self.http, "raw-tcp")
        # Android Emulator's 10.0.2.2 aliases the host loopback. This exercises
        # the loopback-only raw forward, separately from the LAN HTTP proxy.
        result = self.probe(url, proxy_host="10.0.2.2", proxy_port=port)
        self.assertEqual(result.get("status"), 200, result)
        response = base64.b64decode(result["bodyBase64"])
        origin = json.loads(response)
        self.assertEqual(origin["path"], url)
        self.assertEqual(base64.b64decode(origin["body"]), PAYLOAD)
        self.assertIn(["X-Lens-Android-Probe", result["token"]], origin["headers"])
        with self.http.history_lock:
            matches = [item for item in self.http.history if item["path"] == url]
        self.assertEqual(len(matches), 1)
        self.assertEqual(base64.b64decode(matches[0]["body"]), PAYLOAD)
        self.engine.command("stop_capture")  # Android may retain an HTTP keepalive socket.
        _, status = self.engine.command("tcp_status")
        self.assertEqual(len(status["streams"]), 1)
        summary = status["streams"][0]
        sent, received, offset = bytearray(), bytearray(), 0
        while True:
            _, page = self.engine.command("tcp_detail", id=summary["id"], offset=offset)
            for chunk in page["chunks"]:
                (sent if chunk["direction"] == "send" else received).extend(base64.b64decode(chunk["base64"], validate=True))
            offset += len(page["chunks"])
            if offset >= page["total"]:
                break
        head, body = bytes(sent).split(b"\r\n\r\n", 1)
        self.assertEqual(head.split(b"\r\n")[0], f"POST {url} HTTP/1.1".encode())
        self.assertEqual(body, PAYLOAD)
        self.assertEqual(bytes(received).split(b"\r\n\r\n", 1)[1], response)
        self.assertFalse(summary["truncated"])
        self.assertEqual(self.engine.command("export_har")[1]["log"]["entries"], [])
        if EVIDENCE:
            self.engine.command("save_tcp", path=str(EVIDENCE / "android-raw-tcp.lens-tcp.json"))

    def test_lens_rejects_wrong_origin_hostname(self):
        url = self.url(self.wrong_san, "origin-san", tls=True)
        result = self.probe(url, anchor=self.anchor)
        self.assertEqual(result.get("status"), 502, result)
        self.assertNotIn("errorClass", result, result)
        failure = self.engine.flow(url, state="error")
        self.assertIn("certificate", failure["error"].lower())
        self.assert_no_origin(url, self.wrong_san)

    def test_android_udp_preserves_empty_binary_boundaries_and_stopped_session(self):
        self.engine.close()
        origin, port = UDPOrigin(), udp_port()
        self.addCleanup(origin.server_close); self.addCleanup(origin.shutdown)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        directory = self.directory / "udp-engine"; directory.mkdir()
        self.engine = EngineHarness(directory, self.ca, extra_args=["--initialize-from-stdin"],
            initial_configuration={"udp_forwards": [{"listen_port": port, "target_host": "127.0.0.1", "target_port": origin.server_address[1]}]})
        self.addCleanup(self.engine.close)
        payloads = [b"", PAYLOAD, b"last\x00datagram\xff"]
        result = self.probe(f"udp://10.0.2.2:{port}", proxy_host="10.0.2.2", proxy_port=port, datagrams=payloads)
        if EVIDENCE:
            with origin.lock:
                observed = [{"base64": base64.b64encode(data).decode(), "peer": peer} for data, peer in origin.history]
            (EVIDENCE / "android-udp-boundaries.json").write_text(json.dumps({"android": result, "origin": observed,
                "lens": self.engine.command("udp_status")[1]}, indent=2))
        self.assertEqual(result.get("transport"), "udp", result)
        self.assertNotIn("errorClass", result, result)
        self.assertEqual([base64.b64decode(data) for data in result["datagramsBase64"]], [data[::-1] for data in payloads])
        with origin.lock: self.assertEqual([data for data, _peer in origin.history], payloads)
        self.engine.command("stop_capture")
        rows = self.engine.command("udp_status")[1]["associations"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["sent_datagrams"], row["received_datagrams"], row["observed_datagrams"]), (3, 3, 6))
        self.assertEqual(row["listener_address"], ["127.0.0.1", port])
        self.assertEqual(row["state"], "cancelled")
        self.assertFalse(row["truncated"])
        self.assertEqual(row["dropped_client_datagrams"] + row["dropped_upstream_datagrams"], 0)
        page = self.engine.command("udp_detail", id=row["id"])[1]
        for direction in ("send", "receive"):
            data = [base64.b64decode(value["base64"]) for value in page["datagrams"] if value["direction"] == direction]
            self.assertEqual(data, payloads if direction == "send" else [data[::-1] for data in payloads])
        self.assertEqual(self.engine.command("export_har")[1]["log"]["entries"], [])
        if EVIDENCE: self.engine.command("save_udp", path=str(EVIDENCE / "android-udp.lens-udp.json"))

    def test_android_source_can_be_composed_and_repeated_with_exact_binary_and_provenance(self):
        url = self.url(self.https, "compose-source", tls=True)
        android = self.probe(url, anchor=self.anchor)
        source = self.assert_echo_and_capture(android, url)
        source_detail = self.engine.command('detail', id=source['id'])[1]
        before = len(self.engine.events)
        command_id, queued = self.engine.command('compose', source_id=source['id'],
            source_fingerprint=source_detail['request_fingerprint'], request_edit={})
        self.assertTrue(queued['queued'])
        finished = self.engine.wait(lambda e: e.get('event') == 'request_finished' and e.get('command_id') == command_id, after=before)
        composed = self.engine.flows[finished['flow_id']]
        self.assertEqual(composed['request_operation']['source_id'], source['id'])
        self.assertEqual(composed['request_operation']['kind'], 'compose')
        self.assertEqual(base64.b64decode(self.engine.command('export_body', id=composed['id'], side='request', decoded=False)[1]['base64']), PAYLOAD)
        _, job = self.engine.command('repeat', id=composed['id'], count=2, concurrency=2)
        done = self.engine.wait(lambda e: e.get('event') == 'repeat_done' and e.get('job_id') == job['job_id'], after=before)
        self.assertEqual((done['source_id'], done['completed'], done['failed'], done['cancelled']), (composed['id'], 2, 0, 0))
        generated = [row for row in self.engine.flows.values() if row.get('request_operation', {}).get('id') == job['job_id']]
        self.assertEqual(sorted(row['request_operation']['attempt'] for row in generated), [1, 2])
        with self.https.history_lock:
            observed = [row for row in self.https.history if row['path'] == '/' + url.split('/', 3)[3]]
        self.assertEqual(len(observed), 4)
        self.assertTrue(all(base64.b64decode(row['body']) == PAYLOAD for row in observed))
        self.engine.command('stop_capture')
        retained = self.engine.command('detail', id=composed['id'])[1]
        self.assertEqual(base64.b64decode(retained['request_body_base64']), PAYLOAD)
        har = self.engine.command('export_har')[1]
        if EVIDENCE:
            (EVIDENCE / 'android-compose-boundaries.json').write_text(json.dumps({'android': android, 'source': source_detail,
                'composed': retained, 'repeat': done, 'origin': observed}, indent=2))
            self.engine.command('save_har', path=str(EVIDENCE / 'android-compose.har'))
        self.engine.command('clear'); self.engine.command('import_har', har=har)
        self.assertEqual(self.engine.command('export_har')[1], har)

    def test_android_full_breakpoint_edits_request_and_response_binary_with_pause_identity(self):
        original = self.url(self.https, "breakpoint-original", tls=True)
        edited = self.url(self.https, "breakpoint-edited", tls=True)
        self.engine.configure([
            {"kind": "dns_spoof", "match": "*", "value": "127.0.0.1"},
            {"kind": "breakpoint_request", "match": original},
            {"kind": "breakpoint_response", "match": edited}])
        request_body, response_body = b"\x00\xffAndroid request edited", b"\x00\x80Android response edited\xff"
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(self.probe, original, self.anchor)
            request = self.engine.flow(original, state="paused")
            after = len(self.engine.events)
            self.engine.command("resume", id=request["id"], pause_id=request["pause_id"], stage="request", action="continue",
                request_edit={"method": "GET", "url": edited,
                    "headers": [["X-Duplicate", "one"], ["X-Duplicate", "two"]],
                    "body_base64": base64.b64encode(request_body).decode()})
            response = self.engine.flow(edited, state="paused", after=after)
            self.assertEqual(response["pause_stage"], "response")
            self.assertNotEqual(response["pause_id"], request["pause_id"])
            with self.assertRaises(AssertionError):
                self.engine.command("resume", id=request["id"], pause_id=request["pause_id"], action="abort")
            self.engine.command("resume", id=response["id"], pause_id=response["pause_id"], stage="response", action="continue",
                response_edit={"status_code": 202, "reason": "Edited by Lens",
                    "headers": [["X-Duplicate", "first"], ["X-Duplicate", "last"], ["Content-Type", "application/octet-stream"]],
                    "body_base64": base64.b64encode(response_body).decode()})
            result = pending.result(timeout=15)
        self.assertEqual(result.get("status"), 202, result)
        self.assertNotIn("errorClass", result, result)
        self.assertEqual(base64.b64decode(result["bodyBase64"]), response_body)
        self.assert_no_origin(original, self.https)
        with self.https.history_lock:
            origin = next(item for item in self.https.history if item["path"] == "/" + edited.split("/", 3)[3])
        self.assertEqual((origin["method"], base64.b64decode(origin["body"])), ("GET", request_body))
        self.assertEqual([v for k, v in origin["headers"] if k.lower() == "x-duplicate"], ["one", "two"])
        self.engine.command("stop_capture")
        detail = self.engine.command("detail", id=request["id"])[1]
        self.assertEqual((detail["original_url"], detail["breakpoint_url"], detail["url"]), (original, edited, edited))
        self.assertEqual(base64.b64decode(detail["request_body_base64"]), request_body)
        self.assertEqual(base64.b64decode(detail["response_body_base64"]), response_body)
        self.assertIsNone(detail.get("pause_id"))
        if EVIDENCE:
            (EVIDENCE / "android-breakpoint-editing.json").write_text(json.dumps({"android": result, "origin": origin, "detail": detail}, indent=2))
            self.engine.command("save_har", path=str(EVIDENCE / "android-breakpoint-editing.har"))

    def test_stop_interrupts_android_request_at_breakpoint(self):
        url = self.url(self.http, "stop")
        self.engine.configure([{"id": "paused", "kind": "breakpoint_request", "match": url, "timeout_seconds": 30}])
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(self.probe, url)
            self.engine.flow(url, state="paused")
            self.engine.close()
            result = pending.result(timeout=15)
        self.assertNotIn("status", result, result)
        self.assertIn("errorClass", result, result)
        self.assertNotEqual(result["errorClass"], "java.net.SocketTimeoutException", result)
        self.assert_no_origin(url, self.http)

    def test_stopped_proxy_cannot_fall_back_to_direct_origin(self):
        self.engine.command("stop_capture")
        url = self.url(self.http, "stopped")
        result = self.probe(url)
        self.assertNotIn("status", result, result)
        self.assertIn("errorClass", result, result)
        self.assertNotEqual(result["errorClass"], "java.net.SocketTimeoutException", result)
        self.assert_no_origin(url, self.http)

    def test_owned_android_system_proxy_routes_http(self):
        with system_proxy(f"{LAN}:{self.engine.port}"):
            url = self.url(self.http, "system-proxy")
            result = self.probe(url, proxy_mode="system")
            self.assertIn(LAN, result.get("selectedProxies", ""), result)
            self.assert_echo_and_capture(result, url)

    def test_system_proxy_bootstrap_then_https_trust_and_full_capture(self):
        with system_proxy(f"{LAN}:{self.engine.port}"):
            # Poison the explicit endpoint: success must come from Android's
            # default ProxySelector, never the probe's explicit-proxy branch.
            selected = dict(proxy_mode="system", proxy_host="127.0.0.1", proxy_port=1)
            certificate = self.probe("http://lens.invalid/certificate.cer", method="GET", payload=b"", **selected)
            self.assertEqual(certificate.get("status"), 200, certificate)
            self.assertEqual(base64.b64decode(certificate["bodyBase64"]), self.anchor)
            self.assertIn(LAN, certificate.get("selectedProxies", ""), certificate)
            denied_url = self.url(self.https, "system-untrusted", tls=True)
            denied = self.probe(denied_url, **selected)
            self.assertEqual(denied.get("trustMode"), "system-default", denied)
            self.assertEqual(denied.get("errorClass"), "javax.net.ssl.SSLHandshakeException", denied)
            self.assertIn("CertPathValidatorException", denied.get("causes", ""), denied)
            self.assert_no_origin(denied_url, self.https)
            url = self.url(self.https, "system-trusted", tls=True)
            trusted = self.probe(url, anchor=self.anchor, **selected)
            self.assertEqual(trusted.get("trustMode"), "session-anchor", trusted)
            self.assertIn(LAN, trusted.get("selectedProxies", ""), trusted)
            flow = self.assert_echo_and_capture(trusted, url)
            self.engine.command("stop_capture")
            entry = next(item for item in self.engine.command("export_har")[1]["log"]["entries"] if item["request"]["url"] == url)
            self.assertEqual(base64.b64decode(entry["_lensRawRequestBody"]), PAYLOAD)
            self.assertEqual(base64.b64decode(entry["_lensRawResponseBody"]), base64.b64decode(trusted["bodyBase64"]))
            self.assertEqual(self.engine.command("detail", id=flow["id"])[1]["state"], "complete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
