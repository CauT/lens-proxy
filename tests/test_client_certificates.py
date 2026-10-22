"""Real mutual TLS with generated private client identities and explicit proxy trust."""
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import select
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from test_e2e import EngineHarness, FixtureHandler, certificate_fixture, ROOT
from test_network_features import certificates as server_certificates


def client_identity(directory):
    now = datetime.now(timezone.utc)
    def name(label):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    def certificate(label, key, issuer, signer, ca, path_length=None):
        return (x509.CertificateBuilder().subject_name(name(label)).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca, path_length), True)
            .add_extension(x509.KeyUsage(True, False, not ca, False, False, ca, ca, False, False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(signer, hashes.SHA256()))
    root_key, intermediate_key, key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3))
    root = certificate("Client root", root_key, name("Client root"), root_key, True, 1)
    intermediate = certificate("Client intermediate", intermediate_key, root.subject, root_key, True, 0)
    leaf = certificate("Lens mutual TLS client", key, intermediate.subject, intermediate_key, False)
    root_path = directory / "client-root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    password = "only-a-fixture-password"
    p12 = directory / "identity.p12"
    # Deliberately unordered: the owner must build the selected leaf's chain.
    p12.write_bytes(pkcs12.serialize_key_and_certificates(b"fixture", key, leaf, [root, intermediate],
        serialization.BestAvailableEncryption(password.encode())))
    pem = directory / "identity.pem"
    pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + intermediate.public_bytes(serialization.Encoding.PEM)
        + root.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password.encode())))
    return root_path, p12, pem, password, leaf.fingerprint(hashes.SHA256()).hex(), key


class MutualTLSHandler(FixtureHandler):
    def end_headers(self):
        peer = self.connection.getpeercert(binary_form=True)
        self.send_header("X-Client-SHA256", hashlib.sha256(peer).hexdigest() if peer else "none")
        self.send_header("X-Upstream-TLS", self.connection.version())
        super().end_headers()


class MutualTLSServer(ThreadingHTTPServer):
    def finish_request(self, request, address):
        # Handshake inside the worker: a speculative or excluded CONNECT leg
        # must not strand the accepting thread and block unrelated tests.
        request.settimeout(5)
        try:
            connection = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            request.close()
            return
        with connection:
            super().finish_request(connection, address)


class ClientCertificateAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-client-certificates-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.upstream_ca, leaves = server_certificates(cls.directory)
        (cert, key), (wrong_cert, wrong_key) = leaves
        _, rogue_cert, rogue_key = certificate_fixture(cls.directory, "rogue")
        cls.root_ca, cls.p12, cls.pem, cls.password, cls.fingerprint, cls.client_key = client_identity(cls.directory)
        cls.reordered_pem = cls.directory / "root-first.pem"
        cls.reordered_pem.write_bytes(b"".join(certificate.public_bytes(serialization.Encoding.PEM)
            for certificate in reversed(x509.load_pem_x509_certificates(cls.pem.read_bytes())))
            + cls.client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(cls.password.encode())))
        cls.servers = []
        for label, cert_path, key_path, required in (("required", cert, key, True),
                ("optional", cert, key, False), ("rogue", rogue_cert, rogue_key, True),
                ("wrong-name", wrong_cert, wrong_key, True), ("tls12", cert, key, True)):
            server = MutualTLSServer(("127.0.0.1", 0), MutualTLSHandler)
            server.history, server.history_lock, server.fixture_name = [], threading.Lock(), label
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            context.load_verify_locations(cls.root_ca)
            context.verify_mode = ssl.CERT_REQUIRED if required else ssl.CERT_OPTIONAL
            if label == "tls12":
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
            server.tls_context = context
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
            cls.servers.append(server)
        cls.port = cls.servers[0].server_port
        cls.url = f"https://localhost:{cls.port}"

    def start_engine(self, selections, *, extra_args=(), **configuration):
        directory = Path(tempfile.mkdtemp(dir=self.directory))
        engine = EngineHarness(directory, self.upstream_ca, ("--initialize-from-stdin", *extra_args),
            initial_configuration={"client_certificates": selections, **configuration})
        self.addCleanup(engine.close)
        return engine, directory

    def selection(self, path=None, **fields):
        return {"host": "localhost", "port": self.port, "path": str(path or self.p12), "password": self.password, **fields}

    def client(self, engine, **settings):
        return httpx.Client(proxy=engine.proxy, verify=ssl.create_default_context(cafile=engine.ready["ca_cert"]),
            trust_env=False, timeout=5, **settings)

    def test_pkcs12_chain_and_encrypted_pem_authenticate_with_strict_tls(self):
        for path in (self.p12, self.pem, self.reordered_pem):
            with self.subTest(format=path.name):
                keylog = self.directory / "unrequested-keylog.txt"
                with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog), "MITMPROXY_SSLKEYLOGFILE": str(keylog)}):
                    engine, directory = self.start_engine([self.selection(path), self.selection(path, port=self.servers[4].server_port)])
                self.assertEqual(engine.ready["client_certificates"][0]["sha256"], self.fingerprint)
                with self.client(engine, http2=True) as client:
                    for suffix in ("first", "second"):
                        response = client.post(self.url + "/" + suffix, content=b"mutual TLS payload")
                        self.assertEqual(response.status_code, 200, response.text)
                        self.assertEqual(response.headers["X-Client-SHA256"], self.fingerprint)
                        self.assertEqual(response.headers["X-Upstream-TLS"], "TLSv1.3")
                        self.assertEqual(response.json()["path"], "/" + suffix)
                    tls12 = client.get(f"https://localhost:{self.servers[4].server_port}/tls12")
                    self.assertEqual(tls12.status_code, 200, tls12.text)
                    self.assertEqual(tls12.headers["X-Client-SHA256"], self.fingerprint)
                    self.assertEqual(tls12.headers["X-Upstream-TLS"], "TLSv1.2")
                _, har = engine.command("export_har")
                self.assertFalse(keylog.exists(), "Inherited variables silently enabled TLS-secret logging")
                self.assertEqual(len(har["log"]["entries"]), 3)
                public_events = json.dumps(engine.events)
                self.assertNotIn(self.password, public_events)
                private_pem = self.client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                for file in (directory / "engine-state").rglob("*"):
                    if file.is_file():
                        payload = file.read_bytes()
                        self.assertNotIn(self.password.encode(), payload)
                        self.assertNotIn(private_pem, payload)
                engine.close()

    def test_unselected_host_port_and_missing_identity_never_authenticate(self):
        engine, _ = self.start_engine([self.selection()])
        with self.client(engine) as client:
            for index in range(3):
                wrong_host = client.get(f"https://127.0.0.1:{self.port}/wrong-host-{index}")
                self.assertEqual(wrong_host.status_code, 502)
            wrong_port = client.get(f"https://localhost:{self.servers[1].server_port}/wrong-port")
            self.assertEqual(wrong_port.status_code, 200)
            self.assertEqual(wrong_port.headers["X-Client-SHA256"], "none")
            # Fatal alerts on other connections must not poison this identity.
            self.assertEqual(client.get(self.url + "/still-authenticates").headers["X-Client-SHA256"], self.fingerprint)
        empty, _ = self.start_engine([])
        with self.client(empty) as client:
            self.assertEqual(client.get(self.url + "/no-identity").status_code, 502)

    def test_ip_identity_authenticates_using_verified_ip_without_dns_sni(self):
        engine, _ = self.start_engine([self.selection(host="127.0.0.1")])
        with self.client(engine) as client:
            response = client.get(f"https://127.0.0.1:{self.port}/ip-identity")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["X-Client-SHA256"], self.fingerprint)

    def test_selected_identity_does_not_disable_upstream_certificate_verification(self):
        for origin in self.servers[2:4]:
            with self.subTest(origin=origin.fixture_name):
                port = origin.server_port
                engine, _ = self.start_engine([self.selection(port=port)])
                before = len(origin.history)
                with self.client(engine) as client:
                    response = client.get(f"https://localhost:{port}/rogue")
                    self.assertEqual(response.status_code, 502)
                    self.assertIn("certificate", response.text.lower())
                self.assertEqual(len(origin.history), before)

    def test_map_remote_selects_the_effective_tls_host_and_stop_releases_identities(self):
        engine, _ = self.start_engine([self.selection()])
        engine.configure([{"kind": "map_remote", "match": "http://remote.invalid/*", "value": self.url}])
        with self.client(engine) as client:
            response = client.get("http://remote.invalid/remapped")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["X-Client-SHA256"], self.fingerprint)
        engine.command("stop_capture")
        self.assertEqual(engine.command("client_certificate_status")[1], {"identities": []})
        self.assertEqual(engine.command("detail", id=next(iter(engine.flows)))[1]["response_body"], response.text)

    def test_reverse_https_client_identity_and_rejected_authentication_terminate(self):
        for selected in (True, False):
            with self.subTest(identity=selected):
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                engine, _ = self.start_engine([self.selection()] if selected else [],
                    extra_args=("--reverse-port", str(port), "--reverse-url", self.url))
                with httpx.Client(trust_env=False, timeout=5) as client:
                    response = client.post(f"http://127.0.0.1:{port}/reverse-mtls", content=b"reverse payload")
                    self.assertEqual(response.status_code, 200 if selected else 502, response.text)
                    if selected:
                        self.assertEqual(response.headers["X-Client-SHA256"], self.fingerprint)

    def test_initial_rules_dns_mapping_and_tls_exclusion_keep_their_owners(self):
        selections = [self.selection(host="LOCALHOST.")]
        rule = {"kind": "dns_spoof", "match": self.url + "/*", "value": "127.0.0.1"}
        engine, _ = self.start_engine(selections, rules=[rule])
        with self.client(engine) as client:
            response = client.get(self.url + "/dns")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers["X-Client-SHA256"], self.fingerprint)
        excluded, _ = self.start_engine(selections, ssl_hosts="")
        # An excluded host is a raw CONNECT tunnel. Lens must not authenticate
        # on the original client's behalf on this leg.
        with httpx.Client(proxy=excluded.proxy, verify=ssl.create_default_context(cafile=self.upstream_ca), trust_env=False, timeout=5) as client:
            with self.assertRaises(httpx.TransportError):
                client.get(self.url + "/excluded")
        self.assertEqual(excluded.flows, {})

    def test_bad_password_and_unsafe_inputs_fail_before_public_listener(self):
        for selection in (self.selection(password="wrong-secret"), self.selection(host="*.localhost"),
                          self.selection(path="relative.p12"), self.selection(port=True)):
            with self.subTest(selection={k: v for k, v in selection.items() if k != "password"}):
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                directory = Path(tempfile.mkdtemp(dir=self.directory))
                command = [sys.executable, "-u", os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py")),
                    "--proxy-port", str(port), "--data-dir", str(directory), "--initialize-from-stdin"]
                request = json.dumps({"command": "initialize", "command_id": "fixture", "client_certificates": [selection]})
                completed = subprocess.run(command, input=request + "\n", text=True, capture_output=True, timeout=10,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertNotEqual(completed.returncode, 0)
                events = [json.loads(line) for line in completed.stdout.splitlines()]
                self.assertTrue(any(event["event"] == "fatal" for event in events), events)
                self.assertFalse(any(event["event"] == "result" and event.get("value", {}).get("initialized") is True for event in events), events)
                self.assertFalse(any(event["event"] == "ready" for event in events))
                self.assertNotIn("wrong-secret", completed.stdout + completed.stderr)
                with socket.socket() as connection:
                    self.assertNotEqual(connection.connect_ex(("127.0.0.1", port)), 0)

    def test_signal_cancels_waiting_for_initialization_before_listener_opens(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        directory = Path(tempfile.mkdtemp(dir=self.directory))
        process = subprocess.Popen([sys.executable, "-u", os.environ.get("LENS_TEST_ENGINE", str(ROOT / "engine/engine.py")),
            "--proxy-port", str(port), "--data-dir", str(directory), "--initialize-from-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            self.assertTrue(select.select([process.stdout], [], [], 10)[0], "No initialization-stage handshake")
            self.assertEqual(json.loads(process.stdout.readline()), {"event": "initializing"})
            with socket.socket() as connection:
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", port)), 0)
            process.terminate()
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertNotIn(b'"event": "ready"', process.stdout.read())
            self.assertNotIn(b"Task was destroyed", process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()


if __name__ == "__main__":
    unittest.main()
