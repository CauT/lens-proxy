"""Additional real protocol acceptance; no external hosts or system configuration.

Run: mac-charles/.runtime/bin/python -m unittest discover -s mac-charles/tests -p test_protocols.py -v
"""
import base64
from datetime import datetime, timedelta, timezone
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import ssl
import tempfile
import threading
import unittest
import zlib

import brotli
import h2.config
import h2.connection
import h2.events
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from test_e2e import EngineHarness


PLAIN_TEXT = "Lens compressed response — \u672c\u5730\u8bc1\u636e\n" * 8
PLAIN = PLAIN_TEXT.encode()
COMPRESSORS = {"gzip": gzip.compress, "deflate": zlib.compress, "br": brotli.compress}


def protocol_certificates(directory, additional_sans=()):
    """Supply full RFC 5280 extensions for Python 3.13 strict client verification."""
    now = datetime.now(timezone.utc)
    authority = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lens test protocols CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(authority.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(authority.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), True)
          .sign(authority, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=True, data_encipherment=False, key_agreement=False,
              key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")), *additional_sans]), False)
        .sign(authority, hashes.SHA256()))
    ca_path, cert_path, key_path = [directory / f"origin-{suffix}.pem" for suffix in ("ca", "cert", "key")]
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_path, cert_path, key_path


class ProtocolHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.respond()

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                if size == 0:
                    while self.rfile.readline().strip():
                        pass
                    break
                body += self.rfile.read(size)
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("Bad fixture request chunk terminator")
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        record = {"method": self.command, "path": self.path,
                  "http_version": self.request_version,
                  "body": base64.b64encode(body).decode(),
                  "client_port": self.client_address[1],
                  "headers": list(self.headers.raw_items())}
        with self.server.history_lock:
            self.server.history.append(record)
        if self.path.startswith("/compressed/"):
            coding = self.path.rsplit("/", 1)[-1]
            wire = COMPRESSORS[coding](PLAIN)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Encoding", coding)
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (b"chunk one ", b"chunk two", b"\x00\xff"):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        else:
            payload = json.dumps(record).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)


class H2Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        connection = h2.connection.H2Connection(h2.config.H2Configuration(
            client_side=False, header_encoding="utf-8"))
        connection.initiate_connection()
        self.request.sendall(connection.data_to_send())
        requests = {}
        try:
            while data := self.request.recv(65536):
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        requests[event.stream_id] = {"headers": list(event.headers), "body": b""}
                    elif isinstance(event, h2.events.DataReceived):
                        requests[event.stream_id]["body"] += event.data
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        request = requests.pop(event.stream_id)
                        record = {"headers": request["headers"],
                                  "body": base64.b64encode(request["body"]).decode(),
                                  "alpn": self.request.selected_alpn_protocol(),
                                  "stream_id": event.stream_id}
                        with self.server.history_lock:
                            self.server.history.append(record)
                        response = json.dumps(record).encode()
                        connection.send_headers(event.stream_id, [
                            (":status", "200"), ("content-type", "application/json"),
                            ("content-length", str(len(response)))])
                        connection.send_data(event.stream_id, response, end_stream=True)
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return
                pending = connection.data_to_send()
                if pending:
                    self.request.sendall(pending)
        except (OSError, h2.exceptions.ProtocolError):
            return


class H2Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise


class ProtocolAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-protocols-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.origin_ca, cert, key = protocol_certificates(cls.directory)
        cls.http_server = ThreadingHTTPServer(("127.0.0.1", 0), ProtocolHTTPHandler)
        cls.http_server.daemon_threads = True
        cls.tls_server = ThreadingHTTPServer(("127.0.0.1", 0), ProtocolHTTPHandler)
        cls.tls_server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.tls_server.socket = context.wrap_socket(cls.tls_server.socket, server_side=True)
        cls.h2_server = H2Server(("127.0.0.1", 0), H2Handler)
        cls.h2_server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.h2_server.tls.load_cert_chain(cert, key)
        cls.h2_server.tls.set_alpn_protocols(["h2"])
        for server in (cls.http_server, cls.tls_server, cls.h2_server):
            server.history, server.history_lock = [], threading.Lock()
            cls.addClassCleanup(server.server_close)
            cls.addClassCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.http = f"http://127.0.0.1:{cls.http_server.server_port}"
        cls.https = f"https://localhost:{cls.tls_server.server_port}"
        cls.h2 = f"https://localhost:{cls.h2_server.server_address[1]}"
        cls.engine = EngineHarness(cls.directory, cls.origin_ca)
        cls.addClassCleanup(cls.engine.close)
        cls.lens_context = ssl.create_default_context(cafile=cls.engine.ready["ca_cert"])

    def setUp(self):
        self.engine.configure([])
        self.engine.command("clear")

    def client(self, context=None, http2=False):
        return httpx.Client(proxy=self.engine.proxy, verify=context or self.lens_context,
                            trust_env=False, timeout=10, http2=http2)

    def test_http2_tls_end_to_end_with_origin_protocol_evidence(self):
        url = self.h2 + "/h2?stream=1"
        with self.client(http2=True) as client:
            response = client.post(url, content=b"HTTP/2 payload")
        self.assertEqual(response.status_code, 200)
        origin = response.json()
        self.assertEqual(origin["alpn"], "h2")
        self.assertEqual(base64.b64decode(origin["body"]), b"HTTP/2 payload")
        self.assertIn([":path", "/h2?stream=1"], origin["headers"])
        captured = self.engine.flow(url)
        self.assertEqual(response.http_version, "HTTP/2", f"origin evidence: {origin}")
        self.assertEqual(captured["http_version"], "HTTP/2.0")
        _, detail = self.engine.command("detail", id=captured["id"])
        self.assertEqual(detail["request_body"], "HTTP/2 payload")
        self.assertEqual(json.loads(detail["response_body"])["alpn"], "h2")
        archive = self.directory / "http2-request-facts.har"
        self.engine.command("save_har", path=str(archive))
        document = json.loads(archive.read_text())
        facts = document["log"]["entries"][0]["_lensRequestFacts"]
        self.assertEqual(base64.b64decode(facts["authority_base64"]),
                         f"localhost:{self.h2_server.server_address[1]}".encode())
        self.engine.command("clear")
        after = len(self.engine.events)
        self.engine.command("load_har", path=str(archive))
        restored = self.engine.flow(url, after=after)
        self.assertEqual(restored["request_target_source"], "har_facts")
        reopened = self.engine.command("detail", id=restored["id"])[1]
        self.assertEqual(reopened["request_fingerprint"], detail["request_fingerprint"])
        self.assertEqual(reopened["http_version"], "HTTP/2.0")
        self.engine.command("save_har", path=str(archive))
        self.assertEqual(json.loads(archive.read_text()), document)

    def test_http2_client_translates_to_http1_tls_origin(self):
        url = self.https + "/h2-client-h1-origin"
        with self.client(http2=True) as client:
            response = client.post(url, content=b"protocol translation")
        self.assertEqual(response.http_version, "HTTP/2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["http_version"], "HTTP/1.1")
        self.assertEqual(base64.b64decode(response.json()["body"]), b"protocol translation")
        self.assertEqual(self.engine.flow(url)["http_version"], "HTTP/2.0")

    def test_compressed_response_decoding_and_har_wire_roundtrip(self):
        for coding in COMPRESSORS:
            with self.subTest(coding=coding):
                self.engine.command("clear")
                url = self.http + "/compressed/" + coding
                with self.client() as client:
                    response = client.get(url)
                self.assertEqual(response.content, PLAIN)
                captured = self.engine.flow(url)
                _, detail = self.engine.command("detail", id=captured["id"])
                self.assertEqual(detail["response_body"], PLAIN_TEXT)
                _, har = self.engine.command("export_har")
                entry = har["log"]["entries"][0]
                self.assertEqual(entry["response"]["content"]["text"], PLAIN_TEXT)
                wire = base64.b64decode(entry["_lensRawResponseBody"])
                self.assertNotEqual(wire, PLAIN)
                decompress = {"gzip": gzip.decompress, "deflate": zlib.decompress,
                              "br": brotli.decompress}[coding]
                self.assertEqual(decompress(wire), PLAIN)
                self.engine.command("clear")
                self.engine.command("import_har", har=har)
                _, restored = self.engine.command("export_har")
                self.assertEqual(restored["log"]["entries"][0], entry)

    def test_http1_keepalive_reuses_client_and_origin_connections(self):
        with self.client() as client:
            first = client.get(self.http + "/keepalive-one")
            client_address = first.extensions["network_stream"].get_extra_info("socket").getsockname()
            second = client.get(self.http + "/keepalive-two")
            next_address = second.extensions["network_stream"].get_extra_info("socket").getsockname()
        self.assertEqual(first.http_version, "HTTP/1.1")
        self.assertEqual(client_address, next_address)
        self.assertEqual(first.json()["client_port"], second.json()["client_port"])
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

    def test_chunked_request_response_and_head_empty_body(self):
        with self.client() as client:
            request = client.post(self.http + "/chunked-request", content=iter([b"alpha", b"\x00\xff", b"omega"]))
            self.assertEqual(base64.b64decode(request.json()["body"]), b"alpha\x00\xffomega")
            self.assertTrue(any(k.lower() == "transfer-encoding" and v.lower() == "chunked"
                                for k, v in request.json()["headers"]))
            response = client.get(self.http + "/chunked")
            self.assertEqual(response.content, b"chunk one chunk two\x00\xff")
            head = client.head(self.http + "/head")
            self.assertEqual(head.status_code, 200)
            self.assertEqual(head.content, b"")
            self.assertGreater(int(head.headers["Content-Length"]), 0)
            # A request after HEAD detects accidental waiting for or consumption of a body.
            self.assertEqual(client.get(self.http + "/after-head").status_code, 200)
        captured = self.engine.flow(self.http + "/chunked")
        _, detail = self.engine.command("detail", id=captured["id"])
        self.assertEqual(detail["response_size"], len(b"chunk one chunk two\x00\xff"))

    def test_expect_100_continue_before_request_body(self):
        url = self.http + "/continue"
        body = b"body only after 100 Continue"
        with socket.create_connection(("127.0.0.1", self.engine.port), timeout=10) as sock:
            sock.sendall((f"POST {url} HTTP/1.1\r\nHost: 127.0.0.1:{self.http_server.server_port}\r\n"
                          f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\n\r\n").encode())
            stream = sock.makefile("rb")
            try:
                self.assertIn(b" 100 ", stream.readline())
                while True:
                    line = stream.readline()
                    self.assertTrue(line, "EOF before interim response headers completed")
                    if line == b"\r\n":
                        break
                sock.sendall(body)
                # The interim stream has consumed exactly its headers before the final response exists.
                final = http.client.HTTPResponse(sock)
                final.begin()
                try:
                    self.assertEqual(final.status, 200)
                    self.assertEqual(base64.b64decode(json.loads(final.read())["body"]), body)
                finally:
                    final.close()
            finally:
                stream.close()
        self.engine.flow(url)

    def test_ssl_exclusion_is_verified_origin_ca_connect_tunnel(self):
        self.engine.command("configure", rules=[], ssl_hosts="")
        origin_context = ssl.create_default_context(cafile=self.origin_ca)
        url = self.https + "/excluded-from-decryption"
        with self.client(context=origin_context) as client:
            response = client.get(url)
            # The connected TLS peer must be the origin, not a Lens-issued replacement.
            ssl_object = response.extensions["network_stream"].get_extra_info("ssl_object")
            issuer = ssl_object.getpeercert()["issuer"]
        self.assertEqual(response.status_code, 200)
        self.assertIn((("commonName", "Lens test protocols CA"),), issuer)
        _, har = self.engine.command("export_har")
        self.assertEqual(har["log"]["entries"], [], "excluded HTTPS must not become a decrypted HTTP flow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
