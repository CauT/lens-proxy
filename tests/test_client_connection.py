"""Actual front-peer provenance across internal proxy transports and HAR."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import http.client
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from test_e2e import EngineHarness, certificate_fixture, start_fixture
from test_tcp_forwarding import unused_port


class ClientConnectionAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-client-source-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.ca, cert, key = certificate_fixture(self.directory, "client-source")
        self.http, _ = start_fixture("source HTTP")
        self.https, _ = start_fixture("source HTTPS", cert, key)
        for server in (self.http, self.https):
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)

    def engine(self, *arguments):
        engine = EngineHarness(self.directory, self.ca, extra_args=arguments)
        self.addCleanup(engine.close)
        return engine

    def assert_source(self, flow, peer, local, listener="proxy_port"):
        fact = flow["client_connection"]
        self.assertEqual(fact["version"], 1)
        self.assertEqual(fact["peer"], list(peer[:2]))
        self.assertEqual(fact["listener_address"], list(local[:2]))
        self.assertEqual(fact["listener"], listener)
        self.assertEqual(len(fact["id"]), 32)
        self.assertGreater(fact["accepted_at"], 0)
        return fact

    def test_keepalive_clear_and_spoofed_headers_do_not_change_socket_identity(self):
        engine = self.engine()
        with closing(http.client.HTTPConnection("127.0.0.1", engine.port, timeout=5)) as client:
            client.connect(); peer = client.sock.getsockname(); local = client.sock.getpeername()
            facts = []
            for index in range(2):
                url = f"http://127.0.0.1:{self.http.server_port}/source-{index}"
                client.request("GET", url, headers={"X-Forwarded-For": "203.0.113.90", "Forwarded": "for=203.0.113.91"})
                response = client.getresponse(); self.assertEqual(response.status, 200); response.read()
                facts.append(self.assert_source(engine.flow(url), peer, local))
                engine.command("clear")
            self.assertEqual(facts[0], facts[1])
        engine.command("stop_capture")
        self.assertEqual(engine.command("network_status")[1]["client_bindings"], 0)

    def test_concurrent_clients_never_exchange_peer_ports_or_ids(self):
        engine = self.engine()
        barrier = threading.Barrier(8)
        def request(index):
            with closing(http.client.HTTPConnection("127.0.0.1", engine.port, timeout=5)) as client:
                client.connect(); peer = client.sock.getsockname(); local = client.sock.getpeername()
                barrier.wait(timeout=5)
                url = f"http://127.0.0.1:{self.http.server_port}/parallel-{index}"
                client.request("GET", url)
                response = client.getresponse(); response.read()
                return self.assert_source(engine.flow(url), peer, local)
        with ThreadPoolExecutor(max_workers=8) as workers:
            facts = list(workers.map(request, range(8)))
        self.assertEqual(len({fact["id"] for fact in facts}), 8)
        self.assertEqual(len({tuple(fact["peer"]) for fact in facts}), 8)
        engine.command("stop_capture")
        self.assertEqual(engine.command("network_status")[1]["client_bindings"], 0)

    def test_connect_tls_front_peer_survives_stop_har_and_import(self):
        engine = self.engine()
        context = ssl.create_default_context(cafile=engine.ready["ca_cert"])
        with closing(http.client.HTTPSConnection("127.0.0.1", engine.port, context=context, timeout=5)) as client:
            client.set_tunnel("localhost", self.https.server_port)
            client.request("POST", "/tls-source", body=b"\x00\xffTLS source")
            peer, local = client.sock.getsockname(), client.sock.getpeername()
            response = client.getresponse(); self.assertEqual(response.status, 200); response.read()
            url = f"https://localhost:{self.https.server_port}/tls-source"
            flow = engine.flow(url)
            source = self.assert_source(flow, peer, local)
        engine.command("stop_capture")
        self.assertEqual(engine.command("detail", id=flow["id"])[1]["client_connection"], source)
        path = self.directory / "source.har"
        engine.command("save_har", path=str(path))
        engine.command("clear"); engine.command("load_har", path=str(path))
        _, har = engine.command("export_har")
        self.assertEqual(har["log"]["entries"][0]["_lensClientConnection"], source)
        imported = next(value for value in engine.flows.values() if value.get("imported"))
        self.assertEqual(imported["client_connection"], source)

    def test_socks_and_reverse_use_their_public_front_endpoints(self):
        socks, reverse = unused_port(), unused_port()
        engine = self.engine("--socks-port", str(socks), "--reverse-port", str(reverse),
                             "--reverse-url", f"http://127.0.0.1:{self.http.server_port}")
        with socket.create_connection(("127.0.0.1", socks), timeout=5) as stream:
            peer, local = stream.getsockname(), stream.getpeername()
            stream.sendall(b"\x05\x01\x00"); self.assertEqual(stream.recv(2), b"\x05\x00")
            stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + self.http.server_port.to_bytes(2, "big"))
            reply = bytearray()
            while len(reply) < 10: reply.extend(stream.recv(10-len(reply)))
            self.assertEqual(reply[1], 0)
            stream.sendall(f"GET /socks-source HTTP/1.1\r\nHost: 127.0.0.1:{self.http.server_port}\r\n\r\n".encode())
            response = http.client.HTTPResponse(stream); response.begin(); self.assertEqual(response.status, 200); response.read()
            self.assert_source(engine.flow(f"http://127.0.0.1:{self.http.server_port}/socks-source"), peer, local, "socks_port")
        with closing(http.client.HTTPConnection("127.0.0.1", reverse, timeout=5)) as client:
            client.request("GET", "/reverse-source")
            peer, local = client.sock.getsockname(), client.sock.getpeername()
            response = client.getresponse(); self.assertEqual(response.status, 200); response.read()
            self.assert_source(engine.flow(f"http://127.0.0.1:{self.http.server_port}/reverse-source"), peer, local, "reverse_port")
        engine.command("stop_capture")
        self.assertEqual(engine.command("network_status")[1]["client_bindings"], 0)

    def test_map_remote_does_not_reinterpret_client_and_bad_later_import_is_atomic(self):
        engine = self.engine()
        engine.configure([{"kind": "map_remote", "match": "http://source.invalid/*",
                           "value": f"http://127.0.0.1:{self.http.server_port}"}])
        with closing(http.client.HTTPConnection("127.0.0.1", engine.port, timeout=5)) as client:
            client.request("GET", "http://source.invalid/mapped-source")
            peer, local = client.sock.getsockname(), client.sock.getpeername()
            response = client.getresponse(); self.assertEqual(response.status, 200); response.read()
            flow = engine.flow(f"http://127.0.0.1:{self.http.server_port}/mapped-source")
            source = self.assert_source(flow, peer, local)
            self.assertEqual(flow["original_url"], "http://source.invalid/mapped-source")
        engine.command("stop_capture")
        before = engine.command("export_har")[1]
        bad = copy.deepcopy(before)
        bad["log"]["entries"].append(copy.deepcopy(bad["log"]["entries"][0]))
        bad["log"]["entries"][-1]["_lensClientConnection"]["peer"][1] = True
        with self.assertRaisesRegex(AssertionError, "client connection"):
            engine.command("import_har", har=bad)
        self.assertEqual(engine.command("detail", id=flow["id"])[1]["client_connection"], source)
        after = engine.command("export_har")[1]
        self.assertEqual(len(after["log"]["entries"]), len(before["log"]["entries"]))
        for field in ("request", "response", "_lensClientConnection"):
            self.assertEqual(after["log"]["entries"][0][field], before["log"]["entries"][0][field])


if __name__ == "__main__":
    unittest.main()
