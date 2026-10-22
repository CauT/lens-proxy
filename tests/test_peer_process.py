"""Opt-in process attribution through the actual packaged engine and macOS lsof."""
from contextlib import closing
import copy
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_e2e import EngineHarness, ROOT, certificate_fixture, start_fixture
from test_tcp_forwarding import unused_port


CLIENT = r'''
import http.client, json, socket, ssl, sys
mode, port, origin, ca = sys.argv[1:]
port, origin = int(port), int(origin)
stream = None
if mode == "tls":
    client = http.client.HTTPSConnection("127.0.0.1", port, context=ssl.create_default_context(cafile=ca), timeout=10)
    client.set_tunnel("localhost", origin)
elif mode == "socks":
    stream = socket.create_connection(("127.0.0.1", port), timeout=10)
    stream.sendall(b"\x05\x01\x00"); assert stream.recv(2) == b"\x05\x00"
    stream.sendall(b"\x05\x01\x00\x01"+socket.inet_aton("127.0.0.1")+origin.to_bytes(2,"big"))
    reply = bytearray()
    while len(reply) < 10: reply.extend(stream.recv(10-len(reply)))
    assert reply[1] == 0
    client = http.client.HTTPConnection("127.0.0.1", origin, timeout=10); client.sock = stream
else:
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
for index in range(2):
    path = "/process-"+mode+"-"+str(index)
    url = ("http://127.0.0.1:"+str(origin)+path) if mode == "http" else path
    client.request("POST", url, body=b"request-process-body")
    response = client.getresponse()
    body = json.loads(response.read()); assert response.status == 200
    assert body["body"] == "cmVxdWVzdC1wcm9jZXNzLWJvZHk="
print(json.dumps({"peer":client.sock.getsockname(),"local":client.sock.getpeername()}),flush=True)
sys.stdin.readline() # retain this owned client until its birth identity is checked
client.close()
'''


class PeerProcessAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-peer-process-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.ca, cert, key = certificate_fixture(self.directory, "process")
        self.http, _ = start_fixture("process HTTP")
        self.tls, _ = start_fixture("process TLS", cert, key)
        for server in (self.http, self.tls):
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)

    def exercise(self, mode):
        engine_path = os.environ.get("LENS_TEST_ENGINE", str(ROOT / "Lens.app/Contents/Resources/engine/engine.py"))
        helper = Path(engine_path).resolve().parents[1] / "peer-process-identities"
        self.assertTrue(helper.is_file(), "Build Lens.app and select its packaged engine for this lane")
        extra, port = ["--initialize-from-stdin"], None
        if mode == "socks":
            port = unused_port(); extra += ["--socks-port", str(port)]
        elif mode == "reverse":
            port = unused_port(); extra += ["--reverse-port", str(port), "--reverse-url", f"http://127.0.0.1:{self.http.server_port}"]
        with patch.dict(os.environ, {"LENS_TEST_ENGINE": engine_path}):
            engine = EngineHarness(self.directory, self.ca, extra_args=extra, initial_configuration={"client_process": True})
        self.addCleanup(engine.close)
        self.assertTrue(engine.ready["client_process"])
        origin = self.tls.server_port if mode == "tls" else self.http.server_port
        client = subprocess.Popen([sys.executable, "-c", CLIENT, mode, str(port or engine.port), str(origin), engine.ready["ca_cert"]],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def finish():
            if client.poll() is None:
                try: client.communicate("\n", timeout=10)
                except subprocess.TimeoutExpired:
                    client.terminate(); client.communicate(timeout=5)
            for stream in (client.stdin, client.stdout, client.stderr): stream.close()
        self.addCleanup(finish)
        # The client's network timeout bounds this readline; failures emit EOF.
        line = client.stdout.readline()
        if not line: self.fail(f"Owned client failed: {client.stderr.read()}")
        endpoints = json.loads(line)
        identities = json.loads(subprocess.check_output([str(helper), str(client.pid)], timeout=5))
        identity = identities["results"][0]["identity"]
        facts = []
        scheme, host = ("https", "localhost") if mode == "tls" else ("http", "127.0.0.1")
        for index in range(2):
            flow = engine.flow(f"{scheme}://{host}:{origin}/process-{mode}-{index}")
            source = flow["client_connection"]; fact = source["process"]
            self.assertEqual(source["peer"], endpoints["peer"])
            self.assertEqual(fact["state"], "identified", fact)
            self.assertEqual(fact["scope"], "host_tcp_socket")
            self.assertEqual(fact["pid"], client.pid)
            self.assertEqual(fact["start_identity"], identity)
            self.assertTrue(fact["name"])
            facts.append(fact)
        self.assertEqual(facts[0], facts[1], "Keepalive must retain the original observation")
        finish()
        self.assertEqual(client.returncode, 0)
        engine.command("stop_capture")
        self.assertEqual(engine.command("detail", id=flow["id"])[1]["client_connection"]["process"], facts[0])
        before = engine.command("export_har")[1]
        malformed = copy.deepcopy(before)
        malformed["log"]["entries"][-1]["_lensClientConnection"]["process"]["pid"] = True
        with self.assertRaisesRegex(AssertionError, "peer process"):
            engine.command("import_har", har=malformed)
        self.assertEqual(len(engine.command("export_har")[1]["log"]["entries"]), 2)
        engine.command("clear"); engine.command("import_har", har=before)
        after = engine.command("export_har")[1]
        self.assertEqual([entry["_lensClientConnection"] for entry in before["log"]["entries"]],
                         [entry["_lensClientConnection"] for entry in after["log"]["entries"]])
        self.assertEqual(engine.command("network_status")[1]["active_connections"], 0)
        self.assertEqual(engine.command("network_status")[1]["process_lookup_children"], 0)

    def test_http_client_process_keepalive_stop_details_and_har(self): self.exercise("http")
    def test_connect_tls_client_process_keepalive_stop_details_and_har(self): self.exercise("tls")
    def test_socks_client_process_keepalive_stop_details_and_har(self): self.exercise("socks")
    def test_reverse_client_process_keepalive_stop_details_and_har(self): self.exercise("reverse")

    def test_off_by_default_does_not_add_process_metadata(self):
        engine = EngineHarness(self.directory, self.ca)
        self.addCleanup(engine.close)
        self.assertFalse(engine.ready["client_process"])
        with closing(http.client.HTTPConnection("127.0.0.1", engine.port, timeout=5)) as client:
            url = f"http://127.0.0.1:{self.http.server_port}/disabled"
            client.request("GET", url); response = client.getresponse(); response.read()
            self.assertNotIn("process", engine.flow(url)["client_connection"])


if __name__ == "__main__": unittest.main()
