"""Real loopback capture -> atomic HAR -> native summaries and exact re-export."""
from concurrent.futures import ThreadPoolExecutor
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import httpx
from test_e2e import EngineHarness, certificate_fixture


class HAROrigin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        time.sleep(0.09)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "session=one; Path=/; HttpOnly; Secure; SameSite=Lax")
        self.send_header("Set-Cookie", "session=two; Expires=not-a-date")
        self.end_headers()
        self.wfile.flush()
        time.sleep(0.09)
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        if self.path == "/drop":
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
        self.wfile.flush()


class HARFidelityAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-har-fidelity-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, _, _ = certificate_fixture(cls.directory, "har")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HAROrigin)
        cls.server.daemon_threads = True
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)

    def setUp(self):
        self.engine.configure([])
        self.engine.command("clear")

    def client(self):
        return httpx.Client(proxy=self.engine.proxy, trust_env=False, timeout=8)

    def saved(self, name):
        path = self.directory / name
        self.engine.command("save_har", path=str(path))
        return path, json.loads(path.read_text())

    def test_real_receive_intervals_cookies_and_reused_connection_roundtrip(self):
        body = b"\x00\xfffixture body"
        first_url, next_url = self.base + "/phases", self.base + "/same-connection"
        with socket.create_connection(("127.0.0.1", self.engine.port), timeout=8) as sock:
            sock.sendall((f"POST {first_url} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n"
                          f"Content-Length: {len(body)}\r\nCookie: a=1; a=2\r\nCookie: token=%2B+raw\r\n\r\n").encode())
            time.sleep(0.09)
            sock.sendall(body)
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), body)
            response.close()
            sock.sendall((f"GET {next_url} HTTP/1.1\r\nHost: 127.0.0.1:{self.server.server_port}\r\n\r\n").encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.read(), b"ok")
            response.close()
        self.engine.flow(first_url)
        self.engine.flow(next_url)
        path, har = self.saved("phases.har")
        first, reused = har["log"]["entries"]
        phases = first["timings"]
        for key in ("send", "wait", "receive"):
            self.assertGreater(phases[key], 40, (key, phases))
        self.assertAlmostEqual(sum(phases[key] for key in ("send", "wait", "receive")), first["time"], delta=0.001)
        self.assertEqual(first["request"]["cookies"], [
            {"name": "a", "value": "1"}, {"name": "a", "value": "2"}, {"name": "token", "value": "%2B+raw"}])
        cookies = first["response"]["cookies"]
        self.assertEqual([cookie["value"] for cookie in cookies], ["one", "two"])
        self.assertTrue(cookies[0]["httpOnly"] and cookies[0]["secure"])
        self.assertEqual(cookies[0]["_sameSite"], "Lax")
        self.assertTrue(cookies[1]["_lensCookieIssues"])
        first_conn = first["_lensTiming"]["serverConnection"]
        next_conn = reused["_lensTiming"]["serverConnection"]
        self.assertEqual(first_conn["timestamp_start"], next_conn["timestamp_start"])
        self.assertEqual(first_conn["timestamp_tcp_setup"], next_conn["timestamp_tcp_setup"])
        self.assertLess(next_conn["timestamp_tcp_setup"], reused["_lensTiming"]["request"]["start"])
        self.assertEqual(reused["timings"]["connect"], -1, "do not charge reused setup to every request")
        self.engine.command("clear")
        self.engine.command("load_har", path=str(path))
        _, roundtrip = self.saved("roundtrip.har")
        self.assertEqual(roundtrip, har)

    def test_failed_upstream_retains_original_error_time_and_native_duration(self):
        url = self.base + "/drop"
        with self.client() as client:
            response = client.get(url)
        self.assertEqual(response.status_code, 502)
        failed = self.engine.flow(url, state="error")
        self.assertIsNotNone(failed["duration_ms"])
        path, document = self.saved("failed.har")
        entry = document["log"]["entries"][0]
        self.assertIsNotNone(entry["_lensError"])
        timestamp = entry["_lensTiming"]["error"]["timestamp"]
        self.assertGreaterEqual(timestamp, entry["_lensTiming"]["request"]["start"])
        self.assertAlmostEqual(failed["duration_ms"], entry["time"], delta=0.001)
        self.engine.command("clear")
        after = len(self.engine.events)
        self.engine.command("load_har", path=str(path))
        restored = self.engine.flow(url, state="error", after=after)
        self.assertEqual(restored["duration_ms"], failed["duration_ms"])
        _, reexport = self.saved("failed-roundtrip.har")
        self.assertEqual(reexport, document)

    def test_paused_snapshot_is_historical_incomplete_not_a_resumable_live_flow(self):
        url = self.base + "/paused-snapshot"
        self.engine.configure([{"id": "paused", "kind": "breakpoint_request", "enabled": True, "match": url}])
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.client() as client:
                future = pool.submit(client.get, url)
                paused = self.engine.flow(url, state="paused")
                path, document = self.saved("paused.har")
                entry = document["log"]["entries"][0]
                self.assertEqual(entry["time"], -1)
                self.assertEqual(entry["_lensTiming"]["state"], "paused")
                self.engine.command("resume", id=paused["id"], action="continue")
                self.assertEqual(future.result(timeout=4).status_code, 200)
        self.engine.command("clear")
        after = len(self.engine.events)
        self.engine.command("load_har", path=str(path))
        historical = self.engine.flow(url, state="pending", after=after)
        self.assertIsNone(historical["duration_ms"])
        self.assertTrue(historical["imported"])
        with self.assertRaisesRegex(AssertionError, "not paused"):
            self.engine.command("resume", id=historical["id"], action="continue")
        _, reexport = self.saved("paused-roundtrip.har")
        self.assertEqual(reexport, document)

    def test_bad_late_entry_does_not_replace_native_current_captures(self):
        url = self.base + "/existing"
        with self.client() as client:
            self.assertEqual(client.get(url).status_code, 200)
        original = self.engine.flow(url)
        _, document = self.saved("original.har")
        valid = copy.deepcopy(document["log"]["entries"][0])
        bad = copy.deepcopy(valid)
        bad["timings"]["receive"] = True
        document["log"]["entries"] = [valid, bad]
        path = self.directory / "bad.har"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(AssertionError, "finite number"):
            self.engine.command("load_har", path=str(path))
        _, current = self.engine.command("detail", id=original["id"])
        self.assertEqual(current["url"], url)
        _, snapshot = self.saved("unchanged.har")
        self.assertEqual(len(snapshot["log"]["entries"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
