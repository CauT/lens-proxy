#!/usr/bin/env python3
"""Actual JSONL engine + HTTP clients: breakpoint deadlines and release lifecycle.

All listeners, certificates, captures and logs belong to temporary loopback fixtures.
No system proxy, Keychain or Charles installation is read or changed.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import tempfile
import time
import unittest

import httpx
from test_e2e import EngineHarness, certificate_fixture, start_fixture


class BreakpointDeadlineAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_directory = tempfile.TemporaryDirectory(prefix="lens-deadline-fixture-")
        cls.addClassCleanup(cls.fixture_directory.cleanup)
        cls.ca, _, _ = certificate_fixture(Path(cls.fixture_directory.name), "deadline")
        cls.server, cls.worker = start_fixture("deadline")
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-deadline-engine-")
        self.addCleanup(self.temporary.cleanup)
        self.engine = EngineHarness(Path(self.temporary.name), self.ca)
        self.addCleanup(self.engine.close)
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.addCleanup(self.pool.shutdown, wait=True)

    def rule(self, side, url, seconds=None):
        rule = {"id": "deadline-" + side, "enabled": True, "kind": "breakpoint_" + side,
                "match": url, "name": "", "value": ""}
        if seconds is not None:
            rule["timeout_seconds"] = seconds
        return rule

    def request(self, url):
        with httpx.Client(proxy=self.engine.proxy, trust_env=False, timeout=8) as client:
            return client.post(url, content=b"before breakpoint")

    def paused(self, url, stage, after=0):
        return self.engine.wait(lambda event: event.get("event") == "flow"
                                and event["flow"]["url"] == url
                                and event["flow"]["state"] == "paused"
                                and event["flow"].get("pause_stage") == stage,
                                after=after)["flow"]

    def assert_client_aborted(self, future, timeout=3):
        # A client timeout or a Future timeout does not establish actual abort delivery.
        with self.assertRaises((httpx.NetworkError, httpx.RemoteProtocolError)):
            future.result(timeout=timeout)

    def assert_no_late_error(self, url, after):
        self.assertFalse(any(event.get("event") == "flow" and event["flow"]["url"] == url
                             and event["flow"]["state"] == "error"
                             for event in self.engine.events[after:]))

    def test_deadline_aborts_real_request_and_response_and_retains_reason(self):
        for side in ("request", "response"):
            with self.subTest(side=side):
                url = self.base + "/timeout-" + side
                self.engine.configure([self.rule(side, url, 1)])
                after = len(self.engine.events)
                started = time.monotonic()
                future = self.pool.submit(self.request, url)
                paused = self.paused(url, side, after)
                self.assertFalse(future.done())
                self.assertEqual(paused["pause_timeout_seconds"], 1)
                self.assertIsInstance(paused["pause_deadline"], float)
                self.assertAlmostEqual(paused["pause_deadline"] - paused["started"], 1, delta=0.6)
                self.assert_client_aborted(future)
                self.assertGreaterEqual(time.monotonic() - started, 0.85)
                failure = self.engine.flow(url, state="error", after=after)
                self.assertIn(side.title() + " breakpoint timed out", failure["error"])
                self.assertIn("request aborted", failure["error"])
                self.assertIsNone(failure["pause_deadline"])
                self.assertIsNone(failure["pause_stage"])
                _, detail = self.engine.command("detail", id=paused["id"])
                self.assertEqual(detail["error"], failure["error"])
        with self.server.history_lock:
            self.assertFalse(any(item["path"] == "/timeout-request" for item in self.server.history))
            self.assertTrue(any(item["path"] == "/timeout-response" for item in self.server.history))
        # The engine remains useful after both deadline errors.
        self.engine.configure([])
        self.assertEqual(self.request(self.base + "/after-timeout").status_code, 200)

    def test_old_rule_default_and_invalid_timeout_configuration(self):
        url = self.base + "/default-timeout"
        self.engine.configure([self.rule("request", url)])
        for invalid in (True, 0, -1, 1.5, "1", 3601):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(AssertionError, "timeout_seconds must be an integer"):
                    self.engine.configure([self.rule("request", url, invalid)])
        future = self.pool.submit(self.request, url)
        paused = self.paused(url, "request")
        self.assertEqual(paused["pause_timeout_seconds"], 60)
        self.assertAlmostEqual(paused["pause_deadline"] - paused["started"], 60, delta=0.6)
        self.engine.command("resume", id=paused["id"], action="abort")
        self.assert_client_aborted(future)

    def test_continue_cancels_each_stage_deadline_without_late_abort(self):
        url = self.base + "/continue-deadline"
        self.engine.configure([self.rule("request", url, 1), self.rule("response", url, 3)])
        future = self.pool.submit(self.request, url)
        request = self.paused(url, "request")
        after_continue = len(self.engine.events)
        self.engine.command("resume", id=request["id"], action="continue", request_body="edited request")
        response = self.paused(url, "response", after_continue)
        self.assertEqual(response["id"], request["id"])
        # The request's old 1s callback must not abort the later 3s response pause.
        time.sleep(1.15)
        _, detail = self.engine.command("detail", id=response["id"])
        self.assertEqual(detail["state"], "paused")
        self.assertEqual(detail["pause_stage"], "response")
        self.assertFalse(future.done())
        self.engine.command("resume", id=response["id"], action="continue", response_body="edited response")
        self.assertEqual(future.result(timeout=3).content, b"edited response")
        # Wait beyond the second callback's original deadline; completed traffic stays completed.
        time.sleep(max(0, response["pause_deadline"] - time.time()) + 0.15)
        self.assert_no_late_error(url, after_continue)
        _, detail = self.engine.command("detail", id=response["id"])
        self.assertEqual(detail["state"], "complete")
        self.assertIsNone(detail["pause_deadline"])

    def test_explicit_abort_cancels_timer_at_both_stages(self):
        for side in ("request", "response"):
            with self.subTest(side=side):
                url = self.base + "/manual-abort-" + side
                self.engine.configure([self.rule(side, url, 1)])
                future = self.pool.submit(self.request, url)
                paused = self.paused(url, side)
                self.engine.command("resume", id=paused["id"], action="abort")
                self.assert_client_aborted(future)
                time.sleep(1.1)
                _, detail = self.engine.command("detail", id=paused["id"])
                self.assertNotIn("timed out", detail["error"])
                self.assertIsNone(detail["pause_deadline"])

    def test_clear_releases_both_stages_and_prevents_reinterception_or_resurrection(self):
        for side in ("request", "response"):
            with self.subTest(side=side):
                url = self.base + "/clear-deadline-" + side
                # Clear must also suppress later matching breakpoints on this flow.
                self.engine.configure([self.rule(side, url, 1), self.rule("response", url, 1)])
                future = self.pool.submit(self.request, url)
                self.paused(url, side)
                self.engine.command("clear")
                cleared = len(self.engine.events)
                self.assertEqual(future.result(timeout=3).status_code, 200)
                time.sleep(1.1)
                _, har = self.engine.command("export_har")
                self.assertEqual(har["log"]["entries"], [])
                self.assertFalse(any(event.get("event") == "flow" and event["flow"]["url"] == url
                                     for event in self.engine.events[cleared:]))

    def test_request_stage_is_explicit_even_if_map_local_already_created_response(self):
        url = self.base + "/local-before-request-deadline"
        path = Path(self.temporary.name) / "mapped.txt"
        path.write_text("local response")
        mapping = {"kind": "map_local", "match": url, "name": "", "value": str(path)}
        self.engine.configure([mapping, self.rule("request", url, 1)])
        future = self.pool.submit(self.request, url)
        paused = self.paused(url, "request")
        self.assertEqual(paused["status"], 200)
        self.assertEqual(paused["pause_stage"], "request")
        self.assert_client_aborted(future)
        self.assertIn("Request breakpoint timed out", self.engine.flow(url, state="error")["error"])

    def test_shutdown_cancels_paused_waits_and_closes_listener_without_pending_tasks(self):
        # Each stage gets its own owned process so shutdown is the real finalizer.
        for side in ("request", "response"):
            with self.subTest(side=side):
                if self.engine.process.poll() is not None:
                    self.engine.close()
                    self.temporary.cleanup()
                    self.temporary = tempfile.TemporaryDirectory(prefix="lens-deadline-shutdown-")
                    self.addCleanup(self.temporary.cleanup)
                    self.engine = EngineHarness(Path(self.temporary.name), self.ca)
                    self.addCleanup(self.engine.close)
                url = self.base + "/shutdown-deadline-" + side
                self.engine.configure([self.rule(side, url, 60)])
                future = self.pool.submit(self.request, url)
                self.paused(url, side)
                port = self.engine.port
                self.engine.command("shutdown")
                self.engine.process.wait(timeout=4)
                self.assertEqual(self.engine.process.returncode, 0)
                self.assert_client_aborted(future)
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", port), timeout=0.2)
                self.engine.stderr.flush()
                self.engine.stderr.seek(0)
                stderr = self.engine.stderr.read()
                for warning in ("Task was destroyed", "exception was never retrieved", "Traceback"):
                    self.assertNotIn(warning, stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
