"""Real HAR import -> engine controls -> loopback delivery: unavailable != empty."""
import base64
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from test_e2e import EngineHarness, certificate_fixture, start_fixture


class UnavailableBodyAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lens-unavailable-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        ca, _, _ = certificate_fixture(cls.directory, "unavailable")
        cls.server, _ = start_fixture("unavailable")
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.engine = EngineHarness(cls.directory, ca)
        cls.addClassCleanup(cls.engine.close)

    def setUp(self):
        self.engine.configure([])
        self.engine.command("clear")

    def entry(self, path):
        return {"startedDateTime": datetime.now(timezone.utc).isoformat(), "time": 12,
                "timings": {"send": 0, "wait": 12, "receive": 0},
                "request": {"method": "POST", "url": self.base + path, "httpVersion": "HTTP/1.1",
                            "headers": [], "headersSize": -1, "bodySize": -1,
                            "postData": {"mimeType": "application/json"}},
                "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                             "headers": [], "headersSize": -1, "bodySize": 9000,
                             "content": {"size": 9000, "mimeType": "image/png"}}}

    def import_flow(self, entry):
        after = len(self.engine.events)
        self.engine.command("import_har", har={"log": {"entries": [entry]}})
        return self.engine.flow(entry["request"]["url"], after=after)

    def test_unavailable_controls_fail_without_sending_and_har_omission_survives(self):
        entry = self.entry("/unavailable-captured")
        imported = self.import_flow(entry)
        self.assertFalse(imported["request_body_available"])
        self.assertFalse(imported["response_body_available"])
        _, detail = self.engine.command("detail", id=imported["id"])
        self.assertFalse(detail["request_body_available"])
        self.assertFalse(detail["response_body_available"])
        self.assertIsNone(detail["request_body_base64"])
        self.assertIsNone(detail["response_body_base64"])
        for side in ("request", "response"):
            with self.assertRaisesRegex(AssertionError, "body is unavailable"):
                self.engine.command("export_body", id=imported["id"], side=side)
        for name in ("replay", "repeat"):
            with self.assertRaisesRegex(AssertionError, "request body is unavailable"):
                self.engine.command(name, id=imported["id"])
        with self.server.history_lock:
            self.assertFalse(any(item["path"] == "/unavailable-captured" for item in self.server.history))
        _, exported = self.engine.command("export_har")
        saved = exported["log"]["entries"][0]
        self.assertEqual(saved["request"]["postData"], entry["request"]["postData"])
        self.assertEqual(saved["response"]["content"], entry["response"]["content"])
        self.assertNotIn("_lensRawRequestBody", saved)
        self.assertNotIn("_lensRawResponseBody", saved)
        path = self.directory / "unavailable.har"
        self.engine.command("save_har", path=str(path))
        self.engine.command("clear")
        after = len(self.engine.events)
        self.engine.command("load_har", path=str(path))
        reloaded = self.engine.flow(entry["request"]["url"], after=after)
        self.assertFalse(reloaded["request_body_available"])
        self.assertFalse(reloaded["response_body_available"])

    def test_known_empty_has_available_bytes_and_can_replay_or_export(self):
        entry = self.entry("/known-empty")
        entry["request"]["bodySize"] = 0
        entry["response"]["bodySize"] = 0
        entry["response"]["content"] = {"size": 0, "mimeType": "text/plain"}
        imported = self.import_flow(entry)
        self.assertTrue(imported["request_body_available"])
        self.assertTrue(imported["response_body_available"])
        for side in ("request", "response"):
            _, value = self.engine.command("export_body", id=imported["id"], side=side)
            self.assertEqual(base64.b64decode(value["base64"]), b"")
        after = len(self.engine.events)
        command_id, _ = self.engine.command("replay", id=imported["id"])
        self.engine.wait(lambda event: event.get("event") == "request_finished"
                         and event.get("command_id") == command_id, after=after)
        replay = self.engine.flow(entry["request"]["url"], after=after)
        self.assertTrue(replay["request_body_available"])
        self.assertTrue(replay["replayed"])
        with self.server.history_lock:
            request = next(item for item in self.server.history if item["path"] == "/known-empty")
        self.assertEqual(base64.b64decode(request["body"]), b"")

    def test_explicit_compose_replacement_including_empty_is_delivered(self):
        entry = self.entry("/explicit-replacement")
        imported = self.import_flow(entry)
        self.assertFalse(imported["request_body_available"])
        for replacement in ("explicit UTF-8 replacement", ""):
            with self.subTest(replacement=replacement):
                after = len(self.engine.events)
                command_id, _ = self.engine.command("compose", method="POST", url=entry["request"]["url"], headers=[], body=replacement)
                self.engine.wait(lambda event: event.get("event") == "request_finished"
                                 and event.get("command_id") == command_id, after=after)
                created = self.engine.flow(entry["request"]["url"], after=after)
                self.assertTrue(created["request_body_available"])
                _, detail = self.engine.command("detail", id=created["id"])
                self.assertEqual(base64.b64decode(detail["request_body_base64"]), replacement.encode())
        with self.server.history_lock:
            delivered = [base64.b64decode(item["body"]) for item in self.server.history
                         if item["path"] == "/explicit-replacement"]
        self.assertEqual(delivered, [b"explicit UTF-8 replacement", b""])


if __name__ == "__main__":
    unittest.main(verbosity=2)
