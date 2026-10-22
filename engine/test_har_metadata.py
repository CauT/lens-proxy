"""Distinct persistence semantics not reliably forced by network scheduling."""
import copy
import contextlib
import io
import math
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from mitmproxy.flow import Error
from mitmproxy.test import tflow
from har import export_flow, import_entry, snapshot_flow
from har_metadata import flow_duration, flow_state
from persistence import prepare_import, save_snapshot, load_snapshot
from engine import Lens, summary
from bounds import metadata_size


def captured():
    flow = tflow.tflow(resp=True, live=False)
    flow.request.timestamp_start = 0.0
    flow.request.timestamp_end = 0.125
    flow.response.timestamp_start = 0.75
    flow.response.timestamp_end = 1.0
    flow.server_conn.timestamp_start = -0.1
    flow.server_conn.timestamp_tcp_setup = -0.05
    flow.server_conn.timestamp_tls_setup = 0.0
    return flow


class HARMetadata(unittest.TestCase):
    def test_epoch_zero_and_actual_phase_boundaries_survive_atomic_file_roundtrip(self):
        flow = captured()
        entry = export_flow(flow)
        self.assertEqual(entry["time"], 1000)
        self.assertEqual({k: entry["timings"][k] for k in ("send", "wait", "receive")},
                         {"send": 125, "wait": 625, "receive": 250})
        self.assertEqual(entry["_lensTiming"]["serverConnection"]["timestamp_tls_setup"], 0)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "session.har"
            save_snapshot(path, [flow])
            restored = load_snapshot(path, 2000, 256 * 1024 * 1024)[0]
        self.assertEqual(restored.request.timestamp_start, 0)
        self.assertEqual(restored.request.timestamp_end, 0.125)
        self.assertEqual(restored.response.timestamp_start, 0.75)
        self.assertEqual(restored.response.timestamp_end, 1.0)
        self.assertEqual(restored.server_conn.timestamp_tls_setup, 0)
        self.assertEqual(export_flow(restored), entry)

    def test_unknown_real_zero_and_overlap_remain_distinct(self):
        flow = captured()
        flow.request.timestamp_end = None
        missing = export_flow(flow)
        self.assertEqual(missing["timings"]["send"], -1)
        self.assertEqual(missing["timings"]["wait"], -1)
        flow.request.timestamp_end = 0
        self.assertEqual(export_flow(flow)["timings"]["send"], 0)
        flow.request.timestamp_end = 0.9
        overlap = export_flow(flow)
        self.assertEqual(overlap["timings"]["wait"], -1)
        self.assertIn("overlap", overlap["_lensTiming"]["issues"][0])
        self.assertEqual(export_flow(import_entry(overlap)), overlap)

    def test_pending_and_failed_have_no_invented_success_boundary(self):
        pending = captured()
        pending.live = True
        pending.metadata["lens_response_complete"] = False
        entry = export_flow(pending)
        self.assertEqual(entry["time"], -1)
        self.assertIsNone(flow_duration(pending))
        self.assertEqual(flow_state(import_entry(entry)), "pending")
        self.assertEqual(export_flow(import_entry(entry)), entry)
        self.assertEqual(export_flow(snapshot_flow(pending)), entry,
                         "copy() clearing live must not promote a pending response to complete")
        failed = captured()
        failed.response = None
        failed.error = Error("origin failed", timestamp=0.5)
        failed.metadata["lens_breakpoint_error"] = "Request breakpoint timed out after 1s"
        entry = export_flow(failed)
        self.assertEqual(entry["time"], 500)
        self.assertEqual(entry["timings"]["wait"], -1)
        restored = import_entry(entry)
        self.assertEqual(restored.error.timestamp, 0.5)
        self.assertEqual(flow_state(restored), "error")
        self.assertEqual(flow_duration(restored), 500)
        self.assertEqual(export_flow(restored), entry)
        self.assertEqual(summary(restored)["duration_ms"], 500)

    def test_external_source_times_cookies_omissions_and_extra_fields_survive(self):
        entry = export_flow(captured())
        del entry["_lensTiming"]
        entry["startedDateTime"] = "2020-01-02T03:04:05.123456+08:00"
        entry["time"] = 15.5
        entry["timings"] = {"wait": -1, "ssl": -1, "receive": 0, "comment": "original uncertainty", "_producer": "source"}
        entry["connection"] = "shared-source-connection"
        entry["request"]["cookies"] = [{"name": "source", "value": "not-in-headers", "sameSite": "Lax", "_source": "HAR"}]
        entry["request"]["headers"].append({"name": "Cookie", "value": "header=independent"})
        del entry["response"]["cookies"]
        restored = import_entry(entry)
        self.assertIsNone(restored.request.timestamp_end)
        self.assertEqual(export_flow(restored), entry)
        self.assertEqual(flow_duration(restored), 15.5)
        self.assertGreater(restored.metadata["lens_har_metadata_bytes"], 0)

    def test_cookie_duplicates_attributes_and_malformed_dates_are_source_preserving(self):
        flow = captured()
        flow.request.headers.add("Cookie", "a=1; a=2; value=%2B+raw")
        flow.request.headers.add("Cookie", "other=3")
        flow.response.headers.add("Set-Cookie", "a=1; Path=/one; Path=/two; Domain=.example.test; HttpOnly; Secure; SameSite=Lax; Max-Age=60; Expires=Wed, 09 Jun 2038 10:18:14 GMT")
        flow.response.headers.add("Set-Cookie", "a=2; Expires=not-a-date; Priority=High")
        entry = export_flow(flow)
        self.assertEqual(entry["request"]["cookies"], [
            {"name": "a", "value": "1"}, {"name": "a", "value": "2"},
            {"name": "value", "value": "%2B+raw"}, {"name": "other", "value": "3"}])
        first, second = entry["response"]["cookies"]
        self.assertEqual((first["path"], first["domain"], first["httpOnly"], first["secure"], first["_sameSite"]),
                         ("/two", ".example.test", True, True, "Lax"))
        self.assertEqual(first["expires"], "2038-06-09T10:18:14+00:00")
        self.assertEqual([a["value"] for a in first["_lensAttributes"] if a["name"].lower() == "path"], ["/one", "/two"])
        self.assertNotIn("path", second)
        self.assertNotIn("domain", second)
        self.assertNotIn("expires", second)
        self.assertTrue(second["_lensCookieIssues"])
        restored = import_entry(entry)
        self.assertEqual(restored.response.headers.get_all("Set-Cookie"), flow.response.headers.get_all("Set-Cookie"))
        self.assertEqual(export_flow(restored), entry)

    def test_all_retained_route_and_failure_metadata_participates_in_cost(self):
        flow = captured()
        flow.error = Error("", timestamp=0.5)
        entry = export_flow(flow)
        baseline = import_entry(entry)
        self.assertEqual(baseline.error.msg, "")
        entry["_lensBreakpointError"] = "x" * 10000
        entry["_lensOriginalUrl"] = "https://example.test/" + "y" * 10000
        expanded = import_entry(entry)
        self.assertGreaterEqual(expanded.metadata["lens_har_metadata_bytes"] - baseline.metadata["lens_har_metadata_bytes"], 20000)

    def test_missing_body_is_not_empty_and_source_sizes_mime_and_parameters_survive(self):
        entry = export_flow(captured())
        entry.pop("_lensTiming")
        for field in ("_lensRawRequestBody", "_lensRawResponseBody"):
            entry.pop(field)
        entry["request"]["bodySize"] = -1
        entry["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                                        "params": [{"name": "source", "value": "not reconstructed"}]}
        entry["response"]["content"] = {"size": 9000, "mimeType": "image/png", "comment": "body not recorded"}
        entry["response"]["bodySize"] = 9000
        entry["response"]["headersSize"] = -1
        restored = import_entry(entry)
        self.assertIsNone(restored.request.raw_content)
        self.assertIsNone(restored.response.raw_content)
        exported = export_flow(restored)
        self.assertNotIn("_lensRawRequestBody", exported)
        self.assertNotIn("_lensRawResponseBody", exported)
        self.assertEqual(exported, entry)
        empty = copy.deepcopy(entry)
        empty["request"]["bodySize"] = 0
        empty["request"].pop("postData")
        self.assertEqual(import_entry(empty).request.raw_content, b"", "explicit zero is known empty")

    def test_metadata_budget_counts_large_integers_without_decimal_allocation(self):
        value = 10 ** 4000
        self.assertGreaterEqual(metadata_size(value, 10000), 4001)
        with self.assertRaisesRegex(ValueError, "budget"):
            metadata_size([value, value], 5000)

    def test_browser_page_reference_stays_source_evidence_without_dangling_edge(self):
        entry = export_flow(captured())
        entry["pageref"] = "page-from-source-file"
        result = export_flow(import_entry(entry))
        self.assertNotIn("pageref", result)
        self.assertEqual(result["_lensSourcePageRef"], entry["pageref"])
        self.assertEqual(export_flow(import_entry(result)), result)

    def test_surrogateescaped_http_header_bytes_save_and_restore_exactly(self):
        flow = captured()
        flow.response.headers.fields += ((b"X-Observed", b"\xff\xfe"),)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "raw-headers.har"
            save_snapshot(path, [flow])
            restored = load_snapshot(path, 2000, 256 * 1024 * 1024)[0]
        self.assertEqual(restored.response.headers.fields, flow.response.headers.fields)

    def test_bad_boundary_values_fail_before_any_existing_file_is_replaced(self):
        original = export_flow(captured())
        changes = [("time", float("nan")), ("time", True), ("time", -0.5),
                   ("startedDateTime", "2020-01-01T00:00:00"),
                   ("timings", {"send": "0"}), ("timings", {"receive": -2})]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(original)
                bad[key] = value
                with self.assertRaises(ValueError):
                    prepare_import({"log": {"entries": [original, bad]}}, 2000, 256 * 1024 * 1024)
        flow = captured()
        flow.request.timestamp_end = math.inf
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "session.har"
            path.write_text("previous saved data")
            with self.assertRaises(ValueError):
                save_snapshot(path, [flow])
            self.assertEqual(path.read_text(), "previous saved data")
            self.assertEqual(list(Path(folder).iterdir()), [path])


class HARMetadataRetention(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_import_retains_source_metadata_within_shared_store_budget(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            master = Mock()
            master.addons.get.return_value = None
            lens = Lens(master, Path(folder), 8890)
            self.addAsyncCleanup(lens.close)
            entry = export_flow(captured())
            entry["timings"]["_sourceComment"] = "x" * 8192
            sample = import_entry(entry)
            body_bytes = len(sample.request.raw_content or b"") + len(sample.response.raw_content or b"")
            budget = body_bytes + sample.metadata["lens_har_metadata_bytes"]
            self.assertGreater(budget, 8192)
            with patch("engine.MAX_STORED_BYTES", budget + budget // 2):
                await lens.command({"command": "import_har", "har": {"log": {"entries": [entry]}}})
                first = next(iter(lens.flows))
                await lens.command({"command": "import_har", "har": {"log": {"entries": [entry]}}})
                self.assertEqual(len(lens.flows), 1)
                self.assertNotIn(first, lens.flows, "oldest source metadata must participate in eviction")


if __name__ == "__main__":
    unittest.main(verbosity=2)
