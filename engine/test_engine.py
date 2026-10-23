"""Semantic boundary tests use actual mitmproxy flows, not a fake provider."""
import asyncio
import base64
import contextlib
import io
import gzip
import os
from pathlib import Path
import re
import tempfile
import json
import threading
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from OpenSSL import SSL
from mitmproxy import http
from mitmproxy.test import tflow
from engine import BODY_DISPLAY_LIMIT, Lens, body_text, ssl_ignore_pattern, summary
from har import export_flow, import_entry
from bounds import ImportBudget, decoded_bytes
from persistence import prepare_import, save_snapshot, load_snapshot


class Conversions(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX named pipes")
    def test_har_named_pipe_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.har"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_snapshot(path, 2000, 256 * 1024 * 1024)

    def test_ssl_selection_does_not_decrypt_unselected_hosts(self):
        regex = re.compile(ssl_ignore_pattern("*.example.com,localhost")[0])
        self.assertIsNone(regex.search("api.example.com:443"))
        self.assertIsNone(regex.search("localhost:8443"))
        self.assertIsNotNone(regex.search("example.net:443"))
        self.assertIsNotNone(regex.search("api.example.com.evil.net:443"))
        self.assertEqual(ssl_ignore_pattern("*"), [])

    def test_full_binary_har_survives_roundtrip_and_duplicate_headers(self):
        flow = tflow.tflow(resp=True)
        flow.request.raw_content = b"\x00\xffrequest"
        flow.response.raw_content = b"\x00\xffresponse"
        flow.response.headers.add("Set-Cookie", "a=1")
        flow.response.headers.add("Set-Cookie", "b=2")
        restored = import_entry(export_flow(flow))
        self.assertEqual(restored.request.raw_content, flow.request.raw_content)
        self.assertEqual(restored.response.raw_content, flow.response.raw_content)
        self.assertEqual(restored.response.headers.get_all("Set-Cookie"), ["a=1", "b=2"])

    def test_gzip_har_exports_readable_text_and_restores_exact_wire_bytes(self):
        flow = tflow.tflow(resp=True)
        for message, text in ((flow.request, b"request compressed text"),
                              (flow.response, b"response compressed text")):
            message.headers["Content-Encoding"] = "gzip"
            message.raw_content = gzip.compress(text, mtime=123)
            message.headers["Content-Length"] = str(len(message.raw_content))
        exported = export_flow(flow)
        self.assertEqual(exported["request"]["postData"]["text"], "request compressed text")
        self.assertNotIn("encoding", exported["request"]["postData"])
        self.assertEqual(exported["response"]["content"]["text"], "response compressed text")
        self.assertEqual(exported["response"]["content"]["size"], len(b"response compressed text"))
        restored = import_entry(exported)
        self.assertEqual(restored.request.raw_content, flow.request.raw_content)
        self.assertEqual(restored.response.raw_content, flow.response.raw_content)
        self.assertEqual(restored.response.headers.fields, flow.response.headers.fields)

    def test_external_decoded_har_reencodes_content_and_repairs_framing(self):
        exported = export_flow(tflow.tflow(resp=True))
        del exported["_lensRawRequestBody"]
        del exported["_lensRawResponseBody"]
        for section, body_key in (("request", "postData"), ("response", "content")):
            exported[section][body_key] = {"text": "decoded external text"}
            exported[section]["headers"] = [{"name": "Content-Encoding", "value": "gzip"},
                                            {"name": "Content-Length", "value": "999"},
                                            {"name": "Set-Cookie", "value": "a=1"},
                                            {"name": "Set-Cookie", "value": "b=2"}]
        restored = import_entry(exported)
        for message in (restored.request, restored.response):
            self.assertEqual(gzip.decompress(message.raw_content), b"decoded external text")
            self.assertEqual(int(message.headers["Content-Length"]), len(message.raw_content))
            self.assertEqual(message.headers.get_all("Set-Cookie"), ["a=1", "b=2"])

    def test_binary_har_standard_response_and_websocket_roundtrip(self):
        flow = tflow.tflow(resp=True, ws=True)
        flow.response.content = b"\xff\x00binary"
        exported = export_flow(flow)
        self.assertEqual(exported["response"]["content"]["encoding"], "base64")
        self.assertEqual(base64.b64decode(exported["response"]["content"]["text"]), b"\xff\x00binary")
        restored = import_entry(exported)
        self.assertEqual([m.content for m in restored.websocket.messages],
                         [m.content for m in flow.websocket.messages])

    def test_har_base64_size_rejects_before_decoding_allocation(self):
        entry = export_flow(tflow.tflow(resp=True))
        entry["_lensRawRequestBody"] = base64.b64encode(b"a" * 1025).decode()
        with patch("bounds.base64.b64decode", side_effect=AssertionError("must not allocate decoded bytes")):
            with self.assertRaisesRegex(ValueError, "before base64 allocation"):
                ImportBudget(1, 4096, max_body_bytes=1024).prepare(entry)

    def test_har_utf8_expansion_and_cumulative_entries_reject_before_import(self):
        entry = export_flow(tflow.tflow(resp=True))
        entry.pop("_lensRawRequestBody")
        entry["request"]["postData"] = {"text": "\u754c" * 400}
        with self.assertRaisesRegex(ValueError, "byte budget"):
            ImportBudget(1, 4096, max_body_bytes=1024).prepare(entry)
        first = export_flow(tflow.tflow(resp=True))
        first["_lensRawRequestBody"] = base64.b64encode(b"x" * 700).decode()
        first["request"]["postData"] = {"text": "x" * 700}
        first["_lensRawResponseBody"] = ""
        first["response"]["content"] = {"text": ""}
        budget = ImportBudget(2, 1024, max_body_bytes=1024)
        budget.prepare(first)
        with self.assertRaisesRegex(ValueError, "budget"):
            budget.prepare(first)

    def test_compressed_bombs_have_bounded_output_including_raw_extensions(self):
        plain = b"a" * 4096
        encodings = [("gzip", gzip.compress(plain))]
        import brotli, zlib, zstandard
        encodings.extend([("deflate", zlib.compress(plain)), ("br", brotli.compress(plain)),
                          ("zstd", zstandard.ZstdCompressor().compress(plain))])
        for encoding, raw in encodings:
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
                    decoded_bytes(raw, encoding, limit=1024)
        entry = export_flow(tflow.tflow(resp=True))
        entry["_lensRawRequestBody"] = base64.b64encode(gzip.compress(plain)).decode()
        entry["request"]["postData"] = {"text": ""}
        entry["request"]["headers"] = [{"name": "Content-Encoding", "value": "gzip"}]
        with self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
            ImportBudget(1, 4096, max_body_bytes=1024).prepare(entry)

    def test_gzip_concatenated_members_share_one_output_budget(self):
        combined = gzip.compress(b"first ") + gzip.compress(b"second")
        self.assertEqual(decoded_bytes(combined, "gzip", 1024), b"first second")
        late_bomb = gzip.compress(b"small") + gzip.compress(b"x" * 4096)
        with self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
            decoded_bytes(late_bomb, "gzip", 1024)

    def test_zstd_declared_large_window_is_rejected_even_for_tiny_output(self):
        import zstandard
        small = zstandard.ZstdCompressor(write_content_size=False).compress(b"abc")
        self.assertEqual(small[4], 0, "fixture must have a separate window descriptor")
        large_window = small[:5] + b"\x80" + small[6:]
        self.assertEqual(zstandard.get_frame_parameters(large_window).window_size, 64 * 1024 * 1024)
        self.assertEqual(decoded_bytes(small, "zstd"), b"abc")
        with self.assertRaisesRegex(ValueError, "window budget"):
            decoded_bytes(large_window, "zstd")

    def test_zstd_streaming_windows_share_byte_and_output_limits_across_frames(self):
        import zstandard
        small = zstandard.ZstdCompressor(write_content_size=False).compress(b"abc")
        streaming = small[:5] + b"\x60" + small[6:]
        self.assertEqual(zstandard.get_frame_parameters(streaming).window_size, 4 * 1024 * 1024)
        large_window = small[:5] + b"\x80" + small[6:]
        expanded = zstandard.ZstdCompressor(write_content_size=False).compress(b"a" * 4096)
        expanded = expanded[:5] + b"\x60" + expanded[6:]
        for strict in (False, True):
            with self.subTest(strict=strict):
                self.assertEqual(decoded_bytes(streaming, "zstd", strict=strict), b"abc")
                self.assertEqual(decoded_bytes(streaming + streaming, "zstd", strict=strict), b"abcabc")
                with self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
                    decoded_bytes(streaming + expanded, "zstd", limit=1024, strict=strict)
                with self.assertRaisesRegex(ValueError, "window budget"):
                    decoded_bytes(streaming + large_window, "zstd", strict=strict)

    def test_har_metadata_and_file_budget_reject_before_parser_or_replacement(self):
        entry = export_flow(tflow.tflow(resp=True))
        entry["comment"] = "metadata" * 100
        with patch("bounds.METADATA_BYTES", 256):
            with self.assertRaisesRegex(ValueError, "metadata"):
                ImportBudget(1, 4096).prepare(entry)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.har"
            path.write_bytes(b"previous target")
            with patch("persistence.HAR_FILE_BYTES", 16):
                with self.assertRaisesRegex(ValueError, "file budget"):
                    save_snapshot(path, [tflow.tflow(resp=True)])
            self.assertEqual(path.read_bytes(), b"previous target")
            self.assertEqual(list(Path(directory).iterdir()), [path])
            path.write_bytes(b" " * 65)
            with patch("persistence.HAR_FILE_BYTES", 64), patch("persistence.json.loads", side_effect=AssertionError("must not parse")):
                with self.assertRaisesRegex(ValueError, "before parsing"):
                    load_snapshot(path, 2000, 4096)

    def test_display_cap_does_not_truncate_stored_body(self):
        response = http.Response.make(200, b"a" * (BODY_DISPLAY_LIMIT + 1))
        text, truncated = body_text(response)
        self.assertTrue(truncated)
        self.assertEqual(len(text), BODY_DISPLAY_LIMIT)
        self.assertEqual(len(response.raw_content), BODY_DISPLAY_LIMIT + 1)


class Rules(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.master = Mock()
        self.master.addons.get.return_value = None
        self.lens = Lens(self.master, Path("/tmp"), 8890)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    async def asyncTearDown(self):
        await self.lens.close()
        self.output.__exit__(None, None, None)

    async def configure(self, *rules):
        await self.lens.command({"command": "configure", "rules": [dict(enabled=True, match="*", **r) for r in rules]})

    async def test_response_rewrite_and_header_update(self):
        await self.configure({"kind": "rewrite_response_body", "name": "old", "value": "new"},
                             {"kind": "rewrite_response_header", "name": "X-Lens", "value": "yes"})
        flow = tflow.tflow(resp=True)
        flow.response.content = b"old old"
        await self.lens.request(flow)
        await self.lens.response(flow)
        self.assertEqual(flow.response.content, b"new new")
        self.assertEqual(flow.response.headers["X-Lens"], "yes")
        self.assertEqual(flow.response.headers["Content-Length"], "7")

    async def test_recording_off_still_applies_rules(self):
        await self.lens.command({"command": "recording", "enabled": False})
        await self.configure({"kind": "block"})
        flow = tflow.tflow()
        await self.lens.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertNotIn(flow.id, self.lens.flows)

    async def test_recording_decision_stays_with_request_start(self):
        await self.lens.command({"command": "recording", "enabled": False})
        flow = tflow.tflow()
        await self.lens.request(flow)
        await self.lens.command({"command": "recording", "enabled": True})
        flow.response = http.Response.make(200, b"done")
        await self.lens.response(flow)
        self.assertNotIn(flow.id, self.lens.flows)

    async def test_clear_does_not_resurrect_pending_captures(self):
        flow = tflow.tflow()
        await self.lens.request(flow)
        await self.lens.command({"command": "clear"})
        flow.response = http.Response.make(200, b"done")
        await self.lens.response(flow)
        self.assertNotIn(flow.id, self.lens.flows)

    async def test_breakpoint_waits_and_can_be_edited_and_resumed(self):
        await self.configure({"kind": "breakpoint_request"})
        flow = tflow.tflow(live=True)
        pending = asyncio.create_task(self.lens.request(flow))
        await asyncio.sleep(0)
        self.assertFalse(pending.done())
        self.assertTrue(flow.intercepted)
        await self.lens.command({"command": "resume", "id": flow.id, "action": "continue", "request_body": "edited"})
        await asyncio.wait_for(pending, 1)
        self.assertEqual(flow.request.content, b"edited")
        self.assertFalse(flow.intercepted)

    async def test_live_response_completes_only_after_all_response_rules(self):
        await self.configure({"kind": "breakpoint_response"}, {"kind": "breakpoint_response"},
                             {"kind": "rewrite_response_body", "name": "old", "value": "final"})
        flow = tflow.tflow(resp=True, live=True)
        await self.lens.request(flow)
        flow.response.content = b"old"
        self.assertEqual(summary(flow)["state"], "pending", "response presence is not finalization")
        pending = asyncio.create_task(self.lens.response(flow))
        await asyncio.sleep(0)
        self.assertTrue(flow.intercepted)
        for index in range(2):
            await self.lens.command({"command": "resume", "id": flow.id, "action": "continue"})
            self.assertEqual(summary(flow)["state"], "pending", "resume must not publish a final response")
            await asyncio.sleep(0)
            if index == 0:
                self.assertTrue(flow.intercepted)
                self.assertEqual(summary(flow)["state"], "paused")
        await asyncio.wait_for(pending, 1)
        self.assertEqual(summary(flow)["state"], "complete")
        self.assertEqual(flow.response.content, b"final")
        self.assertEqual(summary(tflow.tflow(resp=True, live=False))["state"], "complete")

    async def test_abort_wakes_both_request_and_response_breakpoints(self):
        for side in ("request", "response"):
            await self.configure({"kind": "breakpoint_" + side})
            flow = tflow.tflow(resp=side == "response", live=True)
            if side == "response":
                await self.lens.request(flow)
            pending = asyncio.create_task(getattr(self.lens, side)(flow))
            await asyncio.sleep(0)
            self.assertTrue(flow.intercepted)
            await self.lens.command({"command": "resume", "id": flow.id, "action": "abort"})
            await asyncio.wait_for(pending, 1)
            self.assertIsNotNone(flow.error)
            self.assertFalse(flow.live)

    async def test_lazy_tls_h2_preference_is_per_connection_and_preserves_choices(self):
        context = SSL.Context(SSL.TLS_METHOD)
        for offered, client_choice, upstream, expected in (
                ([b"http/1.1", b"h2"], None, None, b"h2"),
                ([b"http/1.1"], None, None, None),
                ([b"http/1.1", b"h2"], b"http/1.1", None, b"http/1.1"),
                ([b"http/1.1", b"h2"], None, b"http/1.1", None)):
            conn = SSL.Connection(context)
            conn.set_app_data({"http2": True, "client_alpn": client_choice, "server_alpn": upstream})
            data = SimpleNamespace(ssl_conn=conn, is_dtls=False, conn=SimpleNamespace(alpn_offers=offered))
            self.lens.tls_start_client(data)
            self.assertEqual(conn.get_app_data()["client_alpn"], expected)
            other = SSL.Connection(context)
            self.assertIsNone(other.get_app_data(), "policy must not leak via the shared SSL Context")

    async def test_tls_policy_shape_drift_fails_handshake_explicitly(self):
        conn = SSL.Connection(SSL.Context(SSL.TLS_METHOD))
        conn.set_app_data({"unexpected": True})
        data = SimpleNamespace(ssl_conn=conn, is_dtls=False, conn=SimpleNamespace(alpn_offers=[b"h2"]))
        with self.assertRaisesRegex(RuntimeError, "requires mitmproxy 12.2.1"):
            self.lens.tls_start_client(data)
        self.assertIsNone(data.ssl_conn)

    async def test_export_body_retains_full_binary_and_compressed_wire_choices(self):
        flow = tflow.tflow(resp=True)
        binary = b"\xff\x00" * (BODY_DISPLAY_LIMIT // 2 + 5)
        flow.response.headers["Content-Encoding"] = "gzip"
        flow.response.content = binary
        self.lens.flows[flow.id] = flow
        result = await self.lens.command({"command": "export_body", "id": flow.id, "side": "response"})
        self.assertEqual(base64.b64decode(result["base64"]), binary)
        self.assertEqual(result["bytes"], len(binary))
        result = await self.lens.command({"command": "export_body", "id": flow.id, "side": "response", "decoded": False})
        self.assertEqual(base64.b64decode(result["base64"]), flow.response.raw_content)
        with self.assertRaises(ValueError):
            await self.lens.command({"command": "export_body", "id": flow.id, "side": "anything"})

    async def test_rule_provenance_survives_har_file_roundtrip_and_absence_stays_unknown(self):
        await self.configure({"kind": "map_remote", "value": "https://mapped.test:8443/base"},
                             {"kind": "dns_spoof", "value": "127.0.0.1"})
        flow = tflow.tflow()
        flow.request.url = "https://original.test/feature?q=1"
        await self.lens.request(flow)
        # A fixture dial fact exercises persistence independently of the network
        # tests, which establish actual Host/SNI and socket-routing behavior.
        flow.metadata["lens_dns_dial_address"] = ["127.0.0.1", 8443]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.har"
            await self.lens.command({"command": "save_har", "path": str(path)})
            self.lens.flows.clear()
            await self.lens.command({"command": "load_har", "path": str(path)})
        restored = summary(next(iter(self.lens.flows.values())))
        self.assertEqual(restored["original_url"], "https://original.test/feature?q=1")
        self.assertEqual(restored["effective_url"], "https://mapped.test:8443/base/feature?q=1")
        self.assertEqual(restored["dns_address"], "127.0.0.1")
        self.assertEqual(restored["dns_dial_address"], ["127.0.0.1", 8443])
        self.assertTrue(restored["imported"])
        external = summary(import_entry(export_flow(tflow.tflow(resp=True))))
        self.assertIsNone(external["original_url"])
        self.assertIsNone(external["dns_address"])
        self.assertIsNone(external["dns_dial_address"])

    async def test_har_file_roundtrip_preserves_complete_binary_and_headers(self):
        flow = tflow.tflow(resp=True)
        flow.request.raw_content = b"\xff\x00request"
        flow.response.headers["Content-Encoding"] = "gzip"
        flow.response.content = b"complete response" * 100
        flow.response.headers.add("Set-Cookie", "a=1")
        flow.response.headers.add("Set-Cookie", "b=2")
        self.lens.flows[flow.id] = flow
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selected.har"
            saved = await self.lens.command({"command": "save_har", "path": str(path)})
            self.assertEqual(saved["entries"], 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.lens.flows.clear()
            loaded = await self.lens.command({"command": "load_har", "path": str(path)})
            self.assertEqual(loaded["imported"], 1)
            restored = next(iter(self.lens.flows.values()))
            self.assertEqual(restored.request.raw_content, flow.request.raw_content)
            self.assertEqual(restored.response.raw_content, flow.response.raw_content)
            self.assertEqual(restored.response.headers.get_all("Set-Cookie"), ["a=1", "b=2"])

    async def test_failed_har_serialization_preserves_previous_file_and_removes_stage(self):
        first, second = tflow.tflow(resp=True), tflow.tflow(resp=True)
        self.lens.flows[first.id], self.lens.flows[second.id] = first, second
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.har"
            path.write_bytes(b"previous user file")
            with patch("persistence.export_flow", side_effect=[export_flow(first), ValueError("cannot serialize second")]):
                with self.assertRaisesRegex(ValueError, "cannot serialize"):
                    await self.lens.command({"command": "save_har", "path": str(path)})
            self.assertEqual(path.read_bytes(), b"previous user file")
            self.assertEqual(list(Path(directory).iterdir()), [path])
            path.write_text(json.dumps({"log": {"entries": [export_flow(first), {"invalid": True}]}}))
            before = list(self.lens.flows)
            with self.assertRaises(KeyError):
                await self.lens.command({"command": "load_har", "path": str(path)})
            self.assertEqual(list(self.lens.flows), before)

    async def test_overlimit_later_entry_leaves_existing_captures_unchanged(self):
        existing = tflow.tflow(resp=True)
        self.lens.flows[existing.id] = existing
        empty = tflow.tflow(resp=True)
        empty.request.content = empty.response.content = b""
        first, second = export_flow(empty), export_flow(empty)
        second["_lensRawRequestBody"] = base64.b64encode(b"x" * 17).decode()
        with patch("persistence.ImportBudget", side_effect=lambda count, size: ImportBudget(count, size, max_body_bytes=16)):
            with self.assertRaisesRegex(ValueError, "before base64 allocation"):
                await self.lens.command({"command": "import_har", "har": {"log": {"entries": [first, second]}}})
        self.assertEqual(list(self.lens.flows), [existing.id])

    async def test_shutdown_joins_uncancellable_file_worker_transaction(self):
        flow = tflow.tflow(resp=True)
        self.lens.flows[flow.id] = flow
        entered, release = threading.Event(), threading.Event()
        original = export_flow(flow)
        def held_export(value):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("test worker was not released")
            return original
        with tempfile.TemporaryDirectory() as directory, patch("persistence.export_flow", held_export):
            path = Path(directory) / "transaction.har"
            command = self.lens.spawn(self.lens.command({"command": "save_har", "path": str(path)}))
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            closing = asyncio.create_task(self.lens.close())
            await asyncio.sleep(0.01)
            self.assertFalse(closing.done(), "shutdown must await the owned file transaction")
            release.set()
            await asyncio.wait_for(closing, 1)
            self.assertTrue(command.cancelled())
            self.assertEqual(json.loads(path.read_text())["log"]["entries"][0], original)
            self.assertFalse(self.lens.file_tasks)

    async def test_invalid_network_and_dns_configuration_is_atomic(self):
        await self.configure({"kind": "block"})
        for network in ({"upload_kbps": -1}, {"download_kbps": float("inf")}, {"upload_kbps": True}, {"upload_kbps": 1e308},
                        *({"connect_timeout_seconds": value} for value in (True, None, 0, 601, 1.5, "10"))):
            with self.assertRaises(ValueError):
                await self.lens.command({"command": "configure", "rules": [], "network": network})
            self.assertEqual(self.lens.rules[0].parameters["kind"], "block")
        with self.assertRaises(ValueError):
            await self.configure({"kind": "dns_spoof", "value": "hostname.invalid"})
        self.assertEqual(self.lens.rules[0].parameters["kind"], "block")

    async def test_no_cache_and_block_cookies_cover_both_sides(self):
        await self.configure({"kind": "no_cache"}, {"kind": "block_cookies"})
        flow = tflow.tflow(resp=True)
        flow.request.headers["Cookie"] = "secret=a"
        flow.request.headers["If-None-Match"] = "old-tag"
        flow.request.headers["If-Modified-Since"] = "yesterday"
        flow.response.headers.add("Set-Cookie", "a=1")
        flow.response.headers.add("Set-Cookie", "b=2")
        await self.lens.request(flow)
        await self.lens.response(flow)
        for header in ("Cookie", "If-None-Match", "If-Modified-Since"):
            self.assertNotIn(header, flow.request.headers)
        self.assertEqual(flow.request.headers["Cache-Control"], "no-cache")
        self.assertEqual(flow.request.headers["Pragma"], "no-cache")
        self.assertEqual(flow.response.headers["Cache-Control"], "no-store")
        self.assertEqual(flow.response.headers["Expires"], "0")
        self.assertEqual(flow.response.headers.get_all("Set-Cookie"), [])

    async def test_rule_plan_is_immutable_not_serialized_and_released_at_response_or_error(self):
        rule = {"kind": "no_cache", "match": "*"}
        await self.lens.command({"command": "configure", "rules": [rule]})
        rule['kind'] = 'block'
        for enabled in ([], {}, 'false', 1, None):
            with self.subTest(enabled=enabled), self.assertRaisesRegex(ValueError, 'enabled.*boolean'):
                await self.lens.command({"command": "configure", "rules": [{"kind": "block", "enabled": enabled}]})
            self.assertEqual(self.lens.rules[0].parameters['kind'], 'no_cache')
        flow = tflow.tflow(resp=True)
        flow.response.headers['ETag'] = 'old'
        flow.response.headers['Last-Modified'] = 'old'
        await self.lens.request(flow)
        self.assertIn(flow, self.lens.rule_plans)
        await self.configure({"kind": "rewrite_response_header", "name": "X-New", "value": "new"})
        await self.lens.response(flow)
        self.assertNotIn('ETag', flow.response.headers)
        self.assertNotIn('Last-Modified', flow.response.headers)
        self.assertNotIn('X-New', flow.response.headers)
        self.assertNotIn(flow, self.lens.rule_plans)
        self.assertFalse(any('rule' in key for key in flow.metadata))
        self.assertFalse(any('rule' in key.lower() for key in export_flow(flow)))
        with self.assertRaises(TypeError): self.lens.rules[0].parameters['value'] = 'mutated'
        await self.lens.command({"command": "recording", "enabled": False})
        failed = tflow.tflow()
        await self.lens.request(failed)
        self.assertIn(failed, self.lens.rule_plans)
        self.lens.error(failed)
        self.assertNotIn(failed, self.lens.rule_plans)

    async def test_rule_plan_weak_binding_does_not_own_abandoned_unrecorded_flow(self):
        import gc
        import weakref
        await self.configure({"kind": "no_cache"})
        await self.lens.command({"command": "recording", "enabled": False})
        flow = tflow.tflow()
        await self.lens.request(flow)
        reference = weakref.ref(flow)
        self.assertEqual(len(self.lens.rule_plans), 1)
        del flow
        gc.collect()
        self.assertIsNone(reference())
        self.assertEqual(len(self.lens.rule_plans), 0)

    async def test_rule_generation_budget_counts_shared_snapshots_once_and_response_pauses_until_completion(self):
        import gc
        rules = [{"kind": "no_cache", "match": "*"}, {"kind": "breakpoint_response", "match": "*"}]
        await self.lens.command({"command": "configure", "rules": rules})
        cost = self.lens.rules_metadata_bytes
        with patch('engine.METADATA_BYTES', cost - 1), self.assertRaises(ValueError):
            await self.lens.command({"command": "configure", "rules": rules})
        first, second = tflow.tflow(resp=True, live=True), tflow.tflow()
        await self.lens.request(first); await self.lens.request(second)
        pending = asyncio.create_task(self.lens.response(first))
        await asyncio.sleep(0)
        self.assertTrue(first.intercepted)
        self.assertNotIn(first, self.lens.rule_plans)
        self.assertEqual(len(self.lens.active_rule_plans), 2)
        with patch('engine.STORE_BYTES', cost * 2 - 1), self.assertRaisesRegex(ValueError, 'rule-generation budget'):
            await self.lens.command({"command": "configure", "rules": rules})
        # Two active plans share one immutable generation; do not charge twice.
        with patch('engine.STORE_BYTES', cost * 2):
            await self.lens.command({"command": "configure", "rules": rules})
        self.lens.error(second)
        await self.lens.command({"command": "resume", "id": first.id, "action": "continue"})
        await pending
        gc.collect()
        self.assertEqual(len(self.lens.active_rule_plans), 0)
        # Historical captured rows do not retain a generation budget.
        with patch('engine.STORE_BYTES', cost):
            await self.lens.command({"command": "configure", "rules": rules})

    async def test_cancelled_request_hook_releases_its_plan_without_a_later_sdk_error_hook(self):
        import gc
        await self.configure({"kind": "breakpoint_request"})
        flow = tflow.tflow(live=True)
        pending = asyncio.create_task(self.lens.request(flow))
        await asyncio.sleep(0)
        self.assertTrue(flow.intercepted)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError): await pending
        del pending
        gc.collect()
        self.assertIn(flow.id, self.lens.flows)
        self.assertIsNotNone(flow.error)
        self.assertNotIn(flow, self.lens.rule_plans)
        self.assertEqual(len(self.lens.active_rule_plans), 0)
        # Ordinary addon exceptions can be swallowed by the SDK and followed by
        # response; do not discard their configuration as though cancelled.
        await self.configure({"kind": "no_cache"})
        continued = tflow.tflow(resp=True)
        with patch.object(self.lens, 'apply', side_effect=ValueError('controlled addon exception')):
            with self.assertRaisesRegex(ValueError, 'controlled addon'):
                await self.lens.request(continued)
        self.assertIn(continued, self.lens.rule_plans)
        await self.configure({"kind": "block"})
        await self.lens.response(continued)
        self.assertEqual(continued.response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(continued, self.lens.rule_plans)

    async def test_repeat_limits_concurrency_and_accounts_mixed_outcomes(self):
        flow = tflow.tflow()
        self.lens.flows[flow.id] = flow
        active = peak = invoked = 0
        async def send(*args, **kwargs):
            nonlocal active, peak, invoked
            active += 1
            peak = max(peak, active)
            invoked += 1
            result = invoked % 3 != 0
            await asyncio.sleep(0.005)
            active -= 1
            return result
        with patch.object(self.lens, "send_request", send), patch("engine.emit") as output:
            result = await self.lens.command({"command": "repeat", "id": flow.id, "count": 7, "concurrency": 2})
            job = self.lens.repeat_jobs[result["job_id"]]
            await job.task
        self.assertEqual(peak, 2)
        self.assertEqual(job.completed, 5)
        self.assertEqual(job.failed, 2)
        self.assertEqual(job.cancelled, 0)
        self.assertEqual(sum(c.args[0] == "repeat_done" for c in output.call_args_list), 1)

    async def test_repeat_cancellation_owns_only_its_group(self):
        flow = tflow.tflow()
        self.lens.flows[flow.id] = flow
        started = asyncio.Event()
        cancelled = 0
        async def send(*args, **kwargs):
            nonlocal cancelled
            started.set()
            try:
                await asyncio.sleep(10)
                return True
            except asyncio.CancelledError:
                cancelled += 1
                raise
        with patch.object(self.lens, "send_request", send):
            first = await self.lens.command({"command": "repeat", "id": flow.id, "count": 10, "concurrency": 2})
            second = await self.lens.command({"command": "repeat", "id": flow.id, "count": 1})
            await started.wait()
            await asyncio.sleep(0)
            await self.lens.command({"command": "cancel_repeat", "job_id": first["job_id"]})
            job = self.lens.repeat_jobs[first["job_id"]]
            self.assertEqual(job.state, "cancelled")
            self.assertEqual(job.cancelled, 10)
            self.assertEqual(cancelled, 2)
            other = self.lens.repeat_jobs[second["job_id"]]
            self.assertFalse(other.task.done())
            await self.lens.command({"command": "cancel_repeat", "job_id": second["job_id"]})

    async def test_repeat_interval_spaces_request_attempts(self):
        flow = tflow.tflow()
        self.lens.flows[flow.id] = flow
        times = []
        async def send(*args, **kwargs):
            times.append(asyncio.get_running_loop().time())
            return True
        with patch.object(self.lens, "send_request", send):
            result = await self.lens.command({"command": "repeat", "id": flow.id, "count": 3,
                                              "concurrency": 3, "interval_ms": 20})
            await self.lens.repeat_jobs[result["job_id"]].task
        self.assertEqual(len(times), 3)
        self.assertTrue(all(b - a >= 0.019 for a, b in zip(times, times[1:])))

    async def test_close_cancels_repeat_workers_and_releases_owned_tasks(self):
        flow = tflow.tflow()
        self.lens.flows[flow.id] = flow
        started = asyncio.Event()
        async def send(*args, **kwargs):
            started.set()
            await asyncio.sleep(10)
            return True
        with patch.object(self.lens, "send_request", send):
            result = await self.lens.command({"command": "repeat", "id": flow.id, "count": 5, "concurrency": 2})
            await started.wait()
            job = self.lens.repeat_jobs[result["job_id"]]
            await self.lens.close()
        self.assertTrue(job.task.done())
        self.assertEqual(job.children, set())
        self.assertEqual(job.cancelled, 5)
        self.assertIsNone(job.request)

    async def test_repeat_can_cancel_before_worker_start_and_reject_bad_limits(self):
        flow = tflow.tflow()
        self.lens.flows[flow.id] = flow
        for key, value in (("count", 1001), ("count", True), ("concurrency", 0), ("interval_ms", -1)):
            with self.assertRaises(ValueError):
                await self.lens.command({"command": "repeat", "id": flow.id, key: value})
        result = await self.lens.command({"command": "repeat", "id": flow.id, "count": 1000})
        await self.lens.command({"command": "cancel_repeat", "job_id": result["job_id"]})
        job = self.lens.repeat_jobs[result["job_id"]]
        self.assertEqual(job.cancelled, 1000)
        self.assertTrue(job.finalized)

    async def test_empty_body_find_is_rejected_before_configuration_changes(self):
        await self.configure({"kind": "block"})
        for kind in ("rewrite_request_body", "rewrite_response_body"):
            with self.assertRaisesRegex(ValueError, "must not be empty"):
                await self.configure({"kind": kind, "name": "", "value": "replacement"})
        self.assertEqual(self.lens.rules[0].parameters["kind"], "block")

    async def test_clear_releases_paused_connection(self):
        await self.configure({"kind": "breakpoint_request"})
        flow = tflow.tflow(live=True)
        pending = asyncio.create_task(self.lens.request(flow))
        await asyncio.sleep(0)
        await self.lens.command({"command": "clear"})
        await asyncio.wait_for(pending, 1)
        self.assertFalse(flow.intercepted)
        self.assertNotIn(flow.id, self.lens.flows)

    async def test_map_local_is_binary_safe(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\xff\x00asset"); f.flush()
            await self.configure({"kind": "map_local", "value": f.name})
            flow = tflow.tflow()
            await self.lens.request(flow)
            self.assertEqual(flow.response.content, b"\xff\x00asset")

    async def test_invalid_configuration_is_atomic(self):
        await self.configure({"kind": "block"})
        with self.assertRaises(ValueError):
            await self.configure({"kind": "delay", "value": "-1"})
        self.assertEqual(self.lens.rules[0].parameters["kind"], "block")


class OutgoingCleanupLifecycle(unittest.IsolatedAsyncioTestCase):
    class Writer:
        """Inject only stream-close outcomes; the Lens/network owners are real."""
        def __init__(self, *, fail=False, first_failures=0, held=False):
            self.fail, self.first_failures = fail, first_failures
            self.wait_started, self.release = asyncio.Event(), asyncio.Event()
            if not held:
                self.release.set()

        def close(self):
            if self.fail or self.first_failures:
                self.first_failures = max(0, self.first_failures - 1)
                raise OSError("owned outgoing fixture close failure")

        async def wait_closed(self):
            self.wait_started.set()
            await self.release.wait()

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="lens-outgoing-cleanup-")
        self.lens = Lens(None, Path(self.directory.name), 8890)
        self.writers = []

    async def asyncTearDown(self):
        # Even a failed assertion must release the deliberately held resource.
        for writer in self.writers:
            writer.fail = False
            writer.first_failures = 0
            writer.release.set()
        await self.lens.close()
        self.directory.cleanup()

    async def start_late_cleanup(self, writer):
        self.writers.append(writer)
        entered = asyncio.Event()
        async def operation():
            try:
                entered.set()
                await asyncio.Future()
            finally:
                # Matches outgoing_transport's ownership boundary: cancellation
                # admits its writer only when the outgoing coroutine finalizes.
                await self.lens.network.close_streams([writer])
        task = self.lens.spawn(operation())
        await entered.wait()
        return task

    async def test_stop_rejects_late_close_failure_keeps_owner_and_retries_after_repair(self):
        writer = self.Writer(fail=True)
        operation = await self.start_late_cleanup(writer)
        for attempt in range(2):
            with self.subTest(attempt=attempt), self.assertLogs("network", level="WARNING") as warnings:
                with self.assertRaisesRegex(RuntimeError, "retains 1 relay stream.*retry Stop"):
                    await self.lens.command({"command": "stop_capture"})
            self.assertTrue(any("owned outgoing fixture close failure" in line for line in warnings.output))
            self.assertFalse(self.lens.capture_stopped, "Stop must not attest successful cleanup")
            self.assertTrue(self.lens.network.closed, "failed cleanup must leave new admission stopped")
            self.assertIn(writer, self.lens.network.closing)
            for command in ("compose", "replay", "repeat", "resume"):
                with self.subTest(command=command), self.assertRaisesRegex(ValueError, "stopped"):
                    await self.lens.command({"command": command})
        self.assertTrue(operation.cancelled())
        writer.fail = False
        result = await self.lens.command({"command": "stop_capture"})
        self.assertEqual(result, {"capture_stopped": True, "workspace_revision": self.lens.workspace_revision.current()})
        self.assertTrue(self.lens.capture_stopped)
        self.assertFalse(self.lens.network.closing)
        self.assertFalse(self.lens.network.close_waiters)

    async def test_close_rejects_late_failure_and_retains_authority_for_retry(self):
        writer = self.Writer(fail=True)
        operation = await self.start_late_cleanup(writer)
        with self.assertLogs("network", level="WARNING"), self.assertRaisesRegex(RuntimeError, "retains 1 relay stream.*retry Stop"):
            await self.lens.close()
        self.assertTrue(operation.cancelled())
        self.assertIn(writer, self.lens.network.closing)
        self.assertTrue(self.lens.network.closed)
        writer.fail = False
        await self.lens.close()
        self.assertFalse(self.lens.network.closing)
        self.assertFalse(self.lens.network.close_waiters)

    async def test_cancel_stop_during_final_wait_retains_shielded_waiter_until_retry(self):
        # First close fails inside outgoing finalization; the final network
        # recheck retries it, then blocks in wait_closed. Cancel that final wait,
        # after execution is already over, rather than only canceling execution.
        writer = self.Writer(first_failures=1, held=True)
        operation = await self.start_late_cleanup(writer)
        with self.assertLogs("network", level="WARNING"):
            stopping = asyncio.create_task(self.lens.command({"command": "stop_capture"}))
            await asyncio.wait_for(writer.wait_started.wait(), 1)
            self.assertTrue(operation.cancelled())
            waiter = self.lens.network.close_waiters[writer]
            self.assertFalse(waiter.done())
            stopping.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await stopping
        self.assertFalse(self.lens.capture_stopped)
        self.assertIn(writer, self.lens.network.closing)
        self.assertIs(self.lens.network.close_waiters[writer], waiter)
        self.assertFalse(waiter.done(), "parent cancellation must not poison the close future")
        self.assertFalse(waiter.cancelled())
        writer.release.set()
        await self.lens.command({"command": "stop_capture"})
        self.assertTrue(waiter.done())
        self.assertFalse(waiter.cancelled())
        self.assertFalse(self.lens.network.closing)
        self.assertFalse(self.lens.network.close_waiters)
        self.assertTrue(self.lens.capture_stopped)


class RelayCapacity(unittest.IsolatedAsyncioTestCase):
    async def test_admission_rejects_without_queue_and_releases_for_retry_and_close(self):
        from network import ProxyRelays
        class Reader:
            async def read(self, size):
                await asyncio.Event().wait()
        class Writer:
            def __init__(self):
                self.closed = False
            def close(self):
                self.closed = True
            async def wait_closed(self):
                pass
            def can_write_eof(self):
                return False
        opened = []
        async def connect(*args):
            writer = Writer()
            opened.append(writer)
            return Reader(), writer
        relay = ProxyRelays()
        writers = [Writer() for _ in range(5)]
        with patch("network.MAX_CONNECTIONS", 2), patch("network.asyncio.open_connection", connect), self.assertLogs("network", level="WARNING"):
            for writer in writers[:3]:
                relay.accept(Reader(), writer, ("127.0.0.1", 1))
            self.assertEqual(relay.status()["active_connections"], 2)
            self.assertTrue(writers[2].closed)
            await asyncio.sleep(0.01)
            self.assertEqual(len(opened), 2, "rejected clients must not connect to an internal listener")
            cancelled = next(iter(relay.tasks))
            cancelled.cancel()
            await asyncio.gather(cancelled, return_exceptions=True)
            await asyncio.sleep(0)
            self.assertEqual(relay.status()["active_connections"], 1)
            relay.accept(Reader(), writers[3], ("127.0.0.1", 1))
            await asyncio.sleep(0.01)
            self.assertEqual(len(opened), 3)
            await relay.close()
            self.assertEqual(relay.status()["active_connections"], 0)
            self.assertFalse(relay.tasks)
            relay.accept(Reader(), writers[4], ("127.0.0.1", 1))
            self.assertTrue(writers[4].closed)
            self.assertEqual(relay.status()["rejected_connections"], 2)
        self.assertTrue(all(writer.closed for writer in opened))


if __name__ == "__main__":
    unittest.main()
