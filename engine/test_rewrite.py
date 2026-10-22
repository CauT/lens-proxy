"""Production rewrite boundaries; snapshots execute immutable prepared actions."""
import asyncio
import base64
import contextlib
import copy
import gzip
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from mitmproxy import http
from mitmproxy.test import tflow

import rewrite
from bounds import METADATA_BYTES
from engine import Lens, summary
from har import export_flow, import_entry
from http_headers import prepare_headers
from message_edit import prepare_header_fields


def action(kind, name, value="", **fields):
    return rewrite.prepare({"kind": kind, "name": name, "value": value, **fields})


def request_flow(body=b"old", fields=()):
    flow = tflow.tflow(resp=True)
    flow.request = http.Request.make("POST", "http://example.test/p?q=one", body)
    flow.request.headers["Host"] = "example.test"
    flow.request.headers.fields += tuple(fields)
    flow.response = http.Response.make(200, body, {"Content-Type": "application/octet-stream"})
    return flow


class RewriteBoundaries(unittest.TestCase):
    def test_header_set_preserves_first_slot_and_unrelated_raw_duplicate_order(self):
        flow = request_flow(fields=((b"X-Dup", b"one"), (b"X-Raw", b"\xff"), (b"x-dup", b"two"), (b"X-Raw", b"last")))
        old = flow.request.headers.fields
        edit = action("rewrite_request_header", "X-Dup", "new").edit(flow, "request")
        self.assertEqual(flow.request.headers.fields, old)
        edit.apply(flow)
        self.assertEqual(flow.request.headers.fields[-3:], ((b"X-Dup", b"new"), (b"X-Raw", b"\xff"), (b"X-Raw", b"last")))
        self.assertEqual(flow.request.headers.get_all("Host"), ["example.test"])

    def test_header_add_remove_and_replace_first_across_all_ordered_fields(self):
        flow = request_flow(fields=((b"X-Dup", b"no"), (b"X-Else", b"source"), (b"x-dup", b"old old"), (b"X-Dup", b"old")))
        action("rewrite_request_header", "X-Dup", "new", rewrite_mode="replace", rewrite_find="old", rewrite_count="first").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.headers.get_all("X-Dup"), ["no", "new old", "old"])
        action("rewrite_request_header", "X-Dup", "added", rewrite_mode="add").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.headers.fields[-1], (b"X-Dup", b"added"))
        action("rewrite_request_header", "X-Dup", rewrite_mode="remove").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.headers.get_all("X-Dup"), [])
        self.assertEqual(flow.request.headers.get_all("X-Else"), ["source"])

    def test_header_source_invalid_untouched_fields_are_preserved(self):
        flow = request_flow(fields=((b"bad source name", b"\xffsource"), (b"X-Target", b"old")))
        action("rewrite_request_header", "X-Target", "new").edit(flow, "request").apply(flow)
        self.assertIn((b"bad source name", b"\xffsource"), flow.request.headers.fields)

    def test_invalid_header_rules_use_the_shared_field_policy(self):
        for name, value in (("Content-Length", "1"), ("Host", "bad"), ("Transfer-Encoding", "chunked"),
                             ("not token", "ok"), ("X-Good", "bad\0"), ("X-Good", "bad\r\n")):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                action("rewrite_request_header", name, value)
        for fields in ({"rewrite_mode": "unknown"}, {"rewrite_count": "unknown"},
                       {"rewrite_mode": "replace", "rewrite_find": ""}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                action("rewrite_request_header", "X-Good", "new", **fields)

    def test_header_growth_is_admitted_before_value_replacement(self):
        flow = request_flow(fields=((b"X-Dup", b"a" * 100),))
        rewrite_action = action("rewrite_request_header", "X-Dup", "long", rewrite_mode="replace", rewrite_find="a")
        old = flow.request.headers.fields
        with patch.object(rewrite, "HEADER_BYTES", 200), self.assertRaisesRegex(ValueError, "before allocation"):
            rewrite_action.edit(flow, "request")
        self.assertEqual(flow.request.headers.fields, old)

    def test_ordinary_header_rewrite_keeps_chunked_framing_and_trailers(self):
        flow = request_flow()
        flow.request.headers.pop("content-length")
        flow.request.headers["Transfer-Encoding"] = "chunked"
        flow.request.trailers = http.Headers([(b"X-Trailer", b"source")])
        action("rewrite_request_header", "X-New", "value").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.headers["Transfer-Encoding"], "chunked")
        self.assertNotIn("content-length", flow.request.headers)
        self.assertEqual(flow.request.trailers.fields, ((b"X-Trailer", b"source"),))

    def test_encoding_header_changes_use_exact_decoded_body_and_rebuild_framing(self):
        flow = request_flow(b"old bytes\0\xff")
        source = gzip.compress(flow.request.raw_content, mtime=123)
        flow.request.raw_content = source
        flow.request.headers["Content-Encoding"] = "gzip"
        flow.request.headers["Content-Length"] = str(len(source))
        action("rewrite_request_header", "Content-Encoding", "identity").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.raw_content, b"old bytes\0\xff")
        self.assertEqual(flow.request.headers["Content-Length"], str(len(b"old bytes\0\xff")))

    def test_body_rewrite_first_all_binary_bytes_and_gzip_roundtrip(self):
        for count, expected in (("first", b"new old\0\xff"), ("all", b"new new\0\xff")):
            flow = request_flow()
            flow.response.raw_content = gzip.compress(b"old old\0\xff", mtime=123)
            flow.response.headers["Content-Encoding"] = "gzip"
            action("rewrite_response_body", "old", "new", rewrite_count=count).edit(flow, "response").apply(flow)
            self.assertEqual(gzip.decompress(flow.response.raw_content), expected)
            self.assertEqual(flow.response.headers["Content-Length"], str(len(flow.response.raw_content)))
            self.assertEqual(export_flow(import_entry(export_flow(flow))), export_flow(flow))

    def test_body_no_match_preserves_exact_wire_and_invalid_codec_fails_closed(self):
        flow = request_flow()
        flow.response.raw_content = gzip.compress(b"no matches", mtime=123)
        flow.response.headers["Content-Encoding"] = "gzip"
        edit = action("rewrite_response_body", "old", "new").edit(flow, "response")
        self.assertIs(edit.message, flow.response)
        flow.response.headers["Content-Encoding"] = "unsupported"
        with self.assertRaisesRegex(ValueError, "Unsupported Content-Encoding"):
            action("rewrite_response_body", "old", "new").edit(flow, "response")

    def test_body_expansion_rejects_before_replacement_allocation(self):
        flow = request_flow(b"a" * 64)
        before = flow.request.get_state()
        prepared = action("rewrite_request_body", "a", "expanded")
        with patch.object(rewrite, "BODY_BYTES", 64), self.assertRaisesRegex(ValueError, "before allocation"):
            prepared.edit(flow, "request")
        self.assertEqual(flow.request.get_state(), before)

    def test_shared_body_owner_rejects_trailers_unavailable_and_nonempty_head(self):
        flow = request_flow()
        flow.request.trailers = http.Headers([(b"X-Source", b"trailer")])
        with self.assertRaisesRegex(ValueError, "trailers"):
            action("rewrite_request_body", "old", "new").edit(flow, "request")
        flow.request.raw_content = None
        with self.assertRaisesRegex(ValueError, "unavailable"):
            action("rewrite_request_body", "old", "new").edit(flow, "request")
        flow.request.method = "HEAD"
        with self.assertRaisesRegex(ValueError, "HEAD"):
            action("rewrite_response_body", "old", "new").edit(flow, "response")

    def test_url_changes_ipv6_authority_and_no_match_keeps_opaque_target(self):
        flow = request_flow()
        action("rewrite_request_url", "http://example.test", "https://[::1]:9443").edit(flow, "request").apply(flow)
        self.assertEqual((flow.request.scheme, flow.request.host, flow.request.port), ("https", "::1", 9443))
        self.assertEqual(flow.request.host_header, "[::1]:9443")
        flow.request.data.path = b"/opaque\xff?empty="
        edit = action("rewrite_request_url", "never matching", "new").edit(flow, "request")
        self.assertIs(edit.message, flow.request)
        self.assertEqual(edit.message.data.path, b"/opaque\xff?empty=")

    def test_changed_url_preserves_empty_query_marker_at_shared_edit_owner(self):
        flow = request_flow(); flow.request.data.path = b"/empty?"
        action("rewrite_request_url", "example.test", "changed.test").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.data.path, b"/empty?")
        self.assertEqual(flow.request.host_header, "changed.test")

    def test_url_invalid_destination_and_growth_do_not_mutate_source(self):
        for find, value in (("example.test", "user:pass@example.test"), ("one", "bad#fragment"), ("http", "ftp")):
            flow = request_flow(); before = flow.request.get_state()
            with self.subTest(value=value), self.assertRaises(ValueError):
                action("rewrite_request_url", find, value).edit(flow, "request")
            self.assertEqual(flow.request.get_state(), before)

    def test_query_matches_only_strictly_decoded_keys_and_preserves_source_segments(self):
        flow = request_flow()
        flow.request.data.path = b"/opaque\xff?na%6De=one&raw=%ff&na+me=two&&bad%GG=x&name&last="
        action("rewrite_request_query", "name", "空 格").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.data.path, b"/opaque\xff?name=%E7%A9%BA%20%E6%A0%BC&raw=%ff&na+me=two&&bad%GG=x&last=")
        action("rewrite_request_query", "na me", "again", rewrite_mode="add").edit(flow, "request").apply(flow)
        self.assertTrue(flow.request.data.path.endswith(b"&na%20me=again"))
        action("rewrite_request_query", "na me", rewrite_mode="remove").edit(flow, "request").apply(flow)
        self.assertNotIn(b"na+me", flow.request.data.path)
        self.assertNotIn(b"na%20me", flow.request.data.path)
        self.assertIn(b"&&bad%GG=x", flow.request.data.path)

    def test_query_empty_segments_marker_and_bounds_are_explicit(self):
        flow = request_flow(); flow.request.data.path = b"/p?"
        edit = action("rewrite_request_query", "missing", rewrite_mode="remove").edit(flow, "request")
        self.assertIs(edit.message, flow.request)
        action("rewrite_request_query", "key", "value").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.data.path, b"/p?&key=value")
        flow.request.data.path = b"/p?key=value"
        action("rewrite_request_query", "key", rewrite_mode="remove").edit(flow, "request").apply(flow)
        self.assertEqual(flow.request.data.path, b"/p")
        prepared = action("rewrite_request_query", "key", "long value")
        with patch.object(rewrite, "URL_BYTES", 10), self.assertRaisesRegex(ValueError, "before join"):
            prepared.edit(flow, "request")

    def test_status_reuses_shared_reason_and_no_body_protocol_rules(self):
        flow = request_flow()
        action("rewrite_response_status", "201", "Created by Lens").edit(flow, "response").apply(flow)
        self.assertEqual((flow.response.status_code, flow.response.reason), (201, "Created by Lens"))
        for code in ("204", "304"):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "cannot contain a body"):
                action("rewrite_response_status", code).edit(flow, "response")
        for code in ("101", "099", "600", "0200", "２００"):
            with self.subTest(code=code), self.assertRaises(ValueError):
                action("rewrite_response_status", code)
        flow.response.status_code = 101
        with self.assertRaisesRegex(ValueError, "protocol-switch"):
            action("rewrite_response_status", "200").edit(flow, "response")


class RewriteConfiguration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        master = Mock(); master.addons.get.return_value = None
        self.lens = Lens(master, Path("/tmp"), 8890)
        self.output = contextlib.redirect_stdout(io.StringIO()); self.output.__enter__()

    async def asyncTearDown(self):
        await self.lens.close()
        self.output.__exit__(None, None, None)

    async def configure(self, rules):
        return await self.lens.command({"command": "configure", "rules": rules})

    async def test_global_metadata_admission_precedes_compile_and_caller_is_unmodified(self):
        rules = [{"kind": "rewrite_request_header", "name": "X-Test", "value": "value"}]
        before = copy.deepcopy(rules)
        await self.configure(rules)
        self.assertEqual(rules, before)
        self.assertEqual(self.lens.rules[0].parameters["match"], "*")
        with patch("engine.prepare_rewrite", side_effect=AssertionError("must not compile")):
            with self.assertRaisesRegex(ValueError, "metadata"):
                await self.configure([{"kind": "rewrite_request_body", "name": "old", "value": "x" * (METADATA_BYTES + 1)}])
        self.assertEqual(self.lens.rules[0].parameters["kind"], "rewrite_request_header")

    async def test_invalid_late_rule_keeps_entire_previous_configuration(self):
        await self.configure([{"kind": "block", "match": "*"}])
        previous = self.lens.rules
        with self.assertRaises(ValueError):
            await self.configure([{"kind": "rewrite_request_body", "name": "old", "value": "new"},
                                  {"kind": "rewrite_response_header", "name": "Content-Length", "value": "1"}])
        self.assertIs(self.lens.rules, previous)

    async def test_compiled_plan_preserves_generation_and_order_across_breakpoint(self):
        original = [{"kind": "breakpoint_request", "match": "*"},
                    {"kind": "rewrite_request_body", "match": "*", "name": "old", "value": "before"},
                    {"kind": "rewrite_response_body", "match": "*", "name": "old", "value": "before"}]
        await self.configure(original)
        flow = request_flow()
        task = asyncio.create_task(self.lens.request(flow))
        await asyncio.sleep(0)
        self.assertTrue(flow.intercepted)
        original[1]["value"] = "mutated caller"
        await self.configure([{"kind": "rewrite_request_body", "name": "old", "value": "after"}])
        flow.resume(); await task
        await self.lens.response(flow)
        self.assertEqual(flow.request.raw_content, b"before")
        self.assertEqual(flow.response.raw_content, b"before")

    async def test_rewrite_failure_is_observable_keeps_kill_sentinel_and_har_roundtrips(self):
        await self.configure([{"kind": "rewrite_request_body", "name": "a", "value": "expanded"}])
        flow = request_flow(b"a" * 64)
        with patch.object(rewrite, "BODY_BYTES", 64):
            await self.lens.request(flow)
        self.assertEqual(flow.error.msg, "Connection killed.")
        self.assertIn("rewrite failed", summary(flow)["error"])
        self.assertEqual(flow.request.raw_content, b"a" * 64)
        entry = export_flow(flow)
        self.assertIn("before allocation", entry["_lensRewriteError"])
        restored = import_entry(entry)
        self.assertEqual(export_flow(restored), entry)
        self.assertEqual(summary(restored)["error"], summary(flow)["error"])
        bad = copy.deepcopy(entry); bad["_lensRewriteError"] = None
        with self.assertRaises(ValueError):
            import_entry(bad)

    async def test_maximum_content_encoding_failure_kills_before_diagnostic_and_roundtrips(self):
        # This one field consumes the entire valid 64 KiB replacement-header
        # budget. The diagnostic additionally needs its explanatory labels.
        from http_headers import HEADER_BYTES
        codec = "x" * (HEADER_BYTES - len("Content-Encoding") - 4)
        await self.configure([{"kind": "rewrite_request_header", "name": "Content-Encoding", "value": codec}])
        flow = request_flow()
        flow.request.headers = http.Headers()
        before = flow.request.get_state()
        await self.lens.request(flow)
        self.assertEqual(flow.error.msg, "Connection killed.")
        self.assertFalse(flow.live)
        self.assertEqual(flow.request.get_state(), before)
        reason = summary(flow)["error"]
        self.assertGreater(len(reason), HEADER_BYTES)
        self.assertIn(codec, reason)
        entry = export_flow(flow)
        self.assertEqual(entry["_lensRewriteError"], reason)
        self.assertEqual(export_flow(import_entry(entry)), entry)

    async def test_diagnostic_reporting_failure_cannot_prevent_flow_kill(self):
        await self.configure([{"kind": "rewrite_request_body", "name": "a", "value": "expanded"}])
        flow = request_flow(b"a" * 64)
        before = flow.request.get_state()
        with patch.object(rewrite, "BODY_BYTES", 64), patch("engine.parse_rewrite_error", side_effect=ValueError("reporting failed")):
            with self.assertRaisesRegex(ValueError, "reporting failed"):
                await self.lens.request(flow)
        self.assertEqual(flow.error.msg, "Connection killed.")
        self.assertFalse(flow.live)
        self.assertEqual(flow.request.get_state(), before)

    async def test_response_failure_is_not_marked_completed(self):
        await self.configure([{"kind": "rewrite_response_status", "name": "204", "value": "No Content"}])
        flow = request_flow()
        await self.lens.request(flow); await self.lens.response(flow)
        self.assertIsNotNone(flow.error)
        self.assertNotIn("lens_response_complete", flow.metadata)
