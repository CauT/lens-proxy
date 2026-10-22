import base64
import gzip
import unittest
import zlib
from unittest.mock import patch

import brotli
import zstandard
from mitmproxy import connection, http

import message_edit as edits
from breakpoint_edit import prepare_edit
from message_edit import prepare_request_edit, prepare_response_edit
from bounds import decoded_bytes


def b64(data):
    return base64.b64encode(data).decode("ascii")


def flow_for(stage="request"):
    flow = http.HTTPFlow(connection.Client(peername=("127.0.0.1", 1111), sockname=("127.0.0.1", 8080)),
                         connection.Server(address=("example.test", 80)))
    flow.request = http.Request.make("POST", "http://example.test/before?q=1", b"original-request",
                                    {"Host": "example.test", "X-Original": "request"})
    flow.response = http.Response.make(200, b"original-response", {"X-Original": "response"})
    flow.metadata["lens_pause_stage"] = stage
    flow.intercept()
    return flow


class BreakpointEditSemantics(unittest.TestCase):
    def test_no_edits_and_empty_patches_preserve_message_identity_and_wire_state(self):
        flow = flow_for()
        original = flow.request
        original.raw_content = gzip.compress(b"same body", mtime=123)
        original.headers["Content-Encoding"] = "gzip"
        original.headers["Content-Length"] = "arbitrary-source"
        state = original.get_state()
        for command in ({}, {"request_edit": {}}):
            prepared = prepare_edit(flow, command)
            prepared.apply(flow)
            self.assertIs(flow.request, original)
            self.assertEqual(flow.request.get_state(), state)
        self.assertTrue(flow.intercepted)

    def test_whole_request_edit_is_prepared_then_atomically_applied(self):
        flow = flow_for()
        request, response = flow.request, flow.response
        prepared = prepare_edit(flow, {"request_edit": {"method": "PUT", "url": "https://other.test:8443/new?q=%FF",
                                      "headers": [["X-Duplicate", "one"], ["X-Duplicate", "two"]],
                                      "body_base64": b64(b"\xff\0new")}})
        self.assertIs(flow.request, request)
        self.assertEqual(prepared.original_url, "https://other.test:8443/new?q=%FF")
        prepared.apply(flow)
        self.assertIsNot(flow.request, request)
        self.assertIs(flow.response, response)
        self.assertEqual(flow.request.method, "PUT")
        self.assertEqual(flow.request.url, "https://other.test:8443/new?q=%FF")
        self.assertEqual(flow.request.host_header, "other.test:8443")
        self.assertEqual(flow.request.headers.get_all("X-Duplicate"), ["one", "two"])
        self.assertEqual(flow.request.raw_content, b"\xff\0new")
        self.assertEqual(flow.request.headers["Content-Length"], "5")
        self.assertTrue(flow.intercepted)

    def test_rejected_later_field_cannot_partially_mutate_flow(self):
        invalid = [
            {"method": "PUT", "headers": [["X-OK", "one"], ["X-Bad", "later\r\ninjection"]]},
            {"method": "PUT", "url": "https://user:password@example.test/"},
            {"method": "PUT", "body_base64": "%%%="},
            {"method": "PUT", "response_body": "unknown"},
        ]
        for patch_value in invalid:
            with self.subTest(patch_value=patch_value):
                flow = flow_for()
                request = flow.request
                state = request.get_state()
                with self.assertRaises(ValueError):
                    prepare_edit(flow, {"request_edit": patch_value})
                self.assertIs(flow.request, request)
                self.assertEqual(flow.request.get_state(), state)
                self.assertTrue(flow.intercepted)

    def test_body_admission_happens_before_base64_allocation(self):
        flow = flow_for()
        with patch.object(edits, "BODY_BYTES", 2), patch.object(edits.base64, "b64decode", side_effect=AssertionError("allocation")):
            with self.assertRaisesRegex(ValueError, "before base64 allocation"):
                prepare_edit(flow, {"request_edit": {"body_base64": "YWJj"}})
        for value in (None, 1, "A===", "YQ", "YQ==\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare_edit(flow, {"request_edit": {"body_base64": value}})

    def test_stage_and_side_ownership_rejects_legacy_and_new_cross_stage(self):
        flow = flow_for("response")
        for command in ({"request_edit": {}}, {"request_body": "text"},
                        {"response_edit": {}, "response_body": "text"},
                        {"request_edit": {}, "response_edit": {}},
                        {"request_body": "a", "response_body": "b"}):
            with self.subTest(command=command), self.assertRaises(ValueError):
                prepare_edit(flow, command)
        flow.metadata.clear()
        with self.assertRaises(ValueError):
            prepare_edit(flow, {"response_edit": {}})

    def test_legacy_body_uses_same_validation_encoding_and_stage_owner(self):
        flow = flow_for("response")
        flow.response.headers["Content-Encoding"] = "gzip"
        prepare_edit(flow, {"response_body": "测试"}).apply(flow)
        self.assertEqual(gzip.decompress(flow.response.raw_content), "测试".encode())
        for value in (None, b"bytes", ["text"]):
            with self.assertRaises(ValueError):
                prepare_edit(flow, {"response_body": value})
        with patch.object(edits, "BODY_BYTES", 2), self.assertRaises(ValueError):
            prepare_edit(flow, {"response_body": "测试"})

    def test_header_rules_keep_duplicates_order_and_explicit_wire_bytes(self):
        flow = flow_for()
        original_host = tuple(item for item in flow.request.headers.fields if item[0].lower() == b"host")
        prepare_edit(flow, {"request_edit": {"headers": [["X-Raw", "\udcff"], ["X-Raw", "中文"], ["X-Last", "z"]]}}).apply(flow)
        self.assertEqual(flow.request.headers.fields[:3], ((b"X-Raw", b"\xff"), (b"X-Raw", "中文".encode()), (b"X-Last", b"z")))
        self.assertEqual(tuple(item for item in flow.request.headers.fields if item[0].lower() == b"host"), original_host)
        for headers in (None, {}, [["X", "a", "b"]], [["", "value"]], [["X:Bad", "v"]],
                        [["X-中文", "v"]], [["X", "bad\0value"]], [["X", "\ud800"]], [["X", 1]],
                        [["Host", "evil"]], [["cOnTeNt-LeNgTh", "99"]], [["Transfer-Encoding", "chunked"]],
                        [["X", "v"]] * 1025, [["X", "中" * 21846]]):
            with self.subTest(headers_type=type(headers), count=len(headers) if headers else 0), self.assertRaises(ValueError):
                prepare_edit(flow, {"request_edit": {"headers": headers}})
        prepare_edit(flow, {"request_edit": {"headers": [["X", "\udcff" * 65531]]}})
        with self.assertRaises(ValueError):
            prepare_edit(flow, {"request_edit": {"headers": [["X", "\udcff" * 65532]]}})

    def test_url_and_method_validation_and_idna_ipv6(self):
        for url in ("/relative", "ftp://example.test/a", "http://example.test/#", "http://example.test/#part",
                    "http://example.test/a\n", " http://example.test/", "http://example.test:0/",
                    "http://example.test:65536/", "http://example.test:/", "http://example.test\\evil/",
                    "http://user@example.test/", "http://example.test/中文", 123):
            with self.subTest(url=url), self.assertRaises(ValueError):
                prepare_edit(flow_for(), {"request_edit": {"url": url}})
        for method in ("", "GET POST", "G\nET", "中文", None):
            with self.subTest(method=method), self.assertRaises(ValueError):
                prepare_edit(flow_for(), {"request_edit": {"method": method}})
        for url, host in (("https://中文.test/a", "中文.test"), ("http://[::1]:8080/a", "::1")):
            flow = flow_for()
            prepare_edit(flow, {"request_edit": {"url": url}}).apply(flow)
            self.assertEqual(flow.request.host, host)
            if host == "::1":
                self.assertEqual(flow.request.host_header, "[::1]:8080")

    def test_unchanged_body_or_encoding_preserves_compressed_raw_exactly(self):
        flow = flow_for("response")
        raw = gzip.compress(b"gzip source", mtime=1729)
        flow.response.raw_content = raw
        flow.response.headers["Content-Encoding"] = "gzip"
        prepare_edit(flow, {"response_edit": {"reason": "Edited reason", "headers": [["Content-Encoding", "gzip"], ["X", "new"]]}}).apply(flow)
        self.assertEqual(flow.response.raw_content, raw)
        self.assertEqual(flow.response.reason, "Edited reason")
        self.assertEqual(flow.response.headers["Content-Length"], str(len(raw)))

    def test_header_encoding_change_preserves_decoded_body_and_reencodes(self):
        for codec, raw in (("gzip", gzip.compress(b"plain")), ("br", brotli.compress(b"plain")),
                           ("zstd", zstandard.ZstdCompressor().compress(b"plain"))):
            flow = flow_for("response")
            flow.response.raw_content = raw
            flow.response.headers["Content-Encoding"] = codec
            prepare_edit(flow, {"response_edit": {"headers": [["X-New", "yes"]]}}).apply(flow)
            self.assertEqual(flow.response.raw_content, b"plain")
            prepare_edit(flow, {"response_edit": {"headers": [["Content-Encoding", codec]]}}).apply(flow)
            self.assertEqual(flow.response.content, b"plain")
        flow = flow_for()
        flow.request.raw_content = gzip.compress(b"first") + gzip.compress(b"second")
        flow.request.headers["Content-Encoding"] = "gzip"
        prepare_edit(flow, {"request_edit": {"headers": []}}).apply(flow)
        self.assertEqual(flow.request.raw_content, b"firstsecond")

    def test_unknown_malformed_unavailable_or_bomb_encoding_is_atomic(self):
        for codec, raw in (("unknown", b"raw"), ("gzip", b"invalid"), ("br", b"invalid"),
                           ("zstd", zstandard.ZstdCompressor().compress(b"truncated")[:-1]), ("gzip", None)):
            flow = flow_for("response")
            flow.response.headers["Content-Encoding"] = codec
            flow.response.raw_content = raw
            original = flow.response
            with self.subTest(codec=codec, raw=raw), self.assertRaises(ValueError):
                prepare_edit(flow, {"response_edit": {"headers": []}})
            self.assertIs(flow.response, original)
            self.assertEqual(flow.response.raw_content, raw)
        flow = flow_for()
        flow.request.headers["Content-Encoding"] = "gzip"
        flow.request.raw_content = gzip.compress(b"x" * 1024)
        with patch.object(edits, "BODY_BYTES", 128), self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
            prepare_edit(flow, {"request_edit": {"headers": []}})
        with self.assertRaisesRegex(ValueError, "Unsupported Content-Encoding"):
            prepare_edit(flow_for(), {"request_edit": {"headers": [["Content-Encoding", "unknown"]], "body_base64": b64(b"abc")}})

    def test_trailers_are_preserved_without_unproven_framing_conversion(self):
        flow = flow_for("response")
        flow.response.trailers = http.Headers([(b"X-Trailer", b"retained")])
        original = flow.response
        prepare_edit(flow, {"response_edit": {"reason": "New reason"}}).apply(flow)
        self.assertEqual(flow.response.trailers.fields, original.trailers.fields)
        for patch_value in ({"body_base64": b64(b"new")}, {"headers": []}, {"status_code": 201}):
            current = flow.response
            with self.assertRaisesRegex(ValueError, "message with trailers"):
                prepare_edit(flow, {"response_edit": patch_value})
            self.assertIs(flow.response, current)
        prepare_edit(flow, {}).apply(flow)
        self.assertEqual(flow.response.trailers.fields, original.trailers.fields)

    def test_response_fields_no_body_rules_and_framing_are_explicit(self):
        for status in (True, 101, 199, 600, "200"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                prepare_edit(flow_for("response"), {"response_edit": {"status_code": status}})
        for reason in ("bad\rreason", "bad\nreason", "bad\0reason", None):
            with self.assertRaises(ValueError):
                prepare_edit(flow_for("response"), {"response_edit": {"reason": reason}})
        for status in (204, 304):
            flow = flow_for("response")
            original = flow.response
            with self.assertRaisesRegex(ValueError, "explicitly replace"):
                prepare_edit(flow, {"response_edit": {"status_code": status}})
            self.assertIs(flow.response, original)
            prepare_edit(flow, {"response_edit": {"status_code": status, "body_base64": ""}}).apply(flow)
            self.assertEqual(flow.response.raw_content, b"")
            self.assertNotIn("Content-Length", flow.response.headers)
            with self.assertRaisesRegex(ValueError, "cannot contain a body"):
                prepare_edit(flow, {"response_edit": {"body_base64": b64(b"not empty")}})
        flow = flow_for("response")
        flow.request.method = "HEAD"
        flow.response.raw_content = b""
        flow.response.headers["Content-Length"] = "900"
        prepare_edit(flow, {"response_edit": {"headers": [["X", "new"]]}}).apply(flow)
        self.assertEqual(flow.response.headers["Content-Length"], "900")
        self.assertEqual(flow.response.raw_content, b"")
        with self.assertRaises(ValueError):
            prepare_edit(flow, {"response_edit": {"body_base64": b64(b"body")}})
        flow = flow_for("response")
        flow.response.headers["Transfer-Encoding"] = "chunked"
        prepare_edit(flow, {"response_edit": {"body_base64": b64(b"new")}}).apply(flow)
        self.assertNotIn("Transfer-Encoding", flow.response.headers)
        self.assertEqual(flow.response.headers["Content-Length"], "3")


class StandaloneMessageEditSemantics(unittest.TestCase):
    def test_empty_patch_requires_no_flow_pause_or_message_copy(self):
        request = http.Request.make("POST", "http://example.test/", b"complete bytes")
        with patch.object(request, "copy", side_effect=AssertionError("empty patch copied source")):
            prepared = prepare_request_edit(request, {})
        self.assertEqual(prepared.side, "request")
        self.assertIs(prepared.message, request)
        self.assertIsNone(prepared.original_url)
        response = http.Response.make(200, b"body")
        with patch.object(response, "copy", side_effect=AssertionError("empty response copied source")):
            self.assertIs(prepare_response_edit(response, {}, request_method="POST", frontend_method="POST").message, response)

    def test_source_keep_preserves_full_binary_wire_and_opaque_source_headers(self):
        # Larger than detail previews. Keep uses the owning message, never a
        # displayed prefix or text decoding, even with an unknown source codec.
        raw = bytes(range(256)) * 80
        request = http.Request.make("POST", "http://example.test/source", raw)
        request.headers = http.Headers([(b"X-Original", b"\xff\x80"), (b"X-Duplicate", b"one"),
                                        (b"X-Duplicate", b"two"), (b"Content-Encoding", b"opaque"),
                                        (b"Content-Length", b"source length"), (b"Transfer-Encoding", b"source framing")])
        state = request.get_state()
        prepared = prepare_request_edit(request, {"method": "PUT"})
        self.assertIsNot(prepared.message, request)
        self.assertEqual(prepared.message.headers.fields, request.headers.fields)
        self.assertIs(prepared.message.raw_content, raw)
        self.assertEqual(request.get_state(), state)
        # The 1024/64 KiB patch budget applies only to caller replacements,
        # not previously observed source fields that the caller chose to Keep.
        request.headers = http.Headers([(b"X-Source", b"v")] * 1025 + [(b"X-Large", b"x" * 65536)])
        prepared = prepare_request_edit(request, {"method": "PUT"})
        self.assertEqual(prepared.message.headers.fields, request.headers.fields)
        self.assertEqual(prepared.message.raw_content, raw)

    def test_standalone_request_uses_same_codec_url_and_atomic_patch_contract(self):
        decoded = b"\xff\0full decoded body" * 2048
        request = http.Request.make("POST", "http://example.test/", b"")
        request.raw_content = gzip.compress(decoded, mtime=4321)
        request.headers["Content-Encoding"] = "gzip"
        state = request.get_state()
        prepared = prepare_request_edit(request, {"method": "PUT", "url": "HTTP://[::1]:8080/new"})
        self.assertEqual(prepared.original_url, "HTTP://[::1]:8080/new")
        self.assertEqual(prepared.message.host_header, "[::1]:8080")
        self.assertEqual(prepared.message.raw_content, request.raw_content)
        recoded = prepare_request_edit(request, {"headers": [["X-New", "yes"]]})
        self.assertEqual(recoded.message.raw_content, decoded)
        self.assertEqual(recoded.message.headers["Content-Length"], str(len(decoded)))
        for fields in ({"method": "PUT", "headers": [["X-First", "ok"], ["X-Late", "bad\nvalue"]]},
                       {"url": "https://new.test/", "body_base64": "bad%"},
                       {"status_code": 200}):
            with self.assertRaises(ValueError):
                prepare_request_edit(request, fields)
            self.assertEqual(request.get_state(), state)

    def test_body_availability_is_separate_from_preserving_source(self):
        request = http.Request.make("POST", "http://example.test/", b"")
        request.raw_content = None
        self.assertIs(prepare_request_edit(request, {}).message, request)
        self.assertIsNone(prepare_request_edit(request, {"method": "PUT"}).message.raw_content)
        replacement = prepare_request_edit(request, {"body_base64": b64(b"explicit complete body")})
        self.assertEqual(replacement.message.raw_content, b"explicit complete body")
        request.headers["Content-Encoding"] = "gzip"
        with self.assertRaisesRegex(ValueError, "unavailable"):
            prepare_request_edit(request, {"headers": []})
        self.assertIsNone(request.raw_content)

    def test_response_rules_use_explicit_effective_and_frontend_method_facts(self):
        response = http.Response.make(200, b"synthetic response")
        prepared = prepare_response_edit(response, {"reason": "Edited synthetic"},
                                         request_method="HEAD", frontend_method="POST")
        self.assertEqual(prepared.message.raw_content, b"synthetic response")
        with self.assertRaisesRegex(ValueError, "cannot contain a body"):
            prepare_response_edit(response, {"reason": "Edited HEAD"}, request_method="HEAD", frontend_method="HEAD")
        for facts in ({"request_method": None, "frontend_method": "POST"},
                      {"request_method": "POST", "frontend_method": None}):
            with self.assertRaises(ValueError):
                prepare_response_edit(response, {}, **facts)


class SharedDecodingSemantics(unittest.TestCase):
    def test_strict_rejects_malformed_incomplete_and_trailing_while_default_keeps_wire(self):
        plain = b"decoded body"
        gzip_body = gzip.compress(plain)
        deflate_body = zlib.compress(plain)
        brotli_body = brotli.compress(plain)
        for codec, raw in (("gzip", b"not compressed"), ("gzip", gzip_body[:-1]),
                           ("gzip", gzip_body + b"trailing"),
                           ("deflate", deflate_body[:-1]), ("deflate", deflate_body + b"trailing"),
                           ("br", b"not compressed"), ("br", brotli_body[:-1]), ("br", brotli_body + b"trailing")):
            with self.subTest(codec=codec, raw=raw):
                self.assertEqual(decoded_bytes(raw, codec), raw)
                with self.assertRaises(ValueError):
                    decoded_bytes(raw, codec, strict=True)
        self.assertEqual(decoded_bytes(gzip_body + b"\0\0", "gzip"), plain)
        with self.assertRaisesRegex(ValueError, "trailing"):
            decoded_bytes(gzip_body + b"\0\0", "gzip", strict=True)
        for raw in (b"", b"unknown bytes"):
            self.assertEqual(decoded_bytes(raw, "unknown"), raw)
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                decoded_bytes(raw, "unknown", strict=True)

    def test_shared_strict_decoder_preserves_members_and_enforces_each_allocation_cap(self):
        plain = b"decoded body" * 100
        raw_deflater = zlib.compressobj(wbits=-15)
        cases = [("gzip", gzip.compress(plain)), ("deflate", zlib.compress(plain)),
                 ("deflateraw", raw_deflater.compress(plain) + raw_deflater.flush()),
                 ("br", brotli.compress(plain)), ("zstd", zstandard.ZstdCompressor().compress(plain))]
        for codec, raw in cases:
            with self.subTest(codec=codec):
                self.assertEqual(decoded_bytes(raw, codec, strict=True), plain)
                for strict in (False, True):
                    with self.assertRaisesRegex(ValueError, "Decoded body exceeds"):
                        decoded_bytes(raw, codec, limit=256, strict=strict)
        for codec, encode in (("gzip", gzip.compress), ("zstd", zstandard.ZstdCompressor().compress)):
            raw = encode(b"first") + encode(b"second")
            self.assertEqual(decoded_bytes(raw, codec, strict=True), b"firstsecond")
        for codec in ("", "identity", "none"):
            self.assertEqual(decoded_bytes(b"plain", codec, strict=True), b"plain")

    def test_zstd_strict_validates_eof_after_bounded_pass_without_changing_default(self):
        raw = zstandard.ZstdCompressor().compress(b"truncated final frame")[:-1]
        # The pinned SDK reader's historical lenient behavior emits the prefix
        # of this incomplete frame; strict editing must not call it complete.
        self.assertEqual(decoded_bytes(raw, "zstd"), b"truncated final fram")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            decoded_bytes(raw, "zstd", strict=True)
        with self.assertRaisesRegex(ValueError, "window budget"):
            decoded_bytes(b"invalid frame", "zstd")


if __name__ == "__main__":
    unittest.main()
