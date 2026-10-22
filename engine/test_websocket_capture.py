"""Real SDK object boundaries for lossless, bounded WebSocket capture."""
import asyncio
import base64
import copy
import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from bounds import ImportBudget
from engine import Lens, detail, summary
from har import export_flow, import_entry, snapshot_flow
from persistence import prepare_import
import websocket_capture as owner


def flow_with(*messages):
    flow = tflow.tflow(resp=True)
    flow.websocket = WebSocketData(messages=list(messages))
    return flow


def message(payload=b"hello", opcode=1, client=True, timestamp=0, dropped=False, injected=False):
    value = WebSocketMessage(opcode, client, payload, dropped=dropped, injected=injected)
    value.timestamp = timestamp
    return value


class WebSocketCaptureBoundaries(unittest.TestCase):
    def test_wire_facts_and_zero_timestamp_survive_har_and_sdk_snapshot(self):
        flow = flow_with(message(b"text", dropped=True), message(b"\x00\xff", 2, False, 0, injected=True))
        original = export_flow(flow)
        restored = import_entry(original)
        self.assertEqual(export_flow(restored), original)
        self.assertEqual(export_flow(snapshot_flow(restored)), original)
        self.assertEqual([(m.type, m.dropped, m.injected, m.timestamp) for m in restored.websocket.messages],
                         [(1, True, False, 0), (2, False, True, 0)])
        view = owner.page(restored)
        self.assertEqual([item["opcode"] for item in view["messages"]], [1, 2])
        self.assertEqual(base64.b64decode(view["messages"][1]["content_base64"]), b"\x00\xff")

    def test_legacy_unknown_facts_are_not_inferred_from_utf8_or_sdk_placeholders(self):
        entry = export_flow(flow_with(message(b"valid utf8"), message(b"\xff", 2)))
        entry.pop("_lensWebSocketGeneration")
        entry.pop("_webSocketMessagesTruncated")
        for item in entry["_webSocketMessages"]:
            for key in ("opcode", "dropped", "injected"):
                item.pop(key)
            item["caller_fact"] = {"x": [1, "retained"]}
        before = copy.deepcopy(entry)
        flow = import_entry(entry)
        self.assertEqual(export_flow(flow), before)
        self.assertEqual(entry, before)
        for item in owner.page(flow)["messages"]:
            self.assertIsNone(item["opcode"])
            self.assertIsNone(item["dropped"])
            self.assertIsNone(item["injected"])
        self.assertEqual(owner.generation(flow), 0)
        self.assertIsNone(owner.page(flow)["retention_truncated"])
        self.assertIsNone(detail(flow)["messages_truncated"])
        self.assertIsNone(summary(flow)["websocket_messages_truncated"])

    def test_explicit_null_and_plain_text_encoding_presence_roundtrip(self):
        entry = export_flow(flow_with(message()))
        item = entry["_webSocketMessages"][0]
        item.update(data="hello", opcode=None, dropped=None, injected=None)
        item.pop("encoding")
        self.assertEqual(export_flow(import_entry(entry)), entry)
        item["encoding"] = ""
        self.assertEqual(export_flow(import_entry(entry)), entry)

    def test_empty_websocket_and_absent_websocket_remain_distinct(self):
        for flow in (flow_with(), tflow.tflow(resp=True)):
            with self.subTest(present=flow.websocket is not None):
                entry = export_flow(flow)
                restored = import_entry(entry)
                self.assertEqual(restored.websocket is not None, flow.websocket is not None)
                self.assertEqual(export_flow(restored), entry)
        entry = export_flow(flow_with())
        entry.pop("_lensWebSocketGeneration")
        entry.pop("_webSocketMessagesTruncated")
        self.assertEqual(export_flow(import_entry(entry)), entry)

    def test_retention_completeness_preserves_observed_false_and_unknown(self):
        entry = export_flow(flow_with(message()))
        self.assertIs(owner.page(import_entry(entry))["retention_truncated"], False)
        entry["_webSocketMessagesTruncated"] = True
        self.assertIs(owner.page(import_entry(entry))["retention_truncated"], True)
        entry.pop("_webSocketMessagesTruncated")
        restored = import_entry(entry)
        self.assertIsNone(owner.page(restored)["retention_truncated"])
        self.assertNotIn("_webSocketMessagesTruncated", export_flow(snapshot_flow(restored)))
        entry["_webSocketMessagesTruncated"] = None
        with self.assertRaises(ValueError):
            import_entry(entry)

    def test_generation_integer_contract_is_admitted_before_message_decode(self):
        entry = export_flow(flow_with(message()))
        entry["_lensWebSocketGeneration"] = owner.MAX_GENERATION
        self.assertEqual(owner.page(import_entry(entry))["generation"], owner.MAX_GENERATION)
        for generation in (1 << 63, 10 ** 100, -1, True, 0.0):
            entry["_lensWebSocketGeneration"] = generation
            with self.subTest(generation=generation), patch.object(owner.base64, "b64decode", side_effect=AssertionError("decode forbidden")):
                with self.assertRaisesRegex(ValueError, "generation"):
                    owner.prepare(entry, 4096)

    def test_first_page_and_later_pages_have_bounded_raw_byte_previews(self):
        payload = b"\x00\xff" * 5000
        flow = flow_with(*(message(payload, 2, timestamp=0) for _ in range(63)))
        value = detail(flow)
        self.assertEqual(len(value["messages"]), 50)
        self.assertEqual(value["messages_total"], 63)
        self.assertEqual(value["messages_next_offset"], 50)
        self.assertEqual(value["messages_preview_limit"], 4096)
        self.assertEqual(value["messages_offset"], 0)
        page = owner.page(flow, 50, 50, value["messages_generation"])
        self.assertEqual([row["index"] for row in page["messages"]], list(range(50, 63)))
        self.assertIsNone(page["next_offset"])
        for item in value["messages"] + page["messages"]:
            self.assertEqual(base64.b64decode(item["content_base64"]), payload[:4096])
            self.assertEqual(item["content_bytes"], len(payload))
            self.assertTrue(item["preview_truncated"])
        self.assertEqual(flow.websocket.messages[0].content, payload)

    def test_generation_invalidates_stale_pages_and_import_is_stable(self):
        flow = flow_with(message())
        before = owner.page(flow)
        owner.retain(flow)
        self.assertEqual(owner.generation(flow), 1)
        with self.assertRaisesRegex(ValueError, "changed"):
            owner.page(flow, expected_generation=before["generation"])
        imported = import_entry(export_flow(flow))
        self.assertEqual(owner.page(imported), owner.page(imported))
        self.assertEqual(owner.generation(imported), 1)

    def test_invalid_page_values_rejected(self):
        flow = flow_with(message())
        for offset, limit, generation in ((True, 1, None), (-1, 1, None), (2, 1, None), (0, 0, None),
                                           (0, 51, None), (0, True, None), (0, 1, False), (0, 1, -1), (0, 1, 1 << 63), (0, 1, 10 ** 100)):
            with self.subTest(values=(offset, limit, generation)), self.assertRaises(ValueError):
                owner.page(flow, offset, limit, generation)

    def test_count_and_combined_payload_retention_keep_recent_whole_messages(self):
        flow = flow_with(*(message(bytes([index]), 2) for index in range(5)))
        with patch.object(owner, "MESSAGE_LIMIT", 3), patch.object(owner, "BODY_BYTES", 2):
            owner.retain(flow)
        self.assertEqual([item.content for item in flow.websocket.messages], [b"\x03", b"\x04"])
        self.assertTrue(owner.page(flow)["retention_truncated"])

    def test_oversized_last_message_is_omitted_without_mutating_forwarded_object(self):
        oversized = message(b"x" * 17, 2, dropped=False, injected=True)
        flow = flow_with(message(b"old"), oversized)
        original = oversized.get_state()
        with patch.object(owner, "BODY_BYTES", 16):
            owner.retain(flow)
        self.assertEqual([item.content for item in flow.websocket.messages], [b"old"])
        self.assertEqual(oversized.get_state(), original)
        self.assertTrue(flow.metadata["websocket_messages_truncated"])
        self.assertEqual(owner.generation(flow), 1)
        flow.websocket.messages.append(message(b"new"))
        owner.retain(flow)
        self.assertEqual(owner.generation(flow), 2)
        self.assertEqual(len(flow.websocket.messages), 2)

    def test_malformed_late_facts_reject_before_any_message_decode(self):
        original = export_flow(flow_with(message(), message()))
        patches = ({"type": "other"}, {"time": float("nan")}, {"time": True}, {"time": 10 ** 1000}, {"opcode": True},
                   {"opcode": 9}, {"dropped": 1}, {"injected": "false"}, {"encoding": "wat"},
                   {"data": "Zh=="}, {"data": "not base64"})
        for values in patches:
            entry = copy.deepcopy(original)
            entry["_webSocketMessages"][-1].update(values)
            with self.subTest(values=values), patch.object(owner.base64, "b64decode", side_effect=AssertionError("decode forbidden")):
                with self.assertRaises(ValueError):
                    owner.prepare(entry, 4096)

    def test_combined_budget_and_count_reject_before_message_decode(self):
        entry = export_flow(flow_with(message(b"abc"), message(b"def")))
        for cap in (3, 5):
            with self.subTest(cap=cap), patch.object(owner.base64, "b64decode", side_effect=AssertionError("decode forbidden")):
                with self.assertRaises(ValueError):
                    owner.prepare(entry, cap)
        with patch.object(owner, "MESSAGE_LIMIT", 1), self.assertRaises(ValueError):
            owner.prepare(entry, 6)
        # Combined HTTP + WS bytes share the ImportBudget, not separate ceilings.
        entry["_lensRawRequestBody"] = base64.b64encode(b"12345").decode()
        with self.assertRaises(ValueError):
            ImportBudget(1, 10).prepare(entry)

    def test_invalid_top_level_facts_and_late_entry_do_not_mutate_source(self):
        entry = export_flow(flow_with(message()))
        for key, value in (("_webSocketMessages", {}), ("_webSocketMessagesTruncated", 1),
                           ("_lensWebSocketGeneration", -1), ("_lensWebSocketGeneration", True)):
            bad = copy.deepcopy(entry); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                import_entry(bad)
        bad = copy.deepcopy(entry); bad["_webSocketMessages"][0]["opcode"] = 7
        document = {"log": {"entries": [entry, bad]}}
        original = copy.deepcopy(document)
        with self.assertRaises(ValueError):
            prepare_import(document, 2000, 256 * 1024 * 1024)
        self.assertEqual(document, original)


class WebSocketEngineIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_late_overwide_generation_import_preserves_existing_capture(self):
        master = Mock(); master.addons.get.return_value = None
        lens = Lens(master, Path("/tmp"), 8890)
        retained = flow_with(message())
        lens.flows[retained.id] = retained
        good = export_flow(flow_with(message()))
        bad = copy.deepcopy(good); bad["_lensWebSocketGeneration"] = 1 << 63
        with self.assertRaisesRegex(ValueError, "generation"):
            await lens.command({"command": "import_har", "har": {"log": {"entries": [good, bad]}}})
        self.assertEqual(list(lens.flows), [retained.id])
        self.assertIs(lens.flows[retained.id], retained)
        await lens.close()

    async def test_trim_precedes_store_and_paging_uses_retained_owner(self):
        master = Mock(); master.addons.get.return_value = None
        lens = Lens(master, Path("/tmp"), 8890)
        flow = flow_with(message(b"a"), message(b"b" * 17, 2))
        observed = []
        with patch.object(owner, "BODY_BYTES", 16), patch.object(lens, "remember", side_effect=lambda value: observed.append(sum(len(m.content) for m in value.websocket.messages))):
            lens.websocket_message(flow)
        self.assertEqual(observed, [1])
        lens.flows[flow.id] = flow
        page = await lens.command({"command": "websocket_messages", "id": flow.id})
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["generation"], 1)
        self.assertTrue(page["retention_truncated"])
        await lens.close()
