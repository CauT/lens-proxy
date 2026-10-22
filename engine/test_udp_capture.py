import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from forwarding import parse_forwards
from udp_capture import (UDPRecorder, load_associations, save_associations, encode_datagram,
                         DATAGRAM_OVERHEAD, DATAGRAM_BYTES, prepare_associations)


class UDPBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-udp-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "session.json"
        self.events = []
        self.owner = UDPRecorder(lambda event, **fields: self.events.append((event, fields)))
        self.endpoint = parse_forwards([{"listen_port": 10000, "target_host": "EXAMPLE.test.", "target_port": 443}], [], transport="UDP")[0]

    def begin(self, owner=None):
        return (owner or self.owner).begin(self.endpoint, ("127.0.0.1", 30000), ("127.0.0.1", 10000))

    def document(self):
        association = self.begin()
        association.dropped("send", 2, 3)
        association.connected(("::1", 443, 0, 0))
        association.data("send", b"")
        association.data("send", bytes(range(256)))
        association.data("receive", b"\x00\xffreply")
        association.dropped("receive", 1, 0)
        association.finish("idle")
        save_associations(self.path, self.owner.snapshot())
        return json.loads(self.path.read_bytes())

    def write(self, value):
        self.path.write_text(json.dumps(value))

    def test_atomic_empty_and_binary_datagrams_have_separate_forwarded_and_explicit_drop_counts(self):
        document = self.document()
        value = document["associations"][0]
        self.assertEqual([item["base64"] for item in value["datagrams"]][0], "")
        self.assertEqual(value["sent_datagrams"], 2)
        self.assertEqual(value["received_datagrams"], 1)
        self.assertEqual(value["observed_datagrams"], 3)
        self.assertEqual(value["dropped_client_datagrams"], 2)
        self.assertEqual(value["dropped_client_bytes"], 3)
        self.assertEqual(value["dropped_upstream_datagrams"], 1)
        self.assertEqual(value["dropped_upstream_bytes"], 0)
        self.assertFalse(value["truncated"])
        self.assertEqual(self.owner.cost, 263 + 3 * DATAGRAM_OVERHEAD)
        page = self.owner.page(value["id"], offset=1, limit=1)
        self.assertEqual(page["total"], 3)
        self.assertEqual(page["offset"], 1)
        self.assertEqual(page["datagrams"][0]["sequence"], 2)
        self.assertEqual(page["association"]["retained_datagrams"], 3)
        self.assertEqual(page["association"]["client"], ("127.0.0.1", 30000))
        self.assertEqual(page["association"]["listener_address"], ("127.0.0.1", 10000))
        self.assertEqual(self.owner.page(value["id"], offset=4)["datagrams"], [])
        for options in ({"offset": True}, {"offset": -1}, {"limit": True}, {"limit": 0}, {"limit": 33}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.owner.page(value["id"], **options)

    def test_packet_count_and_byte_limits_never_split_or_merge_payloads(self):
        association = self.begin()
        association.connected(("127.0.0.1", 443))
        with patch("udp_capture.DATAGRAMS", 3), patch("udp_capture.ASSOCIATION_BYTES", 7):
            association.data("send", b"12345")
            association.data("receive", b"abcdef")
            association.data("receive", b"")
            association.data("receive", b"ab")
            association.data("send", b"")
        self.assertEqual([item["content"] for item in association.datagrams], [b"12345", b"", b"ab"])
        self.assertEqual([item["sequence"] for item in association.datagrams], [1, 3, 4])
        self.assertTrue(association.value["truncated"])
        self.assertEqual(association.value["observed_datagrams"], 5)
        self.assertEqual(association.value["sent_datagrams"], 2)
        self.assertEqual(association.value["received_bytes"], 8)
        self.assertEqual(association.value["retained_bytes"], 7)
        self.assertEqual(self.owner.cost, 7 + 3 * DATAGRAM_OVERHEAD)

    def test_store_eviction_and_clear_detach_live_owners_and_snapshots_are_independent(self):
        self.owner.limit = DATAGRAM_OVERHEAD + 3
        first = self.begin()
        first.connected(("127.0.0.1", 443))
        first.data("send", b"one")
        frozen = self.owner.snapshot()
        first.datagrams[0]["timestamp"] += 1
        self.assertNotEqual(frozen[0]["datagrams"][0]["timestamp"], first.datagrams[0]["timestamp"])
        second = self.begin()
        second.connected(("127.0.0.1", 443))
        second.data("receive", b"two")
        self.assertFalse(first.retained)
        self.assertEqual(first.datagrams, [])
        first.data("send", b"later")
        self.assertEqual(first.datagrams, [])
        self.assertEqual(self.owner.cost, 3 + DATAGRAM_OVERHEAD)
        self.assertEqual(frozen[0]["datagrams"][0]["content"], b"one")
        self.owner.clear()
        events = len(self.events)
        second.data("receive", b"")
        second.finish("idle")
        self.assertEqual(len(self.events), events)
        self.assertEqual(self.owner.cost, 0)
        self.assertEqual(second.datagrams, [])
        self.assertEqual(frozen[0]["retained_bytes"], 3)

    def test_oversized_packet_does_not_evict_an_unrelated_capture_when_it_cannot_fit(self):
        self.owner.limit = DATAGRAM_OVERHEAD + 3
        first, second = self.begin(), self.begin()
        for association in (first, second):
            association.connected(("127.0.0.1", 443))
        first.data("send", b"one")
        second.data("send", b"larger")
        self.assertTrue(first.retained)
        self.assertEqual(second.datagrams, [])
        self.assertTrue(second.value["truncated"])
        self.assertEqual(self.owner.cost, 3 + DATAGRAM_OVERHEAD)
        zero = UDPRecorder(lambda *args, **kwargs: None, limit=0)
        association = self.begin(zero)
        association.connected(("127.0.0.1", 443))
        association.data("send", b"")
        self.assertEqual(zero.cost, 0)
        self.assertTrue(association.value["truncated"])

    def test_roundtrip_keeps_numeric_peer_flags_sources_and_unfinished_history_without_lookup(self):
        document = self.document()
        with patch("socket.getaddrinfo", side_effect=AssertionError("imports never resolve names")):
            loaded = load_associations(self.path)
            self.owner.replace(loaded)
        association = next(iter(self.owner.associations.values()))
        self.assertEqual(association.value["peer_scope"], 0)
        self.assertEqual(association.value["peer_flowinfo"], 0)
        self.assertEqual(association.value["target_host"], "EXAMPLE.test.")
        self.assertEqual(association.value["dial_host"], "example.test")
        self.assertTrue(association.value["imported"])
        self.assertEqual([encode_datagram(item) for item in association.datagrams], document["associations"][0]["datagrams"])
        loaded[0]["datagrams"][0]["timestamp"] += 1
        self.assertNotEqual(loaded[0]["datagrams"][0]["timestamp"], association.datagrams[0]["timestamp"])
        for source_state in ("resolving", "open"):
            live = self.begin()
            if source_state == "open":
                live.connected(("::1", 443, 0, 0))
                live.data("send", b"")
            snapshot = [self.owner.snapshot()[-1]]
            save_associations(self.path, snapshot)
            loaded = load_associations(self.path)
            self.assertEqual(loaded[0]["state"], "incomplete")
            self.assertEqual(loaded[0]["source_state"], source_state)
            self.assertIsNone(loaded[0]["ended"])
            self.owner.replace(loaded)
            # Incomplete historical records stay incomplete after another save.
            save_associations(self.path, self.owner.snapshot())
            self.assertEqual(load_associations(self.path)[0]["source_state"], source_state)

    def test_invalid_documents_and_later_datagrams_cannot_replace_existing_capture(self):
        document = self.document()
        original = self.owner.snapshot()
        mutations = (
            lambda value: value.update(format="lens-tcp-streams"),
            lambda value: value.update(version=True),
            lambda value: value.update(extra="unowned"),
            lambda value: value["associations"].append(copy.deepcopy(value["associations"][0])),
            lambda value: value["associations"][0].update(extra="unowned"),
            lambda value: value["associations"][0].update(client=["localhost", 30000]),
            lambda value: value["associations"][0].update(listener_address=["127.0.0.1", True]),
            lambda value: value["associations"][0].update(listener_address=["127.0.0.1", 10001]),
            lambda value: value["associations"][0].update(peer=["example.test", 443]),
            lambda value: value["associations"][0].update(peer_scope=None),
            lambda value: value["associations"][0].update(ended=None),
            lambda value: value["associations"][0].update(state="open"),
            lambda value: value["associations"][0].update(source_state="open"),
            lambda value: value["associations"][0].update(started=True),
            lambda value: value["associations"][0].update(started=10**1000),
            lambda value: value["associations"][0].update(dial_host="different.test"),
            lambda value: value["associations"][0].update(retained_bytes=0),
            lambda value: value["associations"][0].update(sent_bytes=0),
            lambda value: value["associations"][0].update(sent_datagrams=1),
            lambda value: value["associations"][0].update(sent_datagrams=True),
            lambda value: value["associations"][0].update(dropped_upstream_datagrams=0, dropped_upstream_bytes=1),
            lambda value: value["associations"][0].update(observed_datagrams=4),
            lambda value: value["associations"][0]["datagrams"][1].update(direction=[]),
            lambda value: value["associations"][0]["datagrams"][1].update(sequence=1),
            lambda value: value["associations"][0]["datagrams"][1].update(observed_bytes=257),
            lambda value: value["associations"][0]["datagrams"][1].update(base64="invalid"),
            lambda value: value["associations"][0]["datagrams"][1].update(timestamp=float("inf")),
            lambda value: value["associations"][0]["datagrams"][1].update(extra="unowned"),
        )
        for mutation in mutations:
            changed = copy.deepcopy(document)
            mutation(changed)
            self.write(changed)
            with self.subTest(document=changed), self.assertRaises(ValueError):
                self.owner.replace(load_associations(self.path))
            self.assertEqual(self.owner.snapshot(), original)

    def test_direct_replace_prevalidates_every_record_and_budget_before_clearing(self):
        self.document()
        original = self.owner.snapshot()
        later = copy.deepcopy(original[0])
        later["id"] = "a" * 32
        later["datagrams"][-1]["content"] = b"short"
        with self.assertRaises(ValueError):
            self.owner.replace([original[0], later])
        self.assertEqual(self.owner.snapshot(), original)
        self.owner.limit = self.owner.cost - 1
        with self.assertRaisesRegex(ValueError, "capture budget"):
            self.owner.replace(original)
        self.assertEqual(self.owner.snapshot(), original)
        for bad in (-1, True, 32 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                UDPRecorder(lambda *args, **kwargs: None, limit=bad)

    def test_import_admission_bounds_precede_payload_decode_and_strict_empty_packet_accounting(self):
        document = self.document()
        cases = (
            ({"DATAGRAMS": 2}, "datagram limit"),
            ({"ASSOCIATION_BYTES": 262}, "association payload budget"),
            ({"ASSOCIATIONS": 0}, "association limit"),
        )
        for constants, reason in cases:
            with self.subTest(constants=constants), patch.multiple("udp_capture", **constants), self.assertRaisesRegex(ValueError, reason):
                load_associations(self.path)
        with patch("udp_capture.base64.b64decode", side_effect=AssertionError("must reject size before allocating")):
            with self.assertRaisesRegex(ValueError, "capture budget"):
                prepare_associations(document["associations"], encoded=True, budget=DATAGRAM_OVERHEAD - 1)
            changed = copy.deepcopy(document)
            changed["associations"][0]["datagrams"][0].update(observed_bytes=DATAGRAM_BYTES + 1)
            self.write(changed)
            with self.assertRaisesRegex(ValueError, "sequence/size"):
                load_associations(self.path)
        self.write(document)
        self.owner.limit = 2 * DATAGRAM_OVERHEAD
        with self.assertRaisesRegex(ValueError, "capture budget"):
            self.owner.replace(self.owner.snapshot())
        empty = self.begin()
        empty.connected(("127.0.0.1", 443))
        empty.data("send", b"")
        empty.data("receive", b"")
        empty.data("send", b"")
        self.assertEqual(len(empty.datagrams), 2)
        self.assertEqual(self.owner.cost, 2 * DATAGRAM_OVERHEAD)
        self.assertTrue(empty.value["truncated"])

    def test_truncated_history_permits_known_gaps_but_rejects_impossible_counts_and_payload_prefixes(self):
        association = self.begin()
        association.connected(("127.0.0.1", 443))
        with patch("udp_capture.DATAGRAMS", 1):
            association.data("send", b"")
            association.data("receive", b"missing")
        association.finish("idle")
        save_associations(self.path, self.owner.snapshot())
        document = json.loads(self.path.read_bytes())
        self.assertEqual(load_associations(self.path)[0]["received_bytes"], 7)
        for change in (
            {"truncated": False},
            {"sent_bytes": 1},  # all sent packets retained; no place for another byte
            {"received_datagrams": 0, "observed_datagrams": 1},
            {"received_bytes": DATAGRAM_BYTES + 1},
        ):
            changed = copy.deepcopy(document)
            changed["associations"][0].update(change)
            self.write(changed)
            with self.subTest(change=change), self.assertRaises(ValueError):
                load_associations(self.path)
        changed = copy.deepcopy(document)
        changed["associations"][0]["datagrams"][0].update(observed_bytes=1)
        self.write(changed)
        with self.assertRaises(ValueError):
            load_associations(self.path)

    def test_failed_write_preserves_private_target_and_read_size_precedes_json_parser(self):
        self.document()
        previous = self.path.read_bytes()
        with patch("udp_capture.FILE_BYTES", 32), self.assertRaises(ValueError):
            save_associations(self.path, self.owner.snapshot())
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        with patch("udp_capture.FILE_BYTES", 32), patch("persistence.json.loads", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "before parsing"):
                load_associations(self.path)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            load_associations(fifo)
        self.path.write_text('{"format":"lens-udp-datagrams","version":1,"version":1,"associations":[]}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_associations(self.path)

    def test_largest_datagram_and_association_admission_preserve_source_and_existing_owners(self):
        association = self.begin()
        association.connected(("::1", 443, 123, 7))
        payload = bytes(range(256)) * 255 + bytes(range(255))
        self.assertEqual(len(payload), DATAGRAM_BYTES)
        association.data("send", payload)
        association.data("receive", b"")
        association.finish("idle")
        save_associations(self.path, self.owner.snapshot())
        loaded = load_associations(self.path)[0]
        self.assertEqual(loaded["datagrams"][0]["content"], payload)
        self.assertEqual(loaded["peer_flowinfo"], 123)
        self.assertEqual(loaded["peer_scope"], 7)
        previous = self.owner.snapshot()
        with patch("udp_capture.ASSOCIATIONS", 1):
            with self.assertRaises(ValueError):
                self.owner.begin(self.endpoint, ("not-numeric", 30000), ("127.0.0.1", 10000))
            self.assertEqual(self.owner.snapshot(), previous)
            replacement = self.begin()
            self.assertFalse(association.retained)
            self.assertEqual(association.datagrams, [])
            self.assertEqual(self.owner.cost, 0)
            self.assertTrue(replacement.retained)
        for peer in (("localhost", 443), ("127.0.0.1", 443, 0, 0), ("::1", 443, True, 0), ("::1", 443, 0, 2**32)):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                replacement.connected(peer)
        self.assertEqual(replacement.value["state"], "resolving")

    def test_resolving_cancel_error_and_finished_owner_events_are_consistent(self):
        association = self.begin()
        association.dropped("send", 1, 0)
        association.finish("cancelled")
        summary = association.summary()
        association.connected(("127.0.0.1", 443))
        association.data("send", b"late")
        association.dropped("send", 1, 4)
        association.finish("error", "late error")
        self.assertEqual(association.summary(), summary)
        save_associations(self.path, self.owner.snapshot())
        self.assertEqual(load_associations(self.path)[0]["state"], "cancelled")
        unresolved = self.begin()
        with self.assertRaises(ValueError):
            unresolved.finish("idle")
        unresolved.finish("error", "a" * 3000)
        self.assertEqual(len(unresolved.value["error"]), 2000)
        for args in (("other", 1, 2), ("send", 0, 1), ("send", True, 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                unresolved.dropped(*args)
        for direction, payload in (("other", b""), ("send", bytearray()), ("send", b"x" * (DATAGRAM_BYTES + 1))):
            with self.assertRaises(ValueError):
                unresolved.data(direction, payload)


class UDPNotificationBoundaries(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.events = []
        self.owner = UDPRecorder(lambda event, **fields: self.events.append((event, fields)))
        self.endpoint = parse_forwards([{"listen_port": 10000, "target_host": "localhost", "target_port": 443}], [], transport="UDP")[0]
        self.addCleanup(self.owner.clear)

    def begin(self):
        return self.owner.begin(self.endpoint, ("127.0.0.1", 30000), ("127.0.0.1", 10000))

    async def test_short_burst_flushes_latest_summary_with_one_coalesced_timer_without_another_packet(self):
        association = self.begin()
        association.connected(("127.0.0.1", 443))
        association.data("send", b"")
        pending = association.pending_emit
        self.assertIsNotNone(pending)
        for _ in range(39):
            association.data("send", b"x")
            self.assertIs(association.pending_emit, pending)
        self.assertEqual(len(self.events), 2)  # resolving, then open before data
        self.assertEqual(self.events[-1][1]["association"]["sent_datagrams"], 0)
        await asyncio.sleep(.13)
        self.assertEqual(len(self.events), 3)
        self.assertIsNone(association.pending_emit)
        latest = self.events[-1][1]["association"]
        self.assertEqual(latest["state"], "open")
        self.assertEqual(latest["sent_datagrams"], 40)
        self.assertEqual(latest["sent_bytes"], 39)
        self.assertEqual(latest["retained_datagrams"], 40)
        # A later resolving association also flushes known forwarding drops.
        resolving = self.begin()
        resolving.dropped("send", 4, 0)
        self.assertIsNotNone(resolving.pending_emit)
        await asyncio.sleep(.13)
        self.assertEqual(self.events[-1][1]["association"]["dropped_client_datagrams"], 4)
        self.assertIsNone(resolving.pending_emit)

    async def test_clear_eviction_replace_and_finish_cancel_timers_and_cannot_resurrect_old_owners(self):
        for action in ("clear", "evict", "replace", "finish"):
            with self.subTest(action=action):
                self.owner.clear()
                self.events.clear()
                association = self.begin()
                association.connected(("127.0.0.1", 443))
                association.data("send", b"burst")
                pending = association.pending_emit
                self.assertIsNotNone(pending)
                if action == "clear":
                    self.owner.clear()
                elif action == "evict":
                    self.owner.discard(association.value["id"])
                elif action == "replace":
                    self.owner.replace(self.owner.snapshot())
                    imported = self.owner.associations[association.value["id"]]
                    self.assertIsNot(imported, association)
                    self.assertIsNone(imported.pending_emit)
                    self.assertEqual(imported.value["state"], "incomplete")
                else:
                    association.finish("idle")
                    latest = self.events[-1][1]["association"]
                    self.assertEqual(latest["state"], "idle")
                    self.assertEqual(latest["sent_datagrams"], 1)
                    self.assertIsNotNone(latest["ended"])
                self.assertTrue(pending.cancelled())
                self.assertIsNone(association.pending_emit)
                previous = copy.deepcopy(self.events)
                # A stale callback is harmless even if already dequeued when
                # the owner was removed or replaced at the producing boundary.
                association.flush_pending()
                association.data("send", b"late")
                await asyncio.sleep(.13)
                self.assertEqual(self.events, previous)


class UDPSynchronousNotifications(unittest.TestCase):
    def test_without_a_running_loop_each_observation_is_immediately_visible(self):
        events = []
        owner = UDPRecorder(lambda event, **fields: events.append((event, fields)))
        endpoint = parse_forwards([{"listen_port": 10000, "target_host": "localhost", "target_port": 443}], [], transport="UDP")[0]
        association = owner.begin(endpoint, ("127.0.0.1", 30000), ("127.0.0.1", 10000))
        association.connected(("127.0.0.1", 443))
        association.data("send", b"")
        self.assertIsNone(association.pending_emit)
        self.assertEqual(events[-1][1]["association"]["sent_datagrams"], 1)


if __name__ == "__main__":
    unittest.main()
