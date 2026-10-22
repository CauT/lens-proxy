import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from network import ProxyRelays
from persistence import atomic_text, cleanup_pending_stages
from tcp_capture import TCPRecorder, load_streams, save_streams, encode_chunk, CHUNK_OVERHEAD
from forwarding import parse_forwards


class TCPBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-tcp-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "session.json"
        self.events = []
        self.owner = TCPRecorder(lambda event, **fields: self.events.append((event, fields)))
        self.endpoint = parse_forwards([{"listen_port": 10000, "target_host": "EXAMPLE.test.", "target_port": 443}], [8890])[0]

    def document(self):
        stream = self.owner.begin(self.endpoint)
        stream.connected(("::1", 443, 0, 0))
        stream.data("send", bytes(range(256)))
        stream.data("receive", b"\x00\xffreply")
        stream.finish("closed")
        save_streams(self.path, self.owner.snapshot())
        return json.loads(self.path.read_bytes())

    def test_endpoint_admission_preserves_source_and_rejects_ambiguous_ports_and_hosts(self):
        self.assertEqual(self.endpoint.target_host, "EXAMPLE.test.")
        self.assertEqual(self.endpoint.dial_host, "example.test")
        for value in ({"listen_port": True}, {"target_port": 0}, {"listen_port": 8890},
                      {"target_host": "http://example.test"}, {"target_host": "*.test"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_forwards([{**self.endpoint.public(), **value}], [8890])
        with self.assertRaises(ValueError):
            parse_forwards([self.endpoint.public()] * 2, [])

    def test_eviction_releases_active_capture_bytes_and_clear_does_not_recapture(self):
        self.owner.limit = 256 + CHUNK_OVERHEAD + 16
        first = self.owner.begin(self.endpoint)
        first.data("send", b"a" * 256)
        frozen = self.owner.snapshot()
        second = self.owner.begin(self.endpoint)
        second.data("receive", b"b" * 256)
        self.assertFalse(first.retained)
        self.assertEqual(first.chunks, [])
        self.assertEqual(frozen[0]["chunks"][0]["content"], b"a" * 256)
        first.data("send", b"later")
        self.assertEqual(first.chunks, [])
        self.assertEqual(self.owner.cost, 256 + CHUNK_OVERHEAD)
        self.owner.clear()
        second.data("send", b"later")
        self.assertEqual(self.owner.cost, 0)
        self.assertEqual(second.chunks, [])

    def test_stream_chunk_and_byte_bounds_mark_loss_while_counting_forwarded_bytes(self):
        stream = self.owner.begin(self.endpoint)
        with patch("tcp_capture.CHUNKS", 2), patch("tcp_capture.STREAM_BYTES", 7):
            stream.data("send", b"12345")
            stream.data("receive", b"abcdef")
            stream.data("send", b"later")
        self.assertEqual([chunk["content"] for chunk in stream.chunks], [b"12345", b"ab"])
        self.assertTrue(stream.value["truncated"])
        self.assertEqual(stream.value["observed_chunks"], 3)
        self.assertEqual(stream.value["sent_bytes"], 10)
        self.assertEqual(stream.value["received_bytes"], 6)

    def test_paging_and_roundtrip_preserve_bytes_peer_source_and_historical_unknowns(self):
        document = self.document()
        values = load_streams(self.path)
        self.owner.replace(values)
        stream = next(iter(self.owner.streams.values()))
        page = self.owner.page(stream.value["id"], limit=1)
        self.assertEqual(len(page["chunks"]), 1)
        self.assertEqual(page["stream"]["peer_scope"], 0)
        self.assertEqual(page["stream"]["target_host"], "EXAMPLE.test.")
        self.assertTrue(page["stream"]["imported"])
        self.assertEqual([encode_chunk(chunk) for chunk in stream.chunks], document["streams"][0]["chunks"])
        values[0].update(state="open", ended=None)
        self.owner.replace(values)
        self.assertEqual(next(iter(self.owner.streams.values())).value["state"], "incomplete")
        self.assertEqual(next(iter(self.owner.streams.values())).chunks[0]["content"], bytes(range(256)))
        self.assertIsNone(next(iter(self.owner.streams.values())).value["ended"])
        with self.assertRaises(ValueError):
            self.owner.page(stream.value["id"], limit=33)

    def test_invalid_later_chunks_and_completeness_claims_cannot_replace_existing_capture(self):
        document = self.document()
        original = self.owner.snapshot()
        for update in ({"version": 2}, {"version": True}):
            self.path.write_text(json.dumps({**document, **update}))
            with self.assertRaises(ValueError):
                load_streams(self.path)
        for change in (lambda stream: stream.update(sent_bytes=0),
                       lambda stream: stream.update(unknown_source_field="must not disappear"),
                       lambda stream: stream["chunks"][1].update(base64="invalid"),
                       lambda stream: stream["chunks"][1].update(observed_bytes=4097),
                       lambda stream: stream["chunks"][1].update(sequence=1),
                       lambda stream: stream.update(retained_bytes=0),
                       lambda stream: stream.update(truncated=False, observed_chunks=3)):
            value = copy.deepcopy(document)
            change(value["streams"][0])
            self.path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.owner.replace(load_streams(self.path))
            self.assertEqual(self.owner.snapshot(), original)

    def test_failed_write_preserves_target_and_read_admission_precedes_parser(self):
        self.document()
        previous = self.path.read_bytes()
        with patch("tcp_capture.FILE_BYTES", 32), self.assertRaises(ValueError):
            save_streams(self.path, self.owner.snapshot())
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        with patch("tcp_capture.FILE_BYTES", 32), patch("persistence.json.loads", side_effect=AssertionError("must not parse")):
            with self.assertRaisesRegex(ValueError, "before parsing"):
                load_streams(self.path)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            load_streams(fifo)

    def test_stage_cleanup_failure_retains_inode_owner_and_retry_cannot_delete_a_replacement(self):
        self.path.write_text("previous target")
        stage = displaced = None
        try:
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                with atomic_text(self.path) as file:
                    file.write("new source")
                    stage = next(self.path.parent.glob(".*.lens-*.tmp"))
                    displaced = self.path.parent / "displaced-owned-stage"
                    stage.rename(displaced)
                    stage.write_text("foreign replacement")
            self.assertEqual(self.path.read_text(), "previous target")
            self.assertEqual(stage.read_text(), "foreign replacement")
            with self.assertRaisesRegex(RuntimeError, "retry Stop"):
                cleanup_pending_stages()
        finally:
            if stage is not None and displaced is not None and displaced.exists():
                # Only these explicitly test-owned files are moved back. The
                # production cleanup refused the changed path and retained proof.
                stage.unlink()
                displaced.rename(stage)
            cleanup_pending_stages()
        self.assertFalse(stage.exists())

    def test_pending_unlink_failure_blocks_new_stages_and_retries_without_losing_target(self):
        self.path.write_text("previous target")
        original = Path.unlink
        def denied(path, *args, **kwargs):
            if ".lens-" in path.name:
                raise PermissionError("fixture unlink denied")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", denied):
            with self.assertRaises(PermissionError):
                with atomic_text(self.path) as file:
                    file.write("incomplete")
                    raise ValueError("fixture serialization failure")
            stages = list(self.path.parent.iterdir())
            with self.assertRaisesRegex(RuntimeError, "retry Stop"):
                with atomic_text(self.path):
                    self.fail("must not allocate another stage")
            self.assertEqual(list(self.path.parent.iterdir()), stages)
        cleanup_pending_stages()
        self.assertEqual(self.path.read_text(), "previous target")
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])


class RelayFinalization(unittest.IsolatedAsyncioTestCase):
    async def test_late_connection_after_stop_is_closed_without_starting_pumps(self):
        entered = asyncio.Event()
        class Writer:
            closed = False
            def close(self):
                self.closed = True
            async def wait_closed(self):
                pass
        relay, downstream, upstream = ProxyRelays(), Writer(), Writer()
        async def late(*args):
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return object(), upstream
        with patch.object(relay, "dial", late), patch.object(relay, "pump", side_effect=AssertionError("late pump")):
            relay.accept(object(), downstream, ("127.0.0.1", 1))
            await entered.wait()
            await relay.close()
        self.assertTrue(downstream.closed and upstream.closed)
        self.assertFalse(relay.connections or relay.closing or relay.tasks)

    async def test_mixed_cleanup_outcomes_do_not_drop_failed_owner_or_block_successful_sibling(self):
        class Writer:
            broken = False
            completed = False
            def close(self):
                if self.broken:
                    raise OSError("fixture close failed")
            async def wait_closed(self):
                self.completed = True
        relay, first, second = ProxyRelays(), Writer(), Writer()
        first.broken = True
        with self.assertLogs("network", level="WARNING"):
            await relay.close_streams([first, second])
        self.assertEqual(relay.closing, {first})
        self.assertTrue(second.completed)
        first.broken = False
        await relay.close()
        self.assertFalse(relay.closing)

    async def test_failed_stream_cleanup_is_owned_and_retry_completes(self):
        class Transport:
            def abort(self):
                pass
        class Writer:
            transport = Transport()
            def close(self):
                pass
            async def wait_closed(self):
                await ready.wait()
        ready = asyncio.Event()
        relay, writer = ProxyRelays(), Writer()
        with patch("network.CLOSE_TIMEOUT", .001):
            await relay.close_streams([writer])
            self.assertIn(writer, relay.closing)
            self.assertIn(writer, relay.close_waiters)
            with self.assertRaisesRegex(RuntimeError, "retry Stop"):
                await relay.close()
            ready.set()
            await relay.close()
        self.assertFalse(relay.closing)
        self.assertFalse(relay.close_waiters)

    async def test_finalization_cancellation_does_not_poison_shared_protocol_close_future(self):
        entered = asyncio.Event()
        closed = asyncio.get_running_loop().create_future()
        class Writer:
            def close(self):
                pass
            async def wait_closed(self):
                entered.set()
                await closed
        relay, writer = ProxyRelays(), Writer()
        task = asyncio.create_task(relay.close_streams([writer]))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(closed.cancelled(), "cancelled waiters must not poison protocol ownership")
        self.assertIn(writer, relay.close_waiters)
        closed.set_result(None)
        await relay.close()
        self.assertFalse(relay.closing or relay.close_waiters)

    async def test_cancellation_during_final_cleanup_retains_both_streams_for_retry(self):
        entered, release = asyncio.Event(), asyncio.Event()
        class Writer:
            def close(self):
                pass
            async def wait_closed(self):
                entered.set()
                await release.wait()
        relay, first, second = ProxyRelays(), Writer(), Writer()
        task = asyncio.create_task(relay.close_streams([first, second]))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(relay.closing, {first, second})
        release.set()
        await relay.close()
        self.assertFalse(relay.closing)

    async def test_ipv4_mapped_self_target_rejects_before_dial_and_waiting_resolution_cancels(self):
        relay = ProxyRelays()
        relay.own_addresses.add(("127.0.0.1", 12345))
        with patch("network.asyncio.open_connection", side_effect=AssertionError("must not dial")):
            with self.assertRaisesRegex(OSError, "own listener"):
                await relay.dial(("::ffff:127.0.0.1", 12345), True)
        entered = asyncio.Event()
        async def blocked(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        with patch.object(asyncio.get_running_loop(), "getaddrinfo", blocked):
            task = asyncio.create_task(relay.dial(("waiting.test", 443), True))
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task


if __name__ == "__main__":
    unittest.main()
