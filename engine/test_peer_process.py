"""Socket-owner proof, import boundaries and owned subprocess finalization."""
import asyncio
import copy
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from client_connection import ClientConnection, import_client_connection
from owned_commands import Child, OwnedCommands
from peer_process import PeerProcesses, import_process, socket_records, unknown


SOURCE = SimpleNamespace(peer=("127.0.0.1", 50123), listener_address=("127.0.0.1", 8890))


def sockets(pid=123, name=b"client", listener_fd=9, extra=b""):
    return (f"p{os.getpid()}\0cengine\0\nf{listener_fd}\0n127.0.0.1:8890->127.0.0.1:50123\0TST=ESTABLISHED\0\n".encode()
            + f"p{pid}\0c".encode() + name + b"\0\nf3\0n127.0.0.1:50123->127.0.0.1:8890\0TST=ESTABLISHED\0\n" + extra)


def identity(pid=123, start="12345:67"):
    return json.dumps({"version": 1, "results": [{"pid": pid, "state": "readable", "identity": start}]}).encode()


class PeerProof(unittest.IsolatedAsyncioTestCase):
    async def result(self, *responses):
        resolver = PeerProcesses("unused")
        values = iter(responses)
        async def run(*_): return next(values)
        resolver.commands.run = run
        return await resolver.observe(SOURCE, 9)

    async def test_exact_tuple_held_fd_and_stable_birth_identity_required(self):
        fact = await self.result(sockets(), identity(), sockets(), identity())
        self.assertEqual((fact["state"], fact["pid"], fact["start_identity"], fact["name"]), ("identified", 123, "12345:67", "client"))
        for rows in (sockets(listener_fd=10), sockets().replace(b"50123->127.0.0.1:8890", b"50124->127.0.0.1:8890")):
            self.assertEqual((await self.result(rows))["state"], "unknown")
        extra = b"p124\0cother\0\nf4\0n127.0.0.1:50123->127.0.0.1:8890\0TST=ESTABLISHED\0\n"
        self.assertEqual((await self.result(sockets(extra=extra)))["reason"], "ambiguous_local_owner")
        self.assertEqual((await self.result(sockets(), identity(), sockets(pid=124)))["reason"], "socket_owner_changed")
        self.assertEqual((await self.result(sockets(), identity(), sockets(), identity(start="12346:1")))["reason"], "identity_changed")

    async def test_source_name_bytes_and_unavailable_identity_are_explicit(self):
        rows = sockets(name=b"a\n\xffclient")
        fact = await self.result(rows, identity(), rows, identity())
        self.assertIsNone(fact["name"])
        self.assertEqual(import_process(fact), fact)
        failure = json.dumps({"version": 1, "results": [{"pid": 123, "state": "unavailable"}]}).encode()
        self.assertEqual((await self.result(sockets(), failure))["reason"], "identity_unavailable")
        self.assertEqual((await self.result(sockets(), b"{invalid"))["reason"], "lookup_unavailable")

    async def test_queue_deadline_includes_admission_and_stop_is_explicit(self):
        resolver = PeerProcesses("unused")
        await resolver.slots.acquire(); await resolver.slots.acquire()
        with patch("peer_process.LOOKUP_SECONDS", .01):
            self.assertEqual((await resolver.observe(SOURCE, 9))["reason"], "lookup_deadline")
        resolver.slots.release(); resolver.slots.release()
        await resolver.close()
        self.assertEqual((await resolver.observe(SOURCE, 9))["reason"], "lookup_stopped")


class FieldsAndImports(unittest.TestCase):
    def test_lsof_hierarchy_ipv6_mapped_ip_and_non_established_are_not_display_parsed(self):
        rows = socket_records(b"p123\0cname with spaces\0\nf3\0n[::ffff:127.0.0.1]:50123->[::1]:8890\0TST=ESTABLISHED\0\nf4\0n127.0.0.1:1->127.0.0.1:2\0TST=CLOSE_WAIT\0\np0\0f5\0n127.0.0.1:3->127.0.0.1:4\0TST=ESTABLISHED\0")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["endpoint"], (("127.0.0.1", 50123), ("::1", 8890)))
        self.assertEqual(rows[0]["name"], b"name with spaces")

    def test_nested_observation_validated_once_and_copied_with_source_extensions(self):
        source = ClientConnection.observed("proxy_port", SOURCE.peer, SOURCE.listener_address, 1).public()
        source["process"] = {**unknown("no_visible_local_owner"), "source_extra": [None]}
        imported = import_client_connection(source)
        source["process"]["source_extra"].append(1)
        self.assertEqual(imported["process"]["source_extra"], [None])
        for update in ({"pid": 123}, {"reason": ""}, {"observed_at": True}, {"state": "identified"}, {"version": True}, {"scope": "android_app"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                import_client_connection({**imported, "process": {**imported["process"], **update}})
        empty = copy.deepcopy(imported); empty["process"] = None
        self.assertIsNone(import_client_connection(empty)["process"])


class ChildLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_during_late_launch_handshake_retains_and_reaps_actual_child(self):
        owner, created, release = OwnedCommands(), asyncio.Event(), asyncio.Event()
        create = asyncio.create_subprocess_exec
        processes = []
        async def late(*args, **kwargs):
            process = await create(*args, **kwargs)
            processes.append(process); created.set()
            await release.wait()
            return process
        with patch("owned_commands.asyncio.create_subprocess_exec", late):
            task = asyncio.create_task(owner.run([sys.executable, "-c", "import time; time.sleep(30)"], 32))
            await created.wait()
            task.cancel(); await asyncio.sleep(0)
            self.assertTrue(owner.children)
            with self.assertRaisesRegex(RuntimeError, "launch cleanup remains pending"):
                await task
            with self.assertRaisesRegex(ValueError, "command_cleanup_pending"):
                await owner.run([sys.executable, "-c", "pass"], 32)
            release.set()
        await owner.close()
        self.assertFalse(owner.children)
        self.assertTrue(all(process.returncode is not None for process in processes))

    async def test_real_commands_output_cap_failure_and_cancel_reap_children(self):
        owner = OwnedCommands()
        self.assertEqual(await owner.run([sys.executable, "-c", "print('ok')"], 10), b"ok\n")
        with self.assertRaisesRegex(ValueError, "command_output_limit"):
            await owner.run([sys.executable, "-c", "import os; os.write(1,b'x'*100000)"], 32)
        with self.assertRaisesRegex(ValueError, "command_failed"):
            await owner.run([sys.executable, "-c", "raise SystemExit(3)"], 32)
        task = asyncio.create_task(owner.run([sys.executable, "-c", "import time; time.sleep(30)"], 32))
        while not owner.children or any(child.process is None for child in owner.children): await asyncio.sleep(.001)
        processes = [child.process for child in owner.children]
        task.cancel()
        with self.assertRaises(asyncio.CancelledError): await task
        await owner.close()
        self.assertFalse(owner.children)
        self.assertTrue(all(process.returncode is not None for process in processes))

    async def test_cancel_during_final_cleanup_preserves_shared_waiter_for_retry(self):
        owner, exited, finished = OwnedCommands(), asyncio.Event(), asyncio.Event()
        class Transport:
            def close(self): pass
        process = SimpleNamespace(returncode=0, _transport=Transport())
        child = Child(process, asyncio.create_task(exited.wait()), asyncio.create_task(finished.wait()))
        owner.children.add(child)
        cleanup = asyncio.create_task(owner.cleanup(child))
        await asyncio.sleep(0)
        cleanup.cancel()
        with self.assertRaises(asyncio.CancelledError): await cleanup
        self.assertIn(child, owner.children)
        self.assertFalse(child.waiter.cancelled())
        exited.set(); finished.set()
        await owner.close()
        self.assertFalse(owner.children)

    async def test_one_failed_finalizer_does_not_discard_it_or_other_outcomes(self):
        owner = OwnedCommands()
        class Transport:
            fail = True
            def close(self):
                if self.fail: raise OSError("fixture pipe close failed")
        transport = Transport()
        async def done(): return None
        bad = Child(SimpleNamespace(returncode=0, _transport=transport), asyncio.create_task(done()), asyncio.create_task(done()))
        good = Child(SimpleNamespace(returncode=0, _transport=SimpleNamespace(close=lambda: None)), asyncio.create_task(done()), asyncio.create_task(done()))
        owner.children.update((bad, good))
        with self.assertRaisesRegex(RuntimeError, "retry Stop"): await owner.close()
        self.assertEqual(owner.children, {bad})
        transport.fail = False
        await owner.close()
        self.assertFalse(owner.children)


if __name__ == "__main__": unittest.main()
