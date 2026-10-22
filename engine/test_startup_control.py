"""Real supervised reader children; controlled stalls, not OS-permission claims."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from mitmproxy.test import tflow
from engine import Lens


class StartupControl(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-startup-control-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.lens = Lens(None, self.directory, 8890)
        self.lens.command_reader = asyncio.StreamReader()
        self.addAsyncCleanup(self.lens.close)
        self.marker = self.directory / "reader-entered"
        self.processes = []
        self.spawn = asyncio.create_subprocess_exec

    async def stalled_reader(self, *args, **kwargs):
        self.assertEqual(Path(args[1]).name, "certificate_inputs.py")
        # The production supervisor must reap a real reader even if the child
        # ignores graceful termination, as a protected open may do on the host.
        source = "import pathlib,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);pathlib.Path(__import__('sys').argv[1]).touch();time.sleep(60)"
        process = await self.spawn(sys.executable, "-c", source, str(self.marker), **kwargs)
        self.processes.append(process)
        return process

    async def entered(self):
        async with asyncio.timeout(3):
            while not self.marker.exists():
                await asyncio.sleep(.01)

    def frame(self, command, identity="stop", **fields):
        self.lens.command_reader.feed_data((json.dumps({"command": command, "command_id": identity, **fields}) + "\n").encode())

    async def test_stop_reaps_blocked_upstream_read_and_retains_workspace_owner(self):
        flow = tflow.tflow(resp=True)
        flow.response.raw_content = b"\0\xffretained response"
        self.lens.flows[flow.id] = flow
        room = self.lens.sessions.capture.id
        with patch("owned_commands.asyncio.create_subprocess_exec", self.stalled_reader):
            operation = asyncio.create_task(self.lens.prepare_tls([], self.directory / "selected.pem"))
            await self.entered()
            self.frame("stop_capture")
            await asyncio.wait_for(operation, 3)
        self.assertTrue(self.lens.inspect_only)
        self.assertEqual(self.lens.sessions.capture.id, room)
        self.assertEqual(self.lens.pending_startup_command["command_id"], "stop")
        self.assertFalse(self.lens.certificate_inputs.commands.children)
        self.assertTrue(all(p.returncode is not None for p in self.processes))
        events = []
        with patch("engine.emit", lambda event, **v: events.append({"event": event, **v})):
            await self.lens.running()
            self.lens.command_reader.feed_eof()
            await asyncio.sleep(0)
        self.assertIsNone(self.lens.pending_startup_command)
        self.assertTrue(self.lens.network.closed)
        self.assertTrue(self.lens.sdk_connections.closed)
        self.assertTrue(any(v.get("command_id") == "stop" and v.get("value") == {"capture_stopped": True, "workspace_revision": self.lens.workspace_revision.current()} for v in events))
        self.assertEqual(self.lens.flows[flow.id].response.raw_content, b"\0\xffretained response")

    async def test_pending_commands_reject_then_client_identity_read_can_be_stopped(self):
        events = []
        selection = {"host": "localhost", "port": 443, "path": str(self.directory / "identity.pem")}
        with patch("owned_commands.asyncio.create_subprocess_exec", self.stalled_reader), patch("engine.emit", lambda event, **v: events.append({"event": event, **v})):
            operation = asyncio.create_task(self.lens.prepare_tls([selection], None))
            await self.entered()
            self.frame("configure", "early", rules=[])
            self.frame("stop_capture")
            await asyncio.wait_for(operation, 3)
        self.assertTrue(any(v.get("command_id") == "early" and "startup is pending" in v.get("message", "") for v in events))
        self.assertFalse(self.lens.client_certificates.public())
        self.assertFalse(self.lens.certificate_inputs.commands.children)
        self.assertTrue(all(p.returncode is not None for p in self.processes))

    async def test_outer_cancellation_joins_reader_and_releases_sole_stdin_consumer(self):
        with patch("owned_commands.asyncio.create_subprocess_exec", self.stalled_reader):
            operation = asyncio.create_task(self.lens.prepare_tls([], self.directory / "selected.pem"))
            await self.entered()
            operation.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await operation
        self.assertFalse(self.lens.certificate_inputs.commands.children)
        self.assertTrue(all(p.returncode is not None for p in self.processes))
        self.frame("network_status", "next-owner")
        frame = await asyncio.wait_for(self.lens.command_reader.readline(), 1)
        self.assertEqual(json.loads(frame)["command_id"], "next-owner")

    async def test_eof_does_not_bypass_subsequent_listener_startup_admission(self):
        self.lens.command_reader.feed_eof()
        await self.lens.prepare_tls([], None)
        self.assertFalse(self.lens.finished.is_set())
        self.assertFalse(self.lens.inspect_only)
        self.assertTrue(self.lens.command_reader.at_eof())


if __name__ == "__main__":
    unittest.main()
