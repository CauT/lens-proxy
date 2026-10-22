"""Actual stopped-listener lifecycle with the same bounded session owner alive."""
import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import tempfile
import time
import unittest

import httpx
from test_e2e import EngineHarness, certificate_fixture, start_fixture


class StoppedSessionAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-stopped-session-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        ca, _, _ = certificate_fixture(self.directory, "stopped")
        self.origin, _ = start_fixture("Stopped session")
        self.addCleanup(self.origin.server_close)
        self.addCleanup(self.origin.shutdown)
        self.engine = EngineHarness(self.directory, ca)
        self.addCleanup(self.engine.close)
        self.url = f"http://127.0.0.1:{self.origin.server_port}"

    def client(self):
        return httpx.Client(proxy=self.engine.proxy, trust_env=False, timeout=5)

    def test_stop_closes_listener_but_retains_all_details_and_full_exports(self):
        ids = []
        with self.client() as client:
            for suffix in ("one", "two"):
                url = self.url + "/" + suffix
                client.post(url, content=b"\x00\xffstopped " + suffix.encode()).raise_for_status()
                ids.append(self.engine.flow(url)["id"])
        before = [self.engine.command("detail", id=identity)[1] for identity in ids]
        stopped = self.engine.command("stop_capture")[1]
        self.assertEqual(set(stopped), {"capture_stopped", "workspace_revision"})
        self.assertIs(stopped["capture_stopped"], True)
        saved = self.engine.command("save_workspace", path=str(self.directory / "stopped.lens.json"))[1]
        self.assertEqual(saved["workspace_revision"], stopped["workspace_revision"])
        self.assertEqual(saved["current_workspace_revision"], stopped["workspace_revision"])
        self.assertIsNone(self.engine.process.poll())
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", self.engine.port), timeout=.5)
        self.assertEqual([self.engine.command("detail", id=identity)[1] for identity in reversed(ids)], list(reversed(before)))
        for identity, expected in zip(ids, before):
            body = self.engine.command("export_body", id=identity, side="request")[1]
            self.assertEqual(base64.b64decode(body["base64"]), base64.b64decode(expected["request_body_base64"]))
        self.assertEqual(self.engine.command("stop_capture")[1], stopped)
        self.engine.command("save_har", path=str(self.directory / "stopped.har"))
        self.engine.close()
        self.assertEqual(self.engine.process.returncode, 0)

    def test_stop_aborts_breakpoint_and_keeps_its_final_error_readable(self):
        url = self.url + "/paused"
        self.engine.configure([{"kind": "breakpoint_request", "match": url, "timeout_seconds": 30}])
        def request():
            with self.client() as client:
                return client.post(url, content=b"paused bytes")
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(request)
            paused = self.engine.flow(url, state="paused")
            self.engine.command("stop_capture")
            with self.assertRaises((httpx.NetworkError, httpx.RemoteProtocolError)):
                pending.result(timeout=3)
        detail = self.engine.command("detail", id=paused["id"])[1]
        self.assertEqual(detail["state"], "error")
        self.assertIn("Lens stopped", detail["error"])
        self.assertEqual(detail["request_body"], "paused bytes")
        self.assertEqual(self.origin.history, [])

    def test_connection_end_observations_are_not_promoted_into_an_earlier_save(self):
        client = self.client()
        self.addCleanup(client.close)
        url = self.url + '/keepalive-save'
        client.post(url, content=b'finished response; connection remains open').raise_for_status()
        self.engine.flow(url, state='complete')
        first = self.engine.command('save_workspace', path=str(self.directory/'before-close.lens.json'))[1]
        entry = self.engine.command('export_har')[1]['log']['entries'][0]
        self.assertIsNone(entry['_lensTiming']['clientConnection']['timestamp_end'])
        client.close()
        deadline = time.monotonic() + 5
        while True:
            entry = self.engine.command('export_har')[1]['log']['entries'][0]
            if entry['_lensTiming']['clientConnection']['timestamp_end'] is not None:
                break
            self.assertLess(time.monotonic(), deadline, 'Client disconnect did not become observable')
            time.sleep(.02)
        after = self.engine.command('save_workspace', path=str(self.directory/'after-close.lens.json'))[1]
        self.assertNotEqual(first['workspace_revision'], after['workspace_revision'], 'Connection timing changed without advancing workspace state')

        second = self.client()
        self.addCleanup(second.close)
        url = self.url + '/keepalive-stop'
        second.post(url, content=b'quiet save before Stop').raise_for_status()
        self.engine.flow(url, state='complete')
        saved = self.engine.command('save_workspace', path=str(self.directory/'before-stop.lens.json'))[1]
        stopped = self.engine.command('stop_capture')[1]
        self.assertNotEqual(saved['workspace_revision'], stopped['workspace_revision'], 'Stop finalized connection timing without requiring confirmation')

    def test_stopped_owner_rejects_traffic_commands_and_reports_missing_detail(self):
        self.engine.command("stop_capture")
        for command in ("compose", "replay", "repeat", "resume"):
            with self.assertRaisesRegex(AssertionError, "Capture is stopped"):
                self.engine.command(command)
        with self.assertRaisesRegex(AssertionError, "Command detail failed"):
            self.engine.command("detail", id="missing")
        self.assertIsNone(self.engine.process.poll())
        self.assertEqual(self.origin.history, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
