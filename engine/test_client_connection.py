import asyncio
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mitmproxy.test import tflow
from client_connection import ClientConnection, import_client_connection
from engine import summary
from har import export_flow, import_entry, snapshot_flow
from network import ProxyRelays


class ConnectionFacts(unittest.TestCase):
    def setUp(self):
        self.fact = ClientConnection.observed("proxy_port", ("127.0.0.1", 50001), ("127.0.0.1", 8890), 1234.5).public()

    def test_source_spelling_unknown_extensions_and_mutable_input_ownership_survive_har(self):
        value = {**self.fact, "peer": ["2001:0db8::1", 50001], "extra_source": {"unknown": [1, None]}}
        flow = tflow.tflow(resp=True)
        document = export_flow(flow)
        document["_lensClientConnection"] = value
        imported = import_entry(document)
        expected = copy.deepcopy(value)
        value["extra_source"]["unknown"].append(2)
        self.assertEqual(export_flow(imported)["_lensClientConnection"], expected)
        self.assertEqual(summary(imported)["client_connection"], expected)
        self.assertGreater(imported.metadata["lens_har_metadata_bytes"], 0)

    def test_invalid_identity_address_listener_and_clock_fail_closed(self):
        for update in ({"version": True}, {"version": 2}, {"id": "bad"}, {"listener": "unrecognized"}, {"listener": []},
                       {"peer": ["not-an-ip", 1]}, {"peer": ["127.0.0.1", True]},
                       {"listener_address": ["127.0.0.1", 0]}, {"accepted_at": float("inf")},
                       {"accepted_at": True}, {"accepted_at": 10**400}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                import_client_connection({**self.fact, **update})

    def test_missing_and_explicit_unknown_do_not_become_internal_loopback_facts(self):
        document = export_flow(tflow.tflow(resp=True))
        imported = import_entry(document)
        self.assertIsNone(summary(imported)["client_connection"])
        self.assertNotIn("_lensClientConnection", export_flow(imported))
        document["_lensClientConnection"] = None
        imported = import_entry(document)
        self.assertIsNone(summary(imported)["client_connection"])
        self.assertIsNone(export_flow(imported)["_lensClientConnection"])

    def test_snapshot_freezes_source_facts_separately_from_live_connection_owner(self):
        flow = tflow.tflow(resp=True)
        flow.metadata["lens_client_connection"] = self.fact
        frozen = snapshot_flow(flow)
        exported = export_flow(flow)
        exported["_lensClientConnection"]["peer"][1] = 50003
        self.assertEqual(self.fact["peer"][1], 50001)
        self.fact["peer"][1] = 50002
        self.assertEqual(export_flow(frozen)["_lensClientConnection"]["peer"][1], 50001)


class RelayFactsOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_bootstrap_failure_retains_admission_and_stream_until_cleanup(self):
        class Writer:
            closed = False
            def close(self): self.closed = True
            async def wait_closed(self): pass
        def failed(): raise RuntimeError("fixture observation bootstrap failed")
        relay, writer = ProxyRelays(), Writer()
        with self.assertRaisesRegex(RuntimeError, "bootstrap"):
            relay.accept(object(), writer, ("127.0.0.1", 1), capture_factory=failed)
        self.assertTrue(writer.closed)
        self.assertEqual(relay.status()["active_connections"], 1)
        await relay.close()
        self.assertFalse(relay.connections or relay.closing or relay.close_waiters or relay.client_bindings)

    async def test_binding_lookup_requires_both_owned_socket_endpoints(self):
        relay = ProxyRelays()
        source = ClientConnection.observed("proxy_port", ("127.0.0.1", 50001), ("127.0.0.1", 8890), 1)
        relay.client_bindings[(("127.0.0.1", 60001), ("127.0.0.1", 60002))] = source
        client = SimpleNamespace(id="sdk-client", peername=("127.0.0.1", 60001), sockname=("127.0.0.1", 60002))
        relay.observe_client(client.id, client.peername, client.sockname)
        self.assertEqual(relay.client_source(client.id), source.public())
        client.sockname = ("127.0.0.1", 60003)
        self.assertEqual(relay.client_source(client.id), source.public(), "protocol-time mutation must not reinterpret the observed socket")
        relay.observe_client("wrong-socket", client.peername, client.sockname)
        self.assertIsNone(relay.client_source("wrong-socket"))
        relay.observe_client("unknown", None, None)
        self.assertIsNone(relay.client_source("unknown"))
        relay.forget_client(client.id)
        self.assertIsNone(relay.client_source(client.id))

    async def test_duplicate_sdk_identity_is_unknown_even_at_capacity(self):
        relay = ProxyRelays()
        source = ClientConnection.observed("proxy_port", ("127.0.0.1", 50001), ("127.0.0.1", 8890), 1)
        relay.client_bindings[(("127.0.0.1", 60001), ("127.0.0.1", 60002))] = source
        with patch("network.MAX_CONNECTIONS", 1):
            relay.observe_client("client", ("127.0.0.1", 60001), ("127.0.0.1", 60002))
            self.assertEqual(relay.client_source("client"), source.public())
            relay.observe_client("client", ("127.0.0.1", 60003), ("127.0.0.1", 60002))
            self.assertIsNone(relay.client_source("client"))
            relay.observe_client("excess", ("127.0.0.1", 60001), ("127.0.0.1", 60002))
            self.assertEqual(len(relay.sdk_clients), 1)


if __name__ == "__main__":
    unittest.main()
