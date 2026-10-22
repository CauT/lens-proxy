"""Pinned CONNECT translation and instance ownership, independent of wire fixtures."""
from dataclasses import dataclass
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.test import tflow
from mitmproxy.proxy import commands, events, layer
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers.http import HttpLayer, HttpStream, HTTPMode, SendHttp
from mitmproxy.proxy.layers.http._events import RequestData, ResponseData, RequestEndOfMessage, ResponseEndOfMessage, ResponseProtocolError
from mitmproxy.addons.next_layer import NextLayer as SDKNextLayer
from mitmproxy.proxy.layers.tcp import TCPLayer

from connect_tunnel import ConnectHttpStream, admit_sdk
from routing import RoutedHttpLayer


def stream_fixture(mode=HTTPMode.regular):
    context = Context(tflow.tclient_conn(), Options())
    parent = RoutedHttpLayer(context, mode)
    list(parent.make_stream(1))
    stream = parent.streams[1]
    stream.flow = tflow.tflow(resp=True)
    stream.flow.request.method = "CONNECT"
    stream.flow.request.http_version = "HTTP/1.1"
    stream.flow.response = http.Response.make(200, b"")
    stream.flow.client_conn = stream.context.client
    stream.flow.server_conn = stream.context.server
    return parent, stream


class CommandsChild:
    def __init__(self, *values):
        self.values, self.events = values, []

    def handle_event(self, event):
        self.events.append(event)
        yield from self.values


@dataclass
class ProbeHook(commands.StartHook):
    value: object


class BlockingChild(layer.Layer):
    def __init__(self, context):
        super().__init__(context)
        self.completed = False
        self.hook = ProbeHook(object())

    def _handle_event(self, event):
        yield self.hook
        self.completed = True
        yield commands.Log("same hook resumed")


class ConnectTranslation(unittest.TestCase):
    def test_factory_creates_distinct_owned_streams_without_modifying_sdk_class(self):
        parent, first = stream_fixture()
        list(parent.make_stream(3))
        second = parent.streams[3]
        self.assertIs(type(first), ConnectHttpStream)
        self.assertIs(type(second), ConnectHttpStream)
        self.assertIsNot(first, second)
        self.assertIsNot(first.context, second.context)
        plain = HttpLayer(parent.context.fork(), HTTPMode.regular)
        list(plain.make_stream(5))
        self.assertIs(type(plain.streams[5]), HttpStream)

    def test_both_half_closes_preserve_exact_command_and_connection_identity(self):
        _, stream = stream_fixture()
        for connection in (stream.context.client, stream.context.server):
            command = commands.CloseTcpConnection(connection, half_close=True)
            stream.child_layer = CommandsChild(command)
            result = list(stream.passthrough(RequestData(1, b"source")))
            self.assertEqual(len(result), 1)
            self.assertIs(result[0], command)
            self.assertIs(result[0].connection, connection)
            self.assertTrue(result[0].half_close)

    def test_stream_events_become_the_original_connection_events(self):
        _, stream = stream_fixture()
        values = ((RequestData(1, b"client"), stream.context.client, b"client"),
                  (ResponseData(1, b"server"), stream.context.server, b"server"),
                  (RequestEndOfMessage(1), stream.context.client, None),
                  (ResponseEndOfMessage(1), stream.context.server, None))
        for event, connection, data in values:
            with self.subTest(event=event):
                child = CommandsChild(); stream.child_layer = child
                self.assertEqual(list(stream.passthrough(event)), [])
                translated, = child.events
                self.assertIs(translated.connection, connection)
                self.assertIsInstance(translated, events.ConnectionClosed if data is None else events.DataReceived)
                if data is not None:
                    self.assertEqual(translated.data, data)

    def test_only_client_data_and_full_close_are_http_translated(self):
        _, stream = stream_fixture()
        to_server = commands.SendData(stream.context.server, b"request")
        to_client = commands.SendData(stream.context.client, b"response")
        full_server = commands.CloseConnection(stream.context.server)
        full_client = commands.CloseConnection(stream.context.client)
        timer, log = commands.RequestWakeup(.1), commands.Log("source")
        stream.child_layer = CommandsChild(to_server, to_client, full_server, full_client, timer, log)
        result = list(stream.passthrough(events.Start()))
        self.assertIs(result[0], to_server)
        self.assertIsInstance(result[1], SendHttp)
        self.assertEqual(result[1].event, ResponseData(1, b"response"))
        self.assertIs(result[2], full_server)
        self.assertIsInstance(result[3].event, ResponseProtocolError)
        self.assertIs(result[4], timer); self.assertIs(result[5], log)

    def test_blocked_child_hook_resumes_through_original_parent_command_sources(self):
        parent, stream = stream_fixture()
        child = BlockingChild(stream.context)
        stream.child_layer = child
        stream._handle_event = stream.passthrough
        result = list(parent.event_to_child(stream, RequestData(1, b"source")))
        self.assertEqual(result, [child.hook])
        self.assertIs(parent.command_sources[child.hook], stream)
        self.assertFalse(child.completed)
        continued = list(parent.handle_event(events.HookCompleted(child.hook)))
        self.assertTrue(child.completed)
        self.assertEqual(len(continued), 1)
        self.assertEqual(continued[0].message, "same hook resumed")
        self.assertNotIn(child.hook, parent.command_sources)

    def test_h2_h3_upgrades_ordinary_http_and_nonsuccess_delegate_sdk(self):
        cases = (("HTTP/2.0", "CONNECT", 200, False, HTTPMode.regular),
                 ("HTTP/3", "CONNECT", 200, False, HTTPMode.regular),
                 ("HTTP/1.1", "GET", 200, False, HTTPMode.regular),
                 ("HTTP/1.1", "CONNECT", 502, False, HTTPMode.regular),
                 ("HTTP/1.1", "GET", 101, True, HTTPMode.regular),
                 ("HTTP/1.1", "CONNECT", 200, False, HTTPMode.transparent))
        def delegated(owner, event):
            yield marker
        marker = commands.Log("SDK delegate")
        for protocol, method, status, websocket, mode in cases:
            with self.subTest(protocol=protocol, method=method, status=status, mode=mode):
                _, stream = stream_fixture(mode)
                stream.flow.request.http_version = protocol
                stream.flow.request.method = method
                stream.flow.response.status_code = status
                if websocket:
                    from mitmproxy.websocket import WebSocketData
                    stream.flow.websocket = WebSocketData()
                with patch.object(HttpStream, "passthrough", delegated):
                    self.assertEqual(list(stream.passthrough(events.Start())), [marker])

    def test_missing_child_is_rejected_instead_of_losing_half_close(self):
        _, stream = stream_fixture()
        with self.assertRaisesRegex(RuntimeError, "owned child"):
            list(stream.passthrough(RequestEndOfMessage(1)))

    def test_sdk_version_and_signature_drift_fail_admission(self):
        admit_sdk()
        with patch("connect_tunnel.version.VERSION", "99.0"), self.assertRaisesRegex(RuntimeError, "pinned"):
            admit_sdk()
        def changed(owner, stream_id, incompatible):
            yield from ()
        with patch.object(HttpLayer, "make_stream", changed), self.assertRaisesRegex(RuntimeError, "contracts"):
            admit_sdk()


class ExcludedConnectSelection(unittest.TestCase):
    def pending(self):
        parent, stream = stream_fixture()
        stream.flow.response = None
        stream.context.server.address = ("example.test", 443)
        return parent, stream

    def sdk_context(self, policy):
        return patch("connect_tunnel.ctx", SimpleNamespace(
            master=SimpleNamespace(addons=SimpleNamespace(get=lambda name: policy)), options=Options()))

    def test_included_unknown_and_h2_keep_original_deferred_selection(self):
        marker = commands.Log("original deferred path")
        def original(owner):
            yield marker
        for excluded, protocol in ((False, "HTTP/1.1"), (None, "HTTP/1.1"), (True, "HTTP/2.0")):
            with self.subTest(excluded=excluded, protocol=protocol):
                _, stream = self.pending()
                stream.flow.request.http_version = protocol
                policy = SDKNextLayer()
                with self.sdk_context(policy), patch.object(policy, "_ignore_connection", return_value=excluded), patch.object(HttpStream, "handle_connect_regular", original):
                    self.assertEqual(list(stream.handle_connect_regular()), [marker])
                    self.assertIsNone(stream.child_layer)

    def test_excluded_owner_dials_before_success_and_freezes_opaque_child(self):
        _, stream = self.pending()
        policy = SDKNextLayer()
        marker = commands.Log("normal CONNECT response")
        def finish(owner):
            yield marker
        with self.sdk_context(policy), patch.object(policy, "_ignore_connection", return_value=True) as select, patch.object(HttpStream, "handle_connect_finish", finish):
            generator = stream.handle_connect_regular()
            opening = next(generator)
            self.assertIsInstance(opening, commands.OpenConnection)
            self.assertIs(opening.connection, stream.context.server)
            self.assertIsNone(stream.flow.response)
            self.assertIs(generator.send(None), marker)
            self.assertIs(type(stream.child_layer), TCPLayer)
            self.assertIsNone(stream.child_layer.flow)
            select.assert_called_once_with(stream.context, b"", b"")

    def test_refusal_has_a_normal_502_response_and_unsupported_owner_fails_closed(self):
        for policy in (SDKNextLayer(), None):
            with self.subTest(policy=policy):
                _, stream = self.pending()
                marker = commands.Log("normal error response")
                def finish(owner):
                    yield marker
                with self.sdk_context(policy), patch.object(HttpStream, "handle_connect_finish", finish):
                    if policy is None:
                        self.assertEqual(list(stream.handle_connect_regular()), [marker])
                    else:
                        with patch.object(policy, "_ignore_connection", return_value=True):
                            generator = stream.handle_connect_regular()
                            self.assertIsInstance(next(generator), commands.OpenConnection)
                            self.assertIs(generator.send("connection refused"), marker)
                    self.assertEqual(stream.flow.response.status_code, 502)
                    self.assertIs(type(stream.child_layer), layer.NextLayer)
