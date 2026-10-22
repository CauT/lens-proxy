"""Instance-owned HTTP/1 CONNECT half-close translation for mitmproxy 12.2.1.

The SDK's HttpStream.passthrough converts TCP half-closes to full transport
closes. Keep the original half-close command at that producing boundary.
HTTP/2, HTTP/3, WebSocket upgrades and ordinary HTTP retain SDK behavior.
"""
import inspect

from mitmproxy import version, ctx, http
from mitmproxy.addons.next_layer import NextLayer as SDKNextLayer
from mitmproxy.proxy.layers.tcp import TCPLayer
from mitmproxy.proxy import layer
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.layers.http import HttpLayer, HttpStream, HTTPMode, SendHttp
from mitmproxy.proxy.layers.http._events import (
    RequestData, ResponseData, RequestEndOfMessage, ResponseEndOfMessage,
    ResponseProtocolError,
)
from mitmproxy.proxy.layers.http._events import ErrorCode


def admit_sdk():
    """Refuse incompatible adapters before any Lens listener can be created."""
    signatures = ((HttpStream.handle_connect_regular, ("self",)),
                  (HttpStream.handle_connect_upstream, ("self",)),
                  (HttpStream.handle_connect_finish, ("self",)),
                  (SDKNextLayer._ignore_connection, ("self", "context", "data_client", "data_server")),
                  (HttpLayer.make_stream, ("self", "stream_id")),
                  (HttpStream.passthrough, ("self", "event")),
                  (HttpStream.__init__, ("self", "context", "stream_id")),
                  (commands.CloseTcpConnection.__init__, ("self", "connection", "half_close")))
    if (version.VERSION != "12.2.1" or not issubclass(commands.CloseTcpConnection, commands.CloseConnection)
            or any(tuple(inspect.signature(method).parameters) != parameters for method, parameters in signatures)):
        raise RuntimeError("Lens CONNECT half-close adapter requires pinned mitmproxy 12.2.1 stream/command contracts")


class ConnectHttpStream(HttpStream):
    def handle_connect_upstream(self):
        from mitmproxy.proxy.layers.http._upstream_proxy import HttpUpstreamProxy
        from upstream_proxy import install_http_upstream_layer
        self.child_layer = install_http_upstream_layer(HttpUpstreamProxy.make(self.context, True)[0])
        policy = ctx.master.addons.get("nextlayer")
        if self.is_http1_connect_request() and type(policy) is SDKNextLayer and policy._ignore_connection(self.context, b"", b"") is True:
            # The destination is already explicitly excluded. Waiting for client
            # protocol bytes after CONNECT would deadlock server-first tunnels.
            self.child_layer.child_layer = TCPLayer(self.context, ignore=not ctx.options.show_ignored_hosts)
        yield from self.handle_connect_finish()

    def is_http1_connect_request(self):
        return (self.mode in (HTTPMode.regular, HTTPMode.upstream) and self.flow.request.method == "CONNECT"
                and self.flow.request.http_version in ("HTTP/1.0", "HTTP/1.1")
                and self.context.client.transport_protocol == "tcp")

    def handle_connect_regular(self):
        if not self.is_http1_connect_request() or self.flow.response is not None:
            yield from super().handle_connect_regular()
            return
        policy = ctx.master.addons.get("nextlayer")
        if type(policy) is not SDKNextLayer:
            # A changed/missing policy owner must not select an arbitrary raw
            # protocol layer or wait forever after an adapter exception.
            self.flow.response = http.Response.make(502, b"Lens CONNECT policy owner is unsupported")
            self.child_layer = layer.NextLayer(self.context)
            yield from self.handle_connect_finish()
            return
        # Reuse the actual SDK ignore owner. Included/unknown targets retain
        # deferred TLS classification; asking on empty data would select rawtcp.
        excluded = policy._ignore_connection(self.context, b"", b"")
        if excluded is not True:
            yield from super().handle_connect_regular()
            return
        ignore_messages = not ctx.options.show_ignored_hosts
        error = yield commands.OpenConnection(self.context.server)
        if error:
            self.flow.response = http.Response.make(502,
                f"Cannot connect excluded CONNECT destination: {error}".encode("utf-8", "replace"),
                {"Content-Type": "text/plain; charset=utf-8"})
            self.child_layer = layer.NextLayer(self.context)
        else:
            # Already connected before acknowledging success. This permits a
            # server greeting and a client FIN with no preceding payload bytes.
            self.child_layer = TCPLayer(self.context, ignore=ignore_messages)
        yield from self.handle_connect_finish()

    def is_http1_connect(self):
        flow = self.flow
        return (self.is_http1_connect_request()
                and flow.response is not None and 200 <= flow.response.status_code < 300
                and flow.response.http_version in ("HTTP/1.0", "HTTP/1.1")
                and flow.websocket is None and self.context.client.transport_protocol == "tcp")

    def passthrough(self, event):
        if not self.is_http1_connect():
            yield from super().passthrough(event)
            return
        if self.child_layer is None:
            raise RuntimeError("Successful CONNECT requires an owned child protocol layer")
        # Consume the same HTTP-stream events as the SDK. Connection identity
        # remains the stream's actual client/server, never a URL-derived socket.
        if isinstance(event, RequestData):
            event = events.DataReceived(self.context.client, event.data)
        elif isinstance(event, ResponseData):
            event = events.DataReceived(self.context.server, event.data)
        elif isinstance(event, RequestEndOfMessage):
            event = events.ConnectionClosed(self.context.client)
        elif isinstance(event, ResponseEndOfMessage):
            event = events.ConnectionClosed(self.context.server)
        for command in self.child_layer.handle_event(event):
            if isinstance(command, commands.CloseTcpConnection) and command.half_close:
                # This is the original command, including its target identity.
                # Let the connection owner clear CAN_WRITE while CAN_READ lives.
                yield command
            elif isinstance(command, commands.SendData) and command.connection == self.context.client:
                yield SendHttp(ResponseData(self.stream_id, command.data), self.context.client)
            elif isinstance(command, commands.CloseConnection) and command.connection == self.context.client:
                yield SendHttp(ResponseProtocolError(self.stream_id, "EOF", ErrorCode.PASSTHROUGH_CLOSE),
                               self.context.client)
            else:
                # In CONNECT there is no HTTP server connection. Blocking
                # commands/hooks and their callbacks retain their exact objects.
                yield command


admit_sdk()
