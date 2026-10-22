"""Per-flow upstream dial overrides for pinned mitmproxy 12.2.1 HTTP layers.

Changing server_connect alone is insufficient: pooled connections bypass it, and
that hook does not carry the URL needed for URL-glob rules. Select the dial target
at its owner, GetHttpConnection, while retaining the HTTP Request representation.
"""
from mitmproxy.proxy import events
from mitmproxy.connection import Server
from mitmproxy.proxy import tunnel
from mitmproxy.proxy.layers import tls, quic
from mitmproxy.proxy.layers.http import HttpLayer, HttpClient
from mitmproxy.proxy.layers.http._upstream_proxy import HttpUpstreamProxy
from mitmproxy.proxy.layers.http._events import ResponseHeaders, ResponseData, ResponseTrailers
from upstream_tls import install_upstream_tls_layer
from connect_tunnel import ConnectHttpStream
from upstream_proxy import install_http_upstream_layer


class RoutedHttpLayer(HttpLayer):
    def make_stream(self, stream_id):
        context = self.context.fork()
        self.streams[stream_id] = ConnectHttpStream(context, stream_id)
        yield from self.event_to_child(self.streams[stream_id], events.Start())

    def event_to_child(self, child, event):
        # An edited upstream method must not redefine the original frontend
        # method's wire semantics. Keep a HEAD client's captured upstream body,
        # but never serialize DATA/trailers to that frontend transport. Per-stream
        # lookup preserves concurrent HTTP/2 requests and leaves inbound capture
        # events untouched. ResponseEndOfMessage still owns normal completion.
        if child is self.connections.get(self.context.client):
            stream = self.streams.get(getattr(event, "stream_id", None))
            flow = getattr(stream, "flow", None)
            if flow and flow.metadata.get("lens_frontend_method") == "HEAD" and flow.request.method != "HEAD":
                if isinstance(event, (ResponseData, ResponseTrailers)):
                    return
                if isinstance(event, ResponseHeaders):
                    event = ResponseHeaders(event.stream_id, event.response, end_stream=True)
        if isinstance(event, events.Start):
            replacement = install_http_upstream_layer(install_upstream_tls_layer(child))
            if replacement is not child:
                for connection, selected in list(self.connections.items()):
                    if selected is child:
                        self.connections[connection] = replacement
                child = replacement
        yield from super().event_to_child(child, event)

    def get_connection(self, event, *, reuse=True):
        stream = self.command_sources.get(event)
        flow = getattr(stream, "flow", None)
        address = flow.metadata.get("lens_dns_address") if flow else None
        if not address:
            yield from super().get_connection(event, reuse=reuse)
            return
        event.address = (address, event.address[1])
        # A DNS rule can vary by URL on one H2 connection. Do not accidentally
        # reuse a connection admitted for another hostname, IP rule, or URL.
        # Own construction of this fresh DNS-routed connection. Repairing only
        # OpenConnection misses the logical origin when an HTTP proxy owns the
        # physical socket. Set SNI before TLS context creation, and use CONNECT
        # for a DNS override so an upstream cannot resolve the original URL host
        # instead. Adapted from pinned mitmproxy's MIT-licensed get_connection;
        # its complete notice is retained in THIRD_PARTY_NOTICES.md.
        context = self.context.fork()
        context.server = Server(address=event.address, transport_protocol=event.transport_protocol)
        stack = tunnel.LayerStack()
        if event.via:
            context.server.via = event.via
            stack /= HttpUpstreamProxy.make(context, True)
            if not event.tls and not (flow.request.is_http2 or flow.request.is_http3):
                flow.request.authority = ""
        if event.tls:
            context.server.sni = flow.request.host
            if event.transport_protocol == "tcp":
                stack /= tls.ServerTLSLayer(context)
            elif event.transport_protocol == "udp":
                stack /= quic.ServerQuicLayer(context)
            else:
                raise RuntimeError("Unsupported DNS-routed TLS transport")
        stack /= HttpClient(context)
        self.connections[context.server] = stack[0]
        self.waiting_for_establishment[context.server].append(event)
        flow.metadata["lens_dns_dial_address"] = list(event.address)
        yield from self.event_to_child(stack[0], events.Start())


def install_routing_layer(next_layer):
    """Replace only fresh instance-owned HTTP layers selected by NextLayer.

    This binds the 12.2.1 HttpLayer.get_connection/command_sources contracts.
    No shared classes, SSL contexts, or module functions are monkeypatched.
    """
    owner, attribute = next_layer, "layer"
    selected = getattr(owner, attribute, None)
    while selected is not None:
        if type(selected) is HttpLayer:
            if selected.streams or selected.connections or selected.command_sources:
                raise RuntimeError("DNS routing requires a fresh mitmproxy 12.2.1 HTTP layer")
            context = selected.context
            index = context.layers.index(selected)
            context.layers.remove(selected)
            replacement = RoutedHttpLayer(context, selected.mode)
            context.layers.remove(replacement)
            context.layers.insert(index, replacement)
            setattr(owner, attribute, replacement)
            return
        owner, attribute = selected, "child_layer"
        selected = getattr(owner, attribute, None)
