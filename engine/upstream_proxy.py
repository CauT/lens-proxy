"""Explicit HTTP upstream selection for the pinned SDK's upstream mode."""
from dataclasses import dataclass
from urllib.parse import urlsplit
import re

from mitmproxy import ctx
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.layers.http._upstream_proxy import HttpUpstreamProxy
from mitmproxy.proxy.tunnel import TunnelState

from endpoints import canonical_host


@dataclass(frozen=True)
class HTTPUpstreamProxy:
    host: str
    port: int

    @property
    def url(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    @property
    def mode(self):
        return f"upstream:{self.url}@127.0.0.1:0"

    @classmethod
    def parse(cls, value):
        if value is None or value == "":
            return None
        if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError("HTTP upstream proxy must be an explicit http://host:port URL")
        parsed = urlsplit(value)
        if (parsed.scheme != "http" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or "?" in value or "#" in value
                or parsed.port is None or not 1 <= parsed.port <= 65535):
            raise ValueError("HTTP upstream proxy requires http://host:port without credentials, path, query or fragment")
        return cls(canonical_host(parsed.hostname), parsed.port)


def require_http_only(proxy, *, socks=0, reverse=0, tcp=(), udp=()):
    if proxy is not None and (socks or reverse or tcp or udp):
        raise ValueError("HTTP upstream proxy currently supports the HTTP/HTTPS listener only; "
                         "disable additional SOCKS, reverse, TCP and UDP listeners before Start")


def install_http_upstream_layer(root):
    """Replace fresh instance-owned SDK tunnel layers, never shared classes."""
    owner, selected = None, root
    while selected is not None:
        if type(selected) is HttpUpstreamProxy:
            if selected.tunnel_state is not TunnelState.INACTIVE:
                raise RuntimeError("HTTP upstream adapter requires a fresh mitmproxy 12.2.1 tunnel")
            context = selected.context
            index = context.layers.index(selected)
            context.layers.remove(selected)
            replacement = BoundedHTTPUpstreamProxy(context, selected.tunnel_connection, selected.send_connect)
            replacement.child_layer = selected.child_layer
            context.layers.remove(replacement)
            context.layers.insert(index, replacement)
            if owner is None:
                return replacement
            owner.child_layer = replacement
            return root
        owner, selected = selected, getattr(selected, "child_layer", None)
    return root


class BoundedHTTPUpstreamProxy(HttpUpstreamProxy):
    """Bound CONNECT negotiation at the SDK's one parser/completion owner."""
    wakeup = None

    def start_handshake(self):
        if self.send_connect:
            seconds = ctx.master.addons.get("lens").network.settings["connect_timeout_seconds"]
            self.wakeup = commands.RequestWakeup(seconds)
            yield self.wakeup
        yield from super().start_handshake()

    def _handle_event(self, event):
        if isinstance(event, events.Wakeup) and event.command is self.wakeup:
            if self.tunnel_state is TunnelState.ESTABLISHING:
                error = f"HTTP upstream CONNECT negotiation timed out after {self.wakeup.delay} s."
                self.conn.error = error
                yield from self.on_handshake_error(error)
                yield from self._handshake_finished(error)
            return
        yield from super()._handle_event(event)

    def receive_handshake_data(self, data):
        if self.send_connect:
            header = bytes(self.buf) + data
            end = re.search(br"\n\r?\n", header)
            if (end.end() if end else len(header)) > 64 * 1024:
                return False, "HTTP upstream CONNECT response headers exceed 64 KiB"
        return (yield from super().receive_handshake_data(data))
