"""Instance-owned upstream TLS read termination for pinned mitmproxy 12.2.1.

receive_data is adapted from mitmproxy's TLSLayer under its MIT license:
Copyright (c) 2013, Aldo Cortesi. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
from logging import WARNING

from OpenSSL import SSL
from mitmproxy.connection import ConnectionState
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.layers.tls import ServerTLSLayer


class TerminatingServerTLSLayer(ServerTLSLayer):
    def __init__(self, context, conn=None):
        super().__init__(context, conn)
        self.fatal_read_closed = False

    def receive_data(self, data):
        if data:
            self.tls.bio_write(data)
        plaintext = bytearray()
        closed, fatal = False, False
        while True:
            try:
                plaintext.extend(self.tls.recv(65535))
            except SSL.WantReadError:
                break
            except SSL.ZeroReturnError:
                closed = True
                break
            except (SSL.WantWriteError, SSL.WantX509LookupError):
                break
            except SSL.Error as exc:
                # TLS 1.3 can reject a missing client certificate *after* the
                # client-side handshake reports success. A log alone leaves
                # the HTTP request pending; its owner needs a terminal event.
                self.conn.error = f"Upstream TLS failed: {exc}"
                yield commands.Log(self.conn.error, WARNING)
                closed = fatal = True
                break
        yield from self.tls_interact()
        if plaintext:
            yield from self.event_to_child(events.DataReceived(self.conn, bytes(plaintext)))
        if closed:
            self.conn.state &= ~ConnectionState.CAN_READ
            self.fatal_read_closed = fatal
            yield from self.event_to_child(events.ConnectionClosed(self.conn))
            if fatal:
                yield commands.CloseConnection(self.conn)

    def receive_close(self):
        if not self.fatal_read_closed:
            yield from super().receive_close()


def install_upstream_tls_layer(root):
    """Replace a fresh server TLS layer before its first Start event."""
    owner, selected = None, root
    while selected is not None:
        if type(selected) is ServerTLSLayer:
            if selected.tls is not None:
                raise RuntimeError("Upstream TLS termination requires a fresh mitmproxy 12.2.1 layer")
            context = selected.context
            index = context.layers.index(selected)
            context.layers.remove(selected)
            replacement = TerminatingServerTLSLayer(context, selected.conn)
            replacement.child_layer = selected.child_layer
            context.layers.remove(replacement)
            context.layers.insert(index, replacement)
            if owner is None:
                return replacement
            owner.child_layer = replacement
            return root
        owner, selected = selected, getattr(selected, "child_layer", None)
    return root
