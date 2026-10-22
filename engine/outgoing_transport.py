"""Bounded HTTP/1 requests through the owned local Lens proxy.

CONNECT selects the snapshot's independent routed destination for HTTP and TLS.
The following origin-form request retains its raw target and Host/authority,
without encoding observed path bytes through a URL parser. h11 owns framing and
response parsing; no vendor code or shared TLS context changes.
"""
import asyncio

import h11

from bounds import BODY_BYTES
from outgoing import REPLAY_HEADER, INTERNAL_TOKEN_LENGTH, valid_internal_token

BLOCK_BYTES = 64 * 1024
HEADER_BYTES = 64 * 1024
TIMEOUT_SECONDS = 120


async def _write_event(connection, writer, event):
    data = connection.send(event)
    if data:
        for offset in range(0, len(data), BLOCK_BYTES):
            writer.write(data[offset:offset + BLOCK_BYTES])
            await writer.drain()


class _ResponseReader:
    def __init__(self, connection, reader):
        self.connection, self.reader = connection, reader
        self.received = self.consumed_headers = self.header_bytes = 0
        self.final_headers = False

    async def next_event(self):
        while True:
            try:
                event = self.connection.next_event()
            except h11.RemoteProtocolError as exc:
                # In particular, unsolicited 101 raises before h11 can return
                # InformationalResponse: protocol switching is unsupported here.
                raise ValueError(f"Unsupported HTTP/1 response or protocol switch: {exc}") from exc
            if event is h11.NEED_DATA:
                if not self.final_headers and self.received - self.consumed_headers + self.header_bytes > HEADER_BYTES:
                    raise ValueError("Outgoing response headers exceed 64 KiB")
                data = await self.reader.read(BLOCK_BYTES)
                self.received += len(data)
                self.connection.receive_data(data)
                continue
            if isinstance(event, (h11.Response, h11.InformationalResponse)):
                # max_incomplete_event_size alone does not reject a complete
                # oversized header arriving across two reads. Public buffered
                # trailing bytes identify the exact consumed wire header length.
                consumed = self.received - len(self.connection.trailing_data[0])
                self.header_bytes += consumed - self.consumed_headers
                self.consumed_headers = consumed
                if self.header_bytes > HEADER_BYTES:
                    raise ValueError("Outgoing response headers exceed 64 KiB")
                if isinstance(event, h11.Response):
                    self.final_headers = True
            return event

    async def final_response(self):
        while True:
            event = await self.next_event()
            if isinstance(event, h11.InformationalResponse):
                if event.status_code == 101:
                    raise ValueError("HTTP 101 protocol switching is unsupported for outgoing requests")
                continue
            if isinstance(event, h11.Response):
                return event
            raise ValueError("Outgoing proxy closed before a final HTTP response")


async def _send_request(connection, writer, method, target, fields, body):
    # The public h11 event/state machine does not admit observed non-ASCII path
    # bytes. Its method/header framing state is independent of target. Advance
    # that state with a routing-neutral target, discard its serialized head, and
    # write the adapter-owned raw request line and these same validated headers.
    # No placeholder request bytes ever reach the socket.
    event = h11.Request(method=method.encode('ascii'), target=b'/', headers=fields)
    connection.send(event)
    head = method.encode('ascii') + b' ' + target + b' HTTP/1.1\r\n'
    head += b''.join(name + b': ' + value + b'\r\n' for name, value in event.headers.raw_items()) + b'\r\n'
    writer.write(head)
    await writer.drain()
    for offset in range(0, len(body), BLOCK_BYTES):
        await _write_event(connection, writer, h11.Data(data=body[offset:offset + BLOCK_BYTES]))
    await _write_event(connection, writer, h11.EndOfMessage())


async def send_via_proxy(snapshot, token, *, proxy_port, ssl_context, close_streams):
    """Send one request and discard a bounded response, returning its final status.

    The immutable snapshot owns outgoing admission, target and framing fields.
    The caller's cleanup callback owns close failures, cancellation and Stop
    retries. A TLS source is deliberately translated to an HTTP/1.1 client hop.
    """
    if type(proxy_port) is not int or not 1 <= proxy_port <= 65535:
        raise ValueError("Lens proxy port must be an integer from 1 to 65535")
    if (not isinstance(token, str) or len(token) != INTERNAL_TOKEN_LENGTH
            or not token.isascii() or not valid_internal_token(token.encode('ascii'))):
        raise ValueError('Outgoing request identity must be a valid internal token')
    prepared = snapshot.destination
    writer = None
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port, limit=BLOCK_BYTES)
            authority = prepared.authority.encode('ascii')
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=HEADER_BYTES)
            await _send_request(connection, writer, "CONNECT", authority, [(b"Host", authority)], b"")
            incoming = _ResponseReader(connection, reader)
            response = await incoming.final_response()
            if not 200 <= response.status_code <= 299:
                raise ValueError(f"Lens CONNECT failed with HTTP {response.status_code}")
            trailing, closed = connection.trailing_data
            if trailing or closed:
                raise ValueError("CONNECT returned unexpected trailing bytes or a closed tunnel")
            # CONNECT switches h11 immediately. Waiting for an HTTP EOM would
            # stall. The proxy sniffs plaintext HTTP versus TLS inside the tunnel.
            if prepared.scheme == "https":
                await writer.start_tls(ssl_context, server_hostname=prepared.host)
                tls = writer.get_extra_info("ssl_object")
                if tls is None or tls.selected_alpn_protocol() not in (None, "http/1.1"):
                    raise ValueError("Outgoing TLS must negotiate HTTP/1.1")
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=HEADER_BYTES)
            outgoing_fields = [*snapshot.headers, (REPLAY_HEADER, token.encode('ascii'))]
            await _send_request(connection, writer, snapshot.method, snapshot.target, outgoing_fields, snapshot.body)
            incoming = _ResponseReader(connection, reader)
            response = await incoming.final_response()
            observed = 0
            while True:
                event = await incoming.next_event()
                if isinstance(event, h11.Data):
                    observed += len(event.data)
                    if observed > BODY_BYTES:
                        raise ValueError("Outgoing response body exceeds 32 MiB")
                elif isinstance(event, h11.EndOfMessage):
                    # h11 bounds incomplete trailers; additionally admit complete
                    # parsed trailers before returning a completed operation.
                    if sum(len(name) + len(value) + 4 for name, value in event.headers.raw_items()) > HEADER_BYTES:
                        raise ValueError("Outgoing response trailers exceed 64 KiB")
                    return response.status_code
                else:
                    raise ValueError("Outgoing response ended without a complete HTTP body")
    finally:
        await close_streams([writer])
