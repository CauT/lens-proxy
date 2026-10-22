import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import h11
from mitmproxy import http

import outgoing_transport as outgoing
from network import ProxyRelays
from outgoing import snapshot_request


def snapshot(method, url, fields=(), body=b''):
    return snapshot_request(http.Request.make(method, url, body, headers=list(fields)))


async def request(reader):
    parser = h11.Connection(h11.SERVER)
    head, body = None, bytearray()
    while True:
        event = parser.next_event()
        if event is h11.NEED_DATA:
            parser.receive_data(await reader.read(65536))
        elif isinstance(event, h11.Request):
            head = event
        elif isinstance(event, h11.Data):
            body.extend(event.data)
        elif isinstance(event, h11.EndOfMessage):
            return head, bytes(body)
        else:
            raise AssertionError(event)


class OutgoingTransportBoundary(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.network = ProxyRelays()
        self.writers, self.tasks = [], set()
        self.addAsyncCleanup(self.network.close)

    async def serve(self, handler):
        async def owned(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            self.writers.append(writer)
            try:
                await handler(reader, writer)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                self.tasks.discard(task)
        server = await asyncio.start_server(owned, "127.0.0.1", 0)
        async def stop():
            server.close()
            await server.wait_closed()
            for writer in self.writers:
                writer.close()
            for task in list(self.tasks):
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.addAsyncCleanup(stop)
        return server.sockets[0].getsockname()[1]

    async def test_plain_ipv6_connect_then_origin_target_custom_method_binary_headers_and_body(self):
        observed, done = {}, asyncio.Event()
        async def proxy(reader, writer):
            observed['connect'] = await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            observed['request'], observed['body'] = await request(reader)
            writer.write(b'HTTP/1.1 103 Early Hints\r\nLink: </hint>\r\n\r\n'
                         b'HTTP/1.1 201 Created\r\nContent-Length: 70000\r\n\r\n' + b'x' * 70000)
            await writer.drain()
            done.set()
        port = await self.serve(proxy)
        body = bytes(range(256)) * 300
        source = snapshot('CuStOm', 'http://[::1]:1234/path?x=1',
            [(b'X-Duplicate', b'one'), (b'X-Duplicate', b'two'), (b'X-Raw', b'\xff')], body)
        status = await outgoing.send_via_proxy(source, '0' * 64,
            proxy_port=port, ssl_context=None, close_streams=self.network.close_streams)
        await done.wait()
        self.assertEqual(status, 201)
        self.assertEqual(observed['request'].method, b'CuStOm')
        self.assertTrue(observed['connect'].startswith(b'CONNECT [::1]:1234 HTTP/1.1\r\n'))
        self.assertEqual(observed['request'].target, b'/path?x=1')
        self.assertEqual(dict(observed['request'].headers)[b'host'], b'[::1]:1234')
        self.assertEqual(observed['body'], body)
        self.assertEqual([v for k, v in observed['request'].headers if k == b'x-duplicate'], [b'one', b'two'])
        self.assertIn((b'x-raw', b'\xff'), observed['request'].headers)
        self.assertFalse(self.network.closing)

    async def test_https_ipv6_connect_then_strict_tls_origin_form_and_head_semantics(self):
        with tempfile.TemporaryDirectory(prefix='lens-outgoing-tls-') as directory:
            path = Path(directory)
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'owned IPv6 TLS fixture')])
            now = datetime.now(timezone.utc)
            certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address('::1'))]), critical=False).sign(key, hashes.SHA256()))
            (path / 'cert.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            (path / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(path / 'cert.pem', path / 'key.pem')
            client_tls = ssl.create_default_context(cafile=str(path / 'cert.pem'))
            observed = {}
            async def proxy(reader, writer):
                observed['connect'] = await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                await writer.drain()
                await writer.start_tls(server_tls)
                observed['request'], _ = await request(reader)
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 987654\r\n\r\n')
                await writer.drain()
            port = await self.serve(proxy)
            result = await outgoing.send_via_proxy(snapshot('HEAD', 'https://[::1]:8443/path?q=1'), '0' * 64, proxy_port=port,
                                                   ssl_context=client_tls, close_streams=self.network.close_streams)
            self.assertEqual(result, 200)
            self.assertTrue(observed['connect'].startswith(b'CONNECT [::1]:8443 HTTP/1.1\r\n'))
            self.assertEqual(observed['request'].target, b'/path?q=1')
            self.assertEqual(dict(observed['request'].headers)[b'host'], b'[::1]:8443')
            self.assertTrue(client_tls.check_hostname)
            self.assertEqual(client_tls.verify_mode, ssl.CERT_REQUIRED)
            self.assertFalse(self.network.closing)

    async def test_capacity_protocol_switch_connect_trailing_and_cancel_use_owned_cleanup(self):
        responses = asyncio.Queue()
        entered = asyncio.Event()
        async def proxy(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            data = await responses.get()
            if isinstance(data, tuple):
                writer.write(data[1])
                await writer.drain()
                return
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            await reader.readuntil(b'\r\n\r\n')
            entered.set()
            if data is None:
                await reader.read()
            else:
                writer.write(data)
                await writer.drain()
        port = await self.serve(proxy)
        async def send(url='http://example.test/'):
            return await outgoing.send_via_proxy(snapshot('GET', url), '0' * 64, proxy_port=port,
                ssl_context=ssl.create_default_context(), close_streams=self.network.close_streams)
        await responses.put(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody')
        with patch.object(outgoing, 'BODY_BYTES', 3), self.assertRaisesRegex(ValueError, 'body exceeds'):
            await send()
        await responses.put(b'HTTP/1.1 200 OK\r\nX-Large: ' + b'x' * 100 + b'\r\nContent-Length: 0\r\n\r\n')
        with patch.object(outgoing, 'HEADER_BYTES', 64), self.assertRaisesRegex(ValueError, 'headers exceed'):
            await send()
        await responses.put(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n')
        with self.assertRaisesRegex(ValueError, 'Unsupported.*protocol switch'):
            await send()
        await responses.put(('connect', b'HTTP/1.1 200 Connection established\r\n\r\nplaintext'))
        with self.assertRaisesRegex(ValueError, 'trailing bytes'):
            await send('https://[::1]/')
        await responses.put(('connect', b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'))
        with self.assertRaisesRegex(ValueError, 'CONNECT failed with HTTP 403'):
            await send()
        entered.clear()
        await responses.put(None)
        pending = asyncio.create_task(send())
        await entered.wait()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertFalse(self.network.closing)
        self.assertFalse(self.network.close_waiters)
