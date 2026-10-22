"""Certificate input, secret handling and cleanup ownership boundaries."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

from client_certificates import ClientCertificates, UpstreamTrust, ordered_chain
from endpoints import canonical_host
from engine import Lens


class ClientCertificateInputs(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Selected fixture identity")])
        now = datetime.now(timezone.utc)
        cls.certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2)).not_valid_after(now - timedelta(days=1))
            .sign(cls.key, hashes.SHA256()))  # Expired is not confused with wrong ownership/key.
        cls.pem = cls.certificate.public_bytes(serialization.Encoding.PEM)
        cls.private = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-certificate-inputs-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "selected.pem"
        self.path.write_bytes(self.pem + self.private)

    def selection(self, **values):
        return {"host": "example.test", "port": 443, "path": str(self.path), **values}

    async def test_host_identity_normalizes_dns_and_ip_without_accepting_globs_urls_or_ports(self):
        for source, expected in (("EXAMPLE.test.", "example.test"), ("127.0.0.1", "127.0.0.1"),
                                 ("2001:0db8::1", "2001:db8::1"), ("bücher.test", "xn--bcher-kva.test"),
                                 ("faß.test", "xn--fa-hia.test")):
            self.assertEqual(canonical_host(source), expected)
        for host in ("", "*.example.test", "https://example.test", "host:443", "../host", "a_b", "fe80::1%en0", "127.0.0.1.", "１２７.０.０.１"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                canonical_host(host)

    async def test_wire_sni_cannot_broaden_unicode_or_ip_identity_scope(self):
        for selected, source, wire in (("faß.test", "faß.test", b"fass.test"),
                                       ("127.0.0.1", "１２７.０.０.１", b"127.0.0.1")):
            with self.subTest(selected=selected):
                owner = ClientCertificates()
                await owner.load([self.selection(host=selected)])
                connection = SSL.Connection(SSL.Context(SSL.TLS_CLIENT_METHOD))
                connection.set_tlsext_host_name(wire)
                data = SimpleNamespace(is_dtls=False, conn=SimpleNamespace(address=("127.0.0.1", 443), sni=source), ssl_conn=connection)
                self.assertIsNone(owner.apply(data, object()))
                self.assertEqual(owner.contexts, {})

    async def test_failed_replacement_preserves_loaded_identity_and_validity_is_separate(self):
        owner = ClientCertificates()
        await owner.load([self.selection()])
        before = owner.public()
        self.assertEqual(before[0]["path"], str(self.path))
        for selections in ([self.selection(), self.selection(host="EXAMPLE.test.")],
                           [self.selection(port=True)], [self.selection(path="relative.pem")],
                           [self.selection(password="\ud800")]):
            with self.assertRaises(ValueError):
                await owner.load(selections)
            self.assertEqual(owner.public(), before)
        self.path.write_bytes(b"not a certificate")
        with self.assertRaisesRegex(ValueError, "Cannot unlock"):
            await owner.load([self.selection()])
        self.assertEqual(owner.public(), before)
        owner.contexts["fixture"] = object()
        owner.clear()
        self.assertEqual(owner.public(), [])
        self.assertEqual(owner.contexts, {})

    async def test_selected_host_fact_survives_canonical_lookup_and_hook_failure_closes_tls(self):
        owner = ClientCertificates()
        await owner.load([self.selection(host="EXAMPLE.test.")])
        self.assertEqual(owner.public()[0]["host"], "example.test")
        self.assertEqual(owner.public()[0]["selected_host"], "EXAMPLE.test.")
        lens = Lens(SimpleNamespace(options=object()), self.directory, 8890)
        lens.client_certificates = owner
        data = SimpleNamespace(ssl_conn=object())
        with patch.object(owner, "apply", side_effect=RuntimeError("fixture context creation failed")):
            with self.assertRaisesRegex(RuntimeError, "fixture context"):
                lens.tls_start_server(data)
        self.assertIsNone(data.ssl_conn)

    async def test_regular_file_admission_precedes_fifo_reads_and_size_allocation(self):
        fifo = self.directory / "fifo.pem"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            await ClientCertificates().load([self.selection(path=str(fifo))])
        large = self.directory / "large.pem"
        with large.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "budget"):
            await ClientCertificates().load([self.selection(path=str(large))])

    async def test_pem_rejects_multiple_keys_and_ambiguous_certificates(self):
        self.path.write_bytes(self.pem + self.private + self.private)
        with self.assertRaisesRegex(ValueError, "Cannot unlock"):
            await ClientCertificates().load([self.selection()])
        now = datetime.now(timezone.utc)
        alternate = (x509.CertificateBuilder().subject_name(self.certificate.subject).issuer_name(self.certificate.subject)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(self.key, hashes.SHA256()))
        self.path.write_bytes(self.pem + alternate.public_bytes(serialization.Encoding.PEM) + self.private)
        with self.assertRaisesRegex(ValueError, "Cannot unlock"):
            await ClientCertificates().load([self.selection()])

    async def test_self_issued_name_does_not_skip_a_differently_signed_issuer(self):
        authority = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rollover authority")])
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Selected leaf")])
        intermediate_key, leaf_key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))
        now = datetime.now(timezone.utc)
        def certificate(subject, issuer, key, signer):
            return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=1))
                .sign(signer, hashes.SHA256()))
        root = certificate(authority, authority, self.key, self.key)
        rollover = certificate(authority, authority, intermediate_key, self.key)
        leaf = certificate(leaf_name, authority, leaf_key, intermediate_key)
        self.assertEqual(ordered_chain(leaf, [root, rollover]), (rollover, root))

    async def test_trust_snapshot_contains_only_certificates_and_cleanup_can_retry(self):
        owner = UpstreamTrust()
        await owner.load(self.path, self.directory)
        self.assertEqual(owner.path.read_bytes(), self.pem)
        self.assertNotIn(self.private, owner.path.read_bytes())
        self.assertEqual(owner.path.stat().st_mode & 0o777, 0o600)
        self.path.unlink()
        self.assertEqual(owner.path.read_bytes(), self.pem)
        selected_directory = owner.directory.name
        with patch.object(owner.directory, "cleanup", side_effect=PermissionError("fixture cleanup denied")):
            with self.assertRaises(PermissionError):
                owner.close()
        self.assertTrue(owner.path.exists())
        self.assertEqual(owner.directory.name, selected_directory)
        owner.close()
        owner.close()
        self.assertFalse(Path(selected_directory).exists())


if __name__ == "__main__":
    unittest.main()
