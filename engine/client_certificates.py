"""Immutable, exact-host TLS client identities. Private material stays in memory."""
from collections import OrderedDict
from dataclasses import dataclass
import ipaddress
import io
import os
from pathlib import Path
import tempfile

from endpoints import canonical_host
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from OpenSSL import SSL
from mitmproxy.addons.tlsconfig import _default_ciphers
from mitmproxy.net import tls

from bounds import BODY_BYTES
from certificate_inputs import CertificateInputs


class UpstreamTrust:
    """A certificate-only snapshot; a selected combined PEM never copies its key."""
    def __init__(self):
        self.directory = None
        self.path = None
        self.source = None

    async def load(self, source, directory, inputs=None):
        self.source = str(source)
        payload = await (inputs or CertificateInputs()).read(str(Path(source).expanduser().absolute()), BODY_BYTES)
        certificates = x509.load_pem_x509_certificates(payload)
        if not certificates:
            raise ValueError("Upstream trust bundle must contain PEM certificates")
        self.directory = tempfile.TemporaryDirectory(prefix=".upstream-trust-", dir=directory)
        self.path = Path(self.directory.name) / "ca.pem"
        with self.path.open("xb") as stream:
            os.chmod(self.path, 0o600)
            for certificate in certificates:
                stream.write(certificate.public_bytes(serialization.Encoding.PEM))

    def close(self):
        if self.directory is not None:
            self.directory.cleanup()


def ordered_chain(leaf, certificates):
    remaining = {certificate.fingerprint(hashes.SHA256()): certificate for certificate in certificates}
    remaining.pop(leaf.fingerprint(hashes.SHA256()), None)
    result, current = [], leaf
    def issued_by(child, issuer):
        if child.issuer != issuer.subject:
            return False
        try:
            child.verify_directly_issued_by(issuer)
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    while not issued_by(current, current):
        candidates = []
        for certificate in remaining.values():
            if issued_by(current, certificate):
                candidates.append(certificate)
        if not candidates:
            if any(certificate is not current and issued_by(current, certificate) for certificate in (leaf, *result)):
                raise ValueError("Client certificate chain contains a signature cycle")
            break  # A leaf-only identity is valid; the peer decides trust.
        if len(candidates) != 1:
            raise ValueError("Client certificate chain has ambiguous issuers")
        current = candidates[0]
        result.append(current)
        del remaining[current.fingerprint(hashes.SHA256())]
    if remaining:
        raise ValueError("Client certificate input contains an unrelated or cyclic chain")
    return tuple(result)


def pem_private_keys(payload):
    """Inventory RFC 7468 framing without splitting/copying the entire input."""
    active, count = None, 0
    key_labels = {b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY", b"DSA PRIVATE KEY"}
    for raw in io.BytesIO(payload):
        line = raw.strip()
        if line.startswith(b"-----BEGIN "):
            if active is not None or not line.endswith(b"-----"):
                raise ValueError("Malformed PEM framing")
            active = line[11:-5]
            if active in key_labels:
                count += 1
        elif line.startswith(b"-----END "):
            if active is None or not line.endswith(b"-----") or line[9:-5] != active:
                raise ValueError("Malformed PEM framing")
            active = None
    if active is not None:
        raise ValueError("Incomplete PEM framing")
    return count


@dataclass(repr=False)
class Identity:
    host: str
    port: int
    selected_host: str
    path: str
    key: object
    certificate: x509.Certificate
    chain: tuple

    def public(self):
        return {"host": self.host, "port": self.port, "selected_host": self.selected_host, "path": self.path,
                "sha256": self.certificate.fingerprint(hashes.SHA256()).hex(),
                "subject": self.certificate.subject.rfc4514_string(),
                "expires": self.certificate.not_valid_after_utc.isoformat()}


class ClientCertificates:
    def __init__(self):
        self.identities = {}
        self.contexts = OrderedDict()

    async def load(self, selections, inputs=None):
        if not isinstance(selections, list) or len(selections) > 32:
            raise ValueError("Client certificates must be an array of at most 32 identities")
        prepared, remaining = {}, BODY_BYTES
        inputs = inputs or CertificateInputs()
        for selection in selections:
            if not isinstance(selection, dict):
                raise ValueError("Client certificate selection must be an object")
            host, port = canonical_host(selection.get("host")), selection.get("port", 443)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("Client certificate port must be between 1 and 65535")
            if (host, port) in prepared:
                raise ValueError("Duplicate client certificate host and port")
            password = selection.get("password", "")
            if not isinstance(password, str):
                raise ValueError("Client certificate password must be a string")
            payload = await inputs.read(selection.get("path"), remaining)
            remaining -= len(payload)
            try:
                secret = password.encode("utf-8") or None
                def public_key(value):
                    return value.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                if Path(selection["path"]).suffix.lower() in (".p12", ".pfx"):
                    key, certificate, chain = pkcs12.load_key_and_certificates(payload, secret)
                else:
                    if pem_private_keys(payload) != 1:
                        raise ValueError("PEM must contain exactly one private key")
                    certificates = x509.load_pem_x509_certificates(payload)
                    try:
                        key = serialization.load_pem_private_key(payload, None)
                    except TypeError:  # Encrypted PEM needs its selected password.
                        key = serialization.load_pem_private_key(payload, secret)
                    key_bytes = public_key(key)
                    matches = {candidate.fingerprint(hashes.SHA256()): candidate for candidate in certificates if public_key(candidate) == key_bytes}
                    if len(matches) != 1:
                        raise ValueError("PEM must identify one matching certificate")
                    certificate, chain = next(iter(matches.values())), certificates
                if key is None or certificate is None:
                    raise ValueError("Missing identity")
                if public_key(key) != public_key(certificate):
                    raise ValueError("Mismatched identity")
            except (ValueError, TypeError, UnsupportedAlgorithm):
                # Parser diagnostics and secret input never enter JSONL/logs.
                raise ValueError(f"Cannot unlock client certificate for {host}:{port}; check format, password and matching private key") from None
            identity = Identity(host, port, selection["host"], selection["path"], key, certificate, ordered_chain(certificate, chain))
            prepared[host, port] = identity
        self.identities = prepared
        self.contexts.clear()

    def public(self):
        return [identity.public() for identity in self.identities.values()]

    def apply(self, data, options):
        if data.is_dtls or not self.identities:
            return None
        server = data.conn
        if not server.address:
            return None
        connection = data.ssl_conn
        if connection is None:
            return None
        try:
            wire_name = connection.get_servername()
            if wire_name is not None:
                host = canonical_host(wire_name.decode("ascii"))
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    pass
                else:
                    return None  # A DNS SNI must not authorize an IP-verification identity.
            else:
                host = str(ipaddress.ip_address(server.sni or server.address[0]))
        except (ValueError, UnicodeError):
            return None
        identity = self.identities.get((host, server.address[1]))
        if identity is None:
            return None
        if connection is None or options.ssl_insecure or connection.get_verify_mode() != SSL.VERIFY_PEER:
            data.ssl_conn = None
            raise RuntimeError("Client certificates require verified upstream TLS")
        ciphers = tuple(server.cipher_list or _default_ciphers(tls.Version[options.tls_version_server_min]))
        policy = (host, identity.port, ciphers, options.tls_version_server_min, options.tls_version_server_max,
                  options.tls_ecdh_curve_server, options.ssl_verify_upstream_trusted_confdir, options.ssl_verify_upstream_trusted_ca)
        context = self.contexts.get(policy)
        if context is None:
            # The unwrapped 12.2.1 factory creates a fresh context with the same
            # TLS/trust policy. Never mutate mitmproxy's cached shared contexts.
            factory = getattr(tls.create_proxy_server_context, "__wrapped__", None)
            if factory is None:
                data.ssl_conn = None
                raise RuntimeError("Client certificates require the pinned mitmproxy TLS context factory")
            context = factory(method=tls.Method.TLS_CLIENT_METHOD,
                min_version=tls.Version[options.tls_version_server_min], max_version=tls.Version[options.tls_version_server_max],
                cipher_list=ciphers, ecdh_curve=tls.get_curve(options.tls_ecdh_curve_server),
                verify=tls.Verify.VERIFY_PEER, ca_path=options.ssl_verify_upstream_trusted_confdir,
                ca_pemfile=options.ssl_verify_upstream_trusted_ca, client_cert=None, legacy_server_connect=False)
            context.use_certificate(identity.certificate)
            context.use_privatekey(identity.key)
            context.check_privatekey()
            for certificate in identity.chain:
                context.add_extra_chain_cert(certificate)
            SSL._lib.SSL_CTX_set_post_handshake_auth(context._context, 1)
            self.contexts[policy] = context
            if len(self.contexts) > 64:
                self.contexts.popitem(last=False)
        else:
            self.contexts.move_to_end(policy)
        # SNI, hostname verification parameters, ALPN and connect state belong
        # to the already-created per-connection SSL object and stay in place.
        connection.set_context(context)
        return identity.public()

    def clear(self):
        self.contexts.clear()
        self.identities.clear()
