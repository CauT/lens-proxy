"""Exact DNS/IP endpoint interpretation shared by TLS selection and TCP forwarding."""
import ipaddress
import re

import idna


def socket_endpoint(address):
    """Socket ownership treats IPv4-mapped IPv6 as the same IPv4 endpoint."""
    host = ipaddress.ip_address(address[0])
    return str(getattr(host, "ipv4_mapped", None) or host), address[1]


def canonical_host(value):
    if not isinstance(value, str) or not value or len(value) > 1024 or any(c in value for c in "/\\%@*?[]\0"):
        raise ValueError("Target host must be an exact DNS hostname or IP address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Non-transitional IDNA preserves distinct names such as faß/fass.
        # Plain ASCII DNS labels retain their exact RFC hostname spelling.
        host = (value if value.isascii() else idna.encode(value, uts46=True, std3_rules=True).decode("ascii")).removesuffix(".").lower()
        if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            raise ValueError("Target host must be an exact DNS hostname or IP address")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        raise ValueError("Host normalizes to an IP address; enter the IP literal without alternate spelling")
