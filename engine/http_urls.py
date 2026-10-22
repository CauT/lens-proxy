"""Own URI rendering from pinned SDK request facts, including IPv6 authorities.

mitmproxy 12.2.1 unparse/hostport omit IPv6 brackets. Keep SDK host-header display
semantics separate from routed host facts, and never repair rendered strings.
"""
from dataclasses import dataclass
import ipaddress
import re
import urllib.parse
from mitmproxy.net import check
from mitmproxy.net.http import url as sdk_url


def request_url(request, *, pretty=False):
    if request.first_line_format == 'authority':
        return request.pretty_url if pretty else request.url
    host, port = request.host, request.port
    if pretty and request.host_header:
        host, observed_port = sdk_url.parse_authority(request.host_header, check=False)
        port = observed_port or sdk_url.default_port(request.scheme) or 443
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        pass
    else:
        host = '[' + host + ']'
    path = request.path if request.path != '*' else ''
    return sdk_url.unparse(request.scheme, host, port, path)


URL_BYTES = 64 * 1024


def mapping_path_prefix(pattern):
    """Directory before the first path glob; scheme/authority may contain globs."""
    _, separator, location = pattern.partition("://")
    path = "/" + location.partition("/")[2] if separator else "/"
    fixed = re.split(r"[*?\[]", path, maxsplit=1)[0]
    return fixed[:fixed.rfind("/") + 1]


@dataclass(frozen=True)
class PreparedHTTPURL:
    source: str
    value: str
    authority: str
    target: bytes


@dataclass(frozen=True)
class HTTPDestination:
    scheme: str
    host: str
    port: int
    authority: str


def prepare_destination(scheme, host, port):
    """Admit separate SDK dial facts without interpreting host text as a URL."""
    if scheme not in ('http', 'https') or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Outgoing requests require HTTP(S) and a known port from 1 to 65535')
    if not isinstance(host, str):
        raise ValueError('Outgoing destination host is invalid')
    try:
        ascii_host = host.encode('idna').decode('ascii')
        if len(ascii_host) > 255:
            raise ValueError('Outgoing destination host exceeds 255 bytes')
        labels = ascii_host.removesuffix('.').split('.')
        hostname = all(re.fullmatch(r'[A-Za-z0-9_-]{1,63}', label) for label in labels)
        if not hostname:
            ipaddress.ip_address(ascii_host)
    except (UnicodeError, ValueError) as exc:
        raise ValueError('Outgoing destination host is invalid') from exc
    # Validate ASCII DNS/IP syntax without decoding an already admitted A-label
    # through Python's older IDNA codec. That roundtrip rejects valid IDNA2008
    # spellings produced by the exact endpoint owner (for example faß.test).
    authority = f'[{ascii_host}]' if ':' in ascii_host else ascii_host
    return HTTPDestination(scheme, ascii_host, port, f'{authority}:{port}')


def prepare_url(value):
    if not isinstance(value, str) or not value or len(value) > URL_BYTES:
        raise ValueError("url must be an absolute HTTP(S) URL within 64 KiB")
    if len(value.encode("utf-8")) > URL_BYTES:
        raise ValueError("url must fit 64 KiB UTF-8 input budget")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("url cannot contain whitespace, controls or backslashes")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise ValueError("url must be absolute HTTP(S)")
        if "@" in parsed.netloc or "#" in value:
            raise ValueError("url cannot contain userinfo or a fragment")
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("url port must be 1..65535")
        if parsed.netloc.endswith(":"):
            raise ValueError("url port must not be empty")
        host = parsed.hostname.encode("idna")
        if not check.is_valid_host(host):
            raise ValueError("url host is invalid")
        # Use the SDK parser after strict admission. Its URL setter owns request
        # scheme/host/port/path and Host/:authority synchronization.
        ascii_netloc = host.decode("ascii")
        if ":" in ascii_netloc:
            ascii_netloc = "[" + ascii_netloc + "]"
        if port is not None:
            ascii_netloc += f":{port}"
        path_query = urllib.parse.urlunsplit((parsed.scheme.lower(), ascii_netloc,
                                               parsed.path, parsed.query, ""))
        path_query.encode("ascii")
        # SDK URL parsing drops an explicitly empty query delimiter. Own the
        # validated origin-form bytes here; consumers must use this fact after
        # the SDK has assigned destination state.
        target = (parsed.path or "/").encode("ascii")
        if "?" in value:
            target += b"?" + parsed.query.encode("ascii")
        return PreparedHTTPURL(value, path_query, ascii_netloc, target)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid absolute HTTP(S) url: {exc}") from exc
