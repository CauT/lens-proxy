"""Own HTTP header patch bytes and explicit text/Base64 input representations.

Existing parsed source fields bypass patch validation when kept. Replacement
fields use one byte validator, preserving duplicate order without reinterpretation.
"""
import base64

from mitmproxy import http

from bounds import canonical_base64_size
from http_method import HTTP_TOKEN

MAX_HEADERS = 1024
HEADER_BYTES = 64 * 1024
MANAGED_HEADERS = {b'host', b'content-length', b'transfer-encoding'}


def wire_text(value, label, limit=None):
    if limit is not None:
        _text_bytes_size(value, limit, label)
    if not isinstance(value, str):
        raise ValueError(f'{label} must be a string')
    try:
        return value.encode('utf-8', 'surrogateescape')
    except UnicodeError as exc:
        raise ValueError(f'{label} contains invalid Unicode') from exc


def _text_bytes_size(value, limit, label):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f'{label} exceeds its byte budget or is not a string')
    if value.isascii():
        return len(value)
    size = 0
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            if not 0xDC80 <= code <= 0xDCFF:
                raise ValueError(f'{label} contains invalid Unicode')
            size += 1
        else:
            size += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
        if size > limit:
            raise ValueError(f'{label} exceeds its byte budget')
    return size


def headers_base64(headers):
    return [[base64.b64encode(name).decode('ascii'), base64.b64encode(value).decode('ascii')]
            for name, value in headers.fields]


def prepare_headers(value, *, encoded=False):
    if not isinstance(value, list) or len(value) > MAX_HEADERS:
        raise ValueError(f'headers must contain at most {MAX_HEADERS} pairs')
    total = 0
    # Admit all decoded/UTF-8 byte lengths before any encoded field allocation.
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError('Each header must be a [name, value] pair')
        name, field_value = pair
        if encoded:
            name_size = canonical_base64_size(name, HEADER_BYTES - total, 'Header name')
            value_size = canonical_base64_size(field_value, HEADER_BYTES - total, 'Header value')
        else:
            name_size = _text_bytes_size(name, HEADER_BYTES - total, 'Header name')
            value_size = _text_bytes_size(field_value, HEADER_BYTES - total, 'Header value')
        total += name_size + value_size + 4
        if total > HEADER_BYTES:
            raise ValueError('Headers exceed 64 KiB byte budget')
    fields = []
    for name, field_value in value:
        if encoded:
            name_bytes = base64.b64decode(name, validate=True)
            value_bytes = base64.b64decode(field_value, validate=True)
        else:
            name_bytes = wire_text(name, 'Header name')
            value_bytes = wire_text(field_value, 'Header value')
        validate_header_field(name_bytes, value_bytes)
        fields.append((name_bytes, value_bytes))
    return http.Headers(fields)


def validate_header_field(name_bytes, value_bytes):
    try:
        name_text = name_bytes.decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Header names must be nonempty ASCII tokens') from exc
    if not HTTP_TOKEN.fullmatch(name_text):
        raise ValueError('Header names must be nonempty ASCII tokens')
    if name_bytes.lower() in MANAGED_HEADERS:
        raise ValueError(f'{name_text} is automatically managed by the engine')
    if any(byte in value_bytes for byte in (b'\r', b'\n', b'\0')):
        raise ValueError('Header values cannot contain CR, LF or NUL')
