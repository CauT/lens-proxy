"""Own lossless SDK request facts separately from HAR's displayed URL.

The SDK URL setter parses ASCII URLs and synchronizes routing and Host fields.
Neither behavior is appropriate when reopening an observed request. The versioned
extension records RequestData fields; restoration constructs that representation
once and verifies its public HAR projection without applying editing policy.
"""
import base64
from urllib.parse import urlsplit

from mitmproxy import http
from mitmproxy.net import check

from bounds import METADATA_BYTES, canonical_base64_size, decode_base64, metadata_size
from http_method import request_method
from http_urls import request_url


_BYTE_FIELDS = ('method', 'scheme', 'authority', 'path', 'http_version')
_FIELDS = frozenset(('version', 'host', 'port', *(name + '_base64' for name in _BYTE_FIELDS)))


def _route(host, port):
    if not isinstance(host, str):
        raise ValueError('_lensRequestFacts.host must be a string')
    # Zero is an observed SDK unknown port, not permission to send to port zero.
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('_lensRequestFacts.port must be an integer from 0 to 65535')


def _standard_request(value):
    if (not isinstance(value, dict)
            or not isinstance(value.get('method'), str)
            or not isinstance(value.get('url'), str)
            or 'httpVersion' in value and not isinstance(value['httpVersion'], str)):
        raise ValueError('HAR request method, url and provided httpVersion must be strings')


def _empty_request_facts(request):
    return {'version': 1, 'host': request.host, 'port': request.port,
            **{name + '_base64': '' for name in _BYTE_FIELDS}}


def request_facts_metadata_size(request):
    """Measure archive projection/retained source cost without encoding bytes."""
    _route(request.host, request.port)
    raw = tuple(getattr(request.data, name) for name in _BYTE_FIELDS)
    if any(not isinstance(value, bytes) for value in raw):
        raise ValueError('_lensRequestFacts source fields must be SDK bytes')
    size = metadata_size(_empty_request_facts(request), METADATA_BYTES)
    for value in raw:
        size += ((len(value) + 2) // 3) * 4
        if size > METADATA_BYTES:
            raise ValueError('_lensRequestFacts exceeds 16 MiB metadata budget before Base64 allocation')
    return size


def export_request_facts(request):
    """Project current RequestData facts, admitting expansion before Base64."""
    request_facts_metadata_size(request)
    result = _empty_request_facts(request)
    for name in _BYTE_FIELDS:
        result[name + '_base64'] = base64.b64encode(getattr(request.data, name)).decode('ascii')
    return result


def restore_request_facts(value, standard_request, headers, timestamp_start):
    """Restore source bytes without treating inspection as outgoing readiness."""
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError('_lensRequestFacts must contain exactly the version 1 fields')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Unsupported _lensRequestFacts version')
    _route(value['host'], value['port'])
    # Count every encoded field, including UTF-8 host expansion, before any
    # decoded bytes are allocated. Then validate every spelling before decoding
    # even the first field, so late malformed fields cannot cause partial work.
    metadata_size(value, METADATA_BYTES)
    for name in _BYTE_FIELDS:
        canonical_base64_size(value[name + '_base64'], METADATA_BYTES,
                              '_lensRequestFacts.' + name + '_base64')
    _standard_request(standard_request)
    raw = {name: decode_base64(value[name + '_base64'], METADATA_BYTES,
                               '_lensRequestFacts.' + name + '_base64')
           for name in _BYTE_FIELDS}
    request = http.Request(host=value['host'], port=value['port'], **raw,
                           headers=headers, content=b'', trailers=None,
                           timestamp_start=timestamp_start, timestamp_end=None)
    projected = {'method': request_method(request), 'url': request_url(request, pretty=True),
                 'httpVersion': request.http_version}
    for name, source in projected.items():
        if name in standard_request and standard_request[name] != source:
            raise ValueError('_lensRequestFacts contradicts HAR request.' + name)
    return request


def restore_legacy_request(standard_request, headers, timestamp_start):
    """Derive a request from legacy HAR URL without claiming original target form.

    The URL establishes only URL-derived routing. A previous exporter may have
    used a displayed Host rather than the original destination, and '*' and
    CONNECT routing cannot be recovered when those facts were never saved.
    Authority parsing retains the SDK's normal IDNA/port behavior; the suffix is
    source text, not a URL to quote, normalize, or encode as ASCII.
    """
    _standard_request(standard_request)
    metadata_size({key: standard_request[key] for key in ('method', 'url', 'httpVersion')
                   if key in standard_request}, METADATA_BYTES)
    source = standard_request['url']
    scheme, delimiter, rest = source.partition('://')
    if not delimiter or scheme.lower() not in ('http', 'https'):
        raise ValueError('Legacy HAR request.url must be an absolute HTTP(S) URL; original target facts are unavailable')
    end = min((position for marker in '/?#' if (position := rest.find(marker)) >= 0), default=len(rest))
    authority, suffix = rest[:end], rest[end:]
    if not authority or any(ord(char) <= 32 or ord(char) == 127 for char in authority):
        raise ValueError('Legacy HAR request.url has an invalid authority')
    try:
        parsed = urlsplit(scheme + '://' + authority)
        host = (parsed.hostname or '').encode('idna')
        if not check.is_valid_host(host):
            raise ValueError('invalid routed hostname')
        # Match Request.make's legacy treatment of an omitted/zero port.
        port = parsed.port or (443 if scheme.lower() == 'https' else 80)
        path = suffix if suffix.startswith('/') else '/' + suffix
        raw = {'method': standard_request['method'].encode('utf-8', 'surrogateescape'),
               'scheme': scheme.lower().encode('ascii'), 'authority': b'',
               'path': path.encode('utf-8', 'surrogateescape'),
               'http_version': (standard_request.get('httpVersion') or 'HTTP/1.1').encode('utf-8', 'surrogateescape')}
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f'Legacy HAR request.url or HTTP text cannot be restored: {exc}') from exc
    return http.Request(host=host, port=port, **raw, headers=headers, content=b'',
                        trailers=None, timestamp_start=timestamp_start, timestamp_end=None)
