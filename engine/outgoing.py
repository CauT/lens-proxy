"""Own composed request snapshots and their historical operation identity."""
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
import h11
from bounds import BODY_BYTES, METADATA_BYTES, metadata_size, text_size
from http_method import HTTP_TOKEN, request_method, parse_method
from http_headers import HEADER_BYTES
from http_urls import HTTPDestination, prepare_destination, prepare_url
from message_edit import prepare_request_edit, prepare_new_request

REPLAY_HEADER = b'X-Lens-Internal-Replay'
INTERNAL_TOKEN_LENGTH = 64


def valid_internal_token(value):
    return (isinstance(value, bytes) and len(value) == INTERNAL_TOKEN_LENGTH
            and all(char in b'0123456789abcdef' for char in value))


class RequestTokens:
    """Prove process-local ownership after a pending operation has been released.

    A fixed private key replaces an unbounded history of cancelled identities.
    The token carries no operation data; only a still-pending owner may bind it.
    """
    def __init__(self):
        self._key = secrets.token_bytes(32)

    def _tag(self, nonce):
        return hmac.digest(self._key, b'Lens outgoing request\0' + nonce, 'sha256')[:16].hex().encode('ascii')

    def new(self):
        nonce = secrets.token_hex(16).encode('ascii')
        return (nonce + self._tag(nonce)).decode('ascii')

    def owns(self, value):
        return (valid_internal_token(value)
                and hmac.compare_digest(value[32:], self._tag(value[:32])))


@dataclass(frozen=True)
class RequestSnapshot:
    method: str
    destination: HTTPDestination
    target: bytes
    headers: tuple
    body: bytes


@dataclass(frozen=True)
class ComposedRequest:
    snapshot: RequestSnapshot
    source_id: str | None
    url_input: str | None


def request_fingerprint(request):
    """Identify source message bytes, independent of display previews/live sockets."""
    digest = hashlib.sha256()
    def field(value):
        digest.update(len(value).to_bytes(8, 'big'))
        digest.update(value)
    for value in (request.data.method, request.data.scheme, request.host.encode('utf-8', 'surrogatepass'),
                  str(request.port).encode('ascii'), request.data.authority, request.data.path, request.data.http_version):
        field(value)
    for headers in (request.headers, request.trailers):
        fields = headers.fields if headers is not None else ()
        field(len(fields).to_bytes(8, 'big'))
        for name, value in fields:
            field(name); field(value)
    field(b'unavailable' if request.raw_content is None else b'available')
    if request.raw_content is not None:
        field(request.raw_content)
    return digest.hexdigest()


def validate_source_fingerprint(request, value):
    if not isinstance(value, str) or len(value) != 64 or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('source_fingerprint must be the source detail fingerprint')
    if request_fingerprint(request) != value:
        raise ValueError('The source request changed after this editor loaded; reload the source before queuing')


def snapshot_request(request):
    if request.raw_content is None:
        raise ValueError('Captured request body is unavailable; compose an explicit replacement')
    if len(request.raw_content) > BODY_BYTES:
        raise ValueError('Request body exceeds 32 MiB')
    method = parse_method(request_method(request))
    if method.upper() == 'CONNECT':
        raise ValueError('CONNECT establishes a tunnel and cannot be composed or replayed as an HTTP request')
    if request.trailers:
        raise ValueError('Outgoing request trailers are unsupported; the source remains available for inspection')
    # URL input admission belongs to explicit edits. A retained path is already
    # SDK-owned bytes: rebuilding a URL would reject opaque bytes and normalize
    # '*' or an empty query delimiter. Validate the dial destination separately.
    destination = prepare_destination(request.scheme, request.host, request.port)
    target = request.data.path
    if len(target) > HEADER_BYTES:
        raise ValueError('Outgoing HTTP/1 request head exceeds 64 KiB')
    if (not target or not (target.startswith(b'/') or target == b'*')
            or any(byte <= 32 or byte == 127 for byte in target)):
        raise ValueError('Outgoing request target must be origin-form or * without controls or whitespace')
    fields = tuple(request.headers.fields)
    end_to_end = transport_headers(fields)
    if (request.is_http2 or request.is_http3) and request.data.authority:
        # Outgoing transport is HTTP/1.1. Its Host represents the source H2/H3
        # authority; the independent CONNECT destination owns routing and SNI.
        host_field = (b'Host', request.data.authority)
    else:
        hosts = (field for field in fields if field[0].lower() == b'host')
        host_field = next(hosts, (b'Host', destination.authority.encode('ascii')))
        if next(hosts, None) is not None:
            raise ValueError('Outgoing HTTP/1 requires one Host field; duplicate source Hosts remain inspectable')
    headers = (host_field, (b'Content-Length', str(len(request.raw_content)).encode('ascii')),
               *end_to_end)
    # The outgoing adapter bounds complete HTTP/1 heads, not just an individual
    # URL. Admit expansion before h11 copies fields or serializes the request.
    check_headers = (*headers, (REPLAY_HEADER, b'0' * INTERNAL_TOKEN_LENGTH))
    size = len(method) + 1 + len(target) + len(b' HTTP/1.1\r\n') + 2
    size += sum(len(name) + len(value) + 4 for name, value in check_headers)
    if size > HEADER_BYTES:
        raise ValueError('Outgoing HTTP/1 request head exceeds 64 KiB')
    try:
        # h11 accepts only ASCII targets. The adapter owns the separately
        # admitted raw request line; method/header/framing admission stays h11.
        h11.Request(method=method.encode('ascii'), target=b'/', headers=check_headers)
    except h11.LocalProtocolError as exc:
        raise ValueError(f'Outgoing HTTP/1 request fields cannot be sent: {exc}') from exc
    return RequestSnapshot(method, destination, target, headers, request.raw_content)


def prepare_compose(command, flows):
    modern = any(key in command for key in ('source_id', 'request_edit', 'source_fingerprint'))
    if modern:
        if any(key in command for key in ('method', 'url', 'headers', 'body')):
            raise ValueError('source_id/request_edit cannot be mixed with legacy Compose fields')
        patch = command.get('request_edit', {})
        if not isinstance(patch, dict):
            raise ValueError('request_edit must be an object')
        source_id = command.get('source_id')
        if 'source_id' in command:
            if not isinstance(source_id, str) or source_id not in flows:
                raise ValueError('The selected Compose source is no longer retained')
            source = flows[source_id].request
            if 'source_fingerprint' in command:
                validate_source_fingerprint(source, command['source_fingerprint'])
            if source.raw_content is None and 'body_base64' not in patch:
                raise ValueError('Captured request body is unavailable; supply an explicit body replacement')
        else:
            if 'source_fingerprint' in command:
                raise ValueError('source_fingerprint requires a selected source_id')
            if 'url' not in patch:
                raise ValueError('A new composed request requires an explicit absolute HTTP(S) URL')
            prepared = prepare_new_request(patch)
            return ComposedRequest(snapshot_request(prepared.message), None, prepared.original_url)
        prepared = prepare_request_edit(source, patch)
        return ComposedRequest(snapshot_request(prepared.message), source_id, prepared.original_url)
    # Keep legacy text commands, but route their fields through the same owner.
    # Admit UTF-8 length before allocation and avoid an unnecessary Base64 copy.
    from message_edit import prepare_legacy_body_edit
    body = command.get('body', '')
    text_size(body, BODY_BYTES, 'Compose body')
    patch = {key: command[key] for key in ('method', 'url', 'headers') if key in command}
    if 'url' not in patch or 'method' not in patch:
        raise ValueError('Legacy Compose requires method and url')
    prepared = prepare_new_request(patch)
    prepared_body = prepare_legacy_body_edit(prepared.message, 'request', body)
    return ComposedRequest(snapshot_request(prepared_body.message), None, prepared.original_url)


def operation_facts(kind, identity, source_id=None, url_input=None, attempt=None):
    facts = {'kind': kind, 'id': identity, 'source_id': source_id, 'url_input': url_input, 'attempt': attempt}
    # Count once before any outgoing work is admitted. HAR imports use the
    # independent boundary validator below rather than trusting saved facts.
    metadata_size({'lens_request_operation': facts}, METADATA_BYTES)
    return facts


def import_operation(value):
    fields = {'kind', 'id', 'source_id', 'url_input', 'attempt'}
    if not isinstance(value, dict) or set(value) != fields or value['kind'] not in ('compose', 'replay', 'repeat'):
        raise ValueError('Invalid request operation facts')
    if not isinstance(value['id'], str):
        raise ValueError('Request operation id must be a string')
    source, url, attempt = value['source_id'], value['url_input'], value['attempt']
    if source is not None and not isinstance(source, str):
        raise ValueError('Request source identity must be a string or null')
    if value['kind'] != 'compose' and (source is None or url is not None):
        raise ValueError('Replay and Repeat facts require a source identity and no Compose URL input')
    if url is not None:
        prepare_url(url)
    if value['kind'] == 'repeat':
        if type(attempt) is not int or not 1 <= attempt <= 1000:
            raise ValueError('Repeat attempt must be an integer from 1 to 1000')
    elif attempt is not None:
        raise ValueError('Only Repeat has a numbered attempt')
    metadata_size({'lens_request_operation': value}, METADATA_BYTES)
    return dict(value)


def transport_headers(fields):
    # Bound source interpretation before split/lower or retained-field copies.
    # Removed hop values are not all retained, so their parser needs its own
    # explicit input bound as well as the final generated-head budget.
    connection_bytes = 0
    for name, value in fields:
        if len(name) > HEADER_BYTES:
            raise ValueError('Outgoing HTTP/1 request head exceeds 64 KiB')
        if name.lower() == b'connection':
            connection_bytes += len(name) + len(value) + 4
            if connection_bytes > HEADER_BYTES:
                raise ValueError('Outgoing Connection header processing exceeds 64 KiB')
    nominated = set()
    for name, value in fields:
        if name.lower() == b'connection':
            for part in value.split(b','):
                try:
                    token = part.strip().decode('ascii')
                except UnicodeError:
                    continue
                if HTTP_TOKEN.fullmatch(token):
                    nominated.add(token.lower().encode('ascii'))
    managed = {b'host', b'content-length', b'transfer-encoding', b'connection', b'proxy-connection',
               b'proxy-authorization', b'keep-alive', b'te', b'trailer', b'upgrade', b'x-lens-internal-replay'}
    excluded = managed | nominated
    retained, size = [], 0
    for name, value in fields:
        if name.lower() not in excluded:
            size += len(name) + len(value) + 4
            if size > HEADER_BYTES:
                raise ValueError('Outgoing HTTP/1 request head exceeds 64 KiB')
            retained.append((name, value))
    return tuple(retained)


@dataclass
class PendingRequest:
    facts: dict
    flow: object = None
    session: object = None
