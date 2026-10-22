"""Own validated HTTP message patches, independently of capture/pause commands.

Header text is UTF-8 with surrogateescape for explicitly represented wire bytes.
Bodies are decoded replacement bytes; unchanged bodies retain their exact wire bytes.
"""
import base64
from dataclasses import dataclass
import zlib

from mitmproxy import http
from mitmproxy.net import encoding

from bounds import BODY_BYTES, CONTENT_ENCODINGS, base64_size, decode_base64, decoded_bytes, text_size
from http_urls import prepare_url
from http_method import parse_method
from http_headers import HEADER_BYTES, prepare_headers, wire_text

@dataclass(frozen=True)
class PreparedEdit:
    side: str | None = None
    message: object = None
    original_url: str | None = None

    def apply(self, flow):
        if self.side is not None:
            setattr(flow, self.side, self.message)


def content_encoding(headers):
    value = headers.get("content-encoding", "").strip().lower()
    if value not in CONTENT_ENCODINGS:
        raise ValueError(f"Unsupported Content-Encoding: {value}")
    return value


def encoded_body(body, codec):
    if codec == "deflateraw":
        encoder = zlib.compressobj(wbits=-15)
        raw = encoder.compress(body) + encoder.flush()
    else:
        raw = encoding.encode(body, codec or "identity")
    if not isinstance(raw, bytes) or len(raw) > BODY_BYTES:
        raise ValueError("Encoded body exceeds 32 MiB byte budget")
    return raw


_UNSET = object()


def prepare_request_edit(request, patch):
    """Prepare a request patch without a flow or pause; an empty patch shares it.

    Source headers and wire body are preserved without reinterpretation unless
    the caller explicitly replaces headers/body or changes Content-Encoding.
    The caller owns admission of unavailable source bodies before execution.
    """
    return _prepare_message(request, "request", patch)


def prepare_new_request(patch):
    """Apply a new explicit request through the same single URL parse owner."""
    if not isinstance(patch, dict) or "url" not in patch:
        raise ValueError("A new request requires an explicit absolute HTTP(S) URL")
    source = http.Request.make("GET", "http://lens.invalid/", b"")
    return prepare_request_edit(source, patch)


def prepare_response_edit(response, patch, *, request_method, frontend_method):
    """Prepare response-only edits using explicit effective/frontend facts."""
    parse_method(request_method)
    parse_method(frontend_method)
    return _prepare_message(response, "response", patch, request_method=request_method,
                            frontend_method=frontend_method)


def prepare_legacy_body_edit(message, side, text, *, request_method=None, frontend_method=None):
    """Adapt the legacy decoded UTF-8 body without a Base64 allocation roundtrip."""
    if side not in ("request", "response"):
        raise ValueError("Legacy body edit side must be request or response")
    if side == "response":
        parse_method(request_method)
        parse_method(frontend_method)
    text_size(text, BODY_BYTES, f"{side}_body")
    body = text.encode("utf-8")
    return _prepare_message(message, side, {"body_base64": None}, replacement_body=body,
                            request_method=request_method, frontend_method=frontend_method)


def prepare_body_replacement(message, side, body, *, request_method=None, frontend_method=None):
    """Adapt already admitted decoded bytes without a Base64 transport copy."""
    if not isinstance(body, bytes) or len(body) > BODY_BYTES:
        raise ValueError("Replacement body must be bytes within 32 MiB")
    return _prepare_message(message, side, {"body_base64": None}, replacement_body=body,
                            request_method=request_method, frontend_method=frontend_method)


def prepare_header_fields(message, side, headers, *, request_method=None, frontend_method=None):
    """Use fields prepared by the header owner, preserving unchanged framing.

    Existing fields are captured facts, not replacement input to revalidate.
    A changed Content-Encoding still passes the shared full-body codec owner.
    """
    return _prepare_message(message, side, {}, replacement_headers=headers, preserve_header_framing=True,
                            request_method=request_method, frontend_method=frontend_method)


def _prepare_message(message, side, patch, *, replacement_body=_UNSET, replacement_headers=_UNSET,
                     preserve_header_framing=False, request_method=None, frontend_method=None):
    allowed = {"headers", "headers_base64", "body_base64"} | ({"method", "url"} if side == "request" else {"status_code", "reason", "reason_base64"})
    if not isinstance(patch, dict) or set(patch) - allowed:
        raise ValueError(f"Invalid {side}_edit fields")
    if not patch and replacement_headers is _UNSET:
        return PreparedEdit(side, message)

    # Validate everything that can be checked without a message copy first.
    if "headers" in patch and "headers_base64" in patch:
        raise ValueError("headers and headers_base64 are mutually exclusive")
    if "reason" in patch and "reason_base64" in patch:
        raise ValueError("reason and reason_base64 are mutually exclusive")
    headers = (prepare_headers(patch["headers"]) if "headers" in patch else
               prepare_headers(patch["headers_base64"], encoded=True) if "headers_base64" in patch else None)
    if replacement_headers is not _UNSET:
        headers = replacement_headers
    body = None
    if "body_base64" in patch:
        if replacement_body is not _UNSET:
            body = replacement_body
        else:
            base64_size(patch["body_base64"], BODY_BYTES, "Message body")
            body = base64.b64decode(patch["body_base64"], validate=True)
    if "method" in patch:
        parse_method(patch["method"])
    url = prepare_url(patch["url"]) if "url" in patch else None
    if "status_code" in patch and (type(patch["status_code"]) is not int or not 200 <= patch["status_code"] <= 599):
        raise ValueError("status_code must be an integer between 200 and 599")
    if "reason_base64" in patch:
        reason = decode_base64(patch["reason_base64"], HEADER_BYTES, "Response reason")
        if any(byte in reason for byte in (b"\r", b"\n", b"\0")):
            raise ValueError("reason cannot contain CR, LF or NUL and must fit 64 KiB")
    elif "reason" in patch:
        if not isinstance(patch["reason"], str) or len(patch["reason"]) > HEADER_BYTES:
            raise ValueError("reason must be a string within 64 KiB")
        reason = wire_text(patch["reason"], "reason")
        if len(reason) > HEADER_BYTES or any(byte in reason for byte in (b"\r", b"\n", b"\0")):
            raise ValueError("reason cannot contain CR, LF or NUL and must fit 64 KiB")

    replacement = message.copy()
    if headers is not None:
        # Host is request routing state, not user header state. Preserve original
        # bytes when the URL is unchanged, including duplicate source fields.
        if side == "request" and replacement_headers is _UNSET:
            headers.fields += tuple((name, value) for name, value in message.headers.fields if name.lower() == b"host")
        replacement.headers = headers
    if "method" in patch:
        replacement.method = patch["method"]
        if replacement.method == "CONNECT" and message.method != "CONNECT":
            raise ValueError("CONNECT changes protocol state and cannot replace an ordinary HTTP method")
    if url is not None:
        replacement.url = url.value
        replacement.data.path = url.target
        # The installed SDK's hostport helper omits brackets for IPv6. The
        # already validated netloc is the wire authority for this URL edit.
        authority = url.authority
        replacement.host_header = authority
        if replacement.authority:
            replacement.authority = authority
    if "status_code" in patch:
        replacement.status_code = patch["status_code"]
    if "reason" in patch or "reason_base64" in patch:
        replacement.reason = reason

    old_codec = message.headers.get("content-encoding", "").strip().lower()
    new_codec = replacement.headers.get("content-encoding", "").strip().lower()
    body_changed = "body_base64" in patch
    encoding_changed = old_codec != new_codec
    if body_changed or encoding_changed:
        new_codec = content_encoding(replacement.headers)
        if not body_changed:
            old_codec = content_encoding(message.headers)
            if message.raw_content is None:
                raise ValueError("Original body is unavailable; provide body_base64 explicitly")
            body = decoded_bytes(message.raw_content, old_codec, limit=BODY_BYTES, strict=True)
        replacement.raw_content = encoded_body(body, new_codec)

    no_body = side == "response" and (replacement.status_code in (204, 304) or (request_method == "HEAD" and frontend_method == "HEAD"))
    if no_body and body_changed and body == b"":
        replacement.raw_content = b""
    if no_body and replacement.raw_content:
        raise ValueError("HEAD, 204 and 304 responses cannot contain a body; explicitly replace with empty body_base64")
    # Rebuild framing only when headers/body/status changed. A URL/method-only
    # edit must not transcode bytes or reinterpret original source headers.
    if (headers is not None and not preserve_header_framing) or body_changed or encoding_changed or "status_code" in patch:
        if replacement.trailers:
            # SDK HTTP/1 raises NotImplementedError for received trailers; H2
            # owns separate trailer frames. Until the adapter can guarantee the
            # eventual protocol, do not silently discard or misframe them.
            raise ValueError("Cannot rebuild framing for a message with trailers; continue unchanged or edit only method, URL or reason")
        replacement.headers.pop("transfer-encoding", None)
        if side == "response" and replacement.status_code == 204:
            replacement.headers.pop("content-length", None)
        elif no_body:
            # HEAD/304 may advertise representation length while carrying no
            # payload. Preserve the source value unless an explicit body edit
            # declares a new empty representation.
            replacement.headers.pop("content-length", None)
            if not body_changed:
                replacement.headers.fields += tuple((name, value) for name, value in message.headers.fields
                                                    if name.lower() == b"content-length")
        elif replacement.raw_content is not None:
            replacement.headers["content-length"] = str(len(replacement.raw_content))
        else:
            replacement.headers.pop("content-length", None)
    return PreparedEdit(side, replacement, url.source if url is not None else None)
