"""HAR body normalization and explicit allocation budgets, shared by save/import."""
import base64
import copy
from dataclasses import dataclass
import io
import math
import re
import zlib
import brotli
import zstandard

BODY_BYTES = 32 * 1024 * 1024
STORE_BYTES = 256 * 1024 * 1024
HAR_FILE_BYTES = 512 * 1024 * 1024
METADATA_BYTES = 16 * 1024 * 1024
BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z", re.ASCII)
_BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def text_size(text, limit, label, metadata=False):
    if not isinstance(text, str):
        raise ValueError(f"{label} must be a string")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds its byte budget")
    size = 0
    for offset in range(0, len(text), 65536):
        # HTTP fields can contain surrogateescaped raw bytes. Metadata is emitted
        # as ASCII JSON escapes and restored by the header owner, never as UTF-8
        # body text. Count these code points without making valid headers unsavable.
        size += len(text[offset:offset + 65536].encode("utf-8", "surrogatepass" if metadata else "strict"))
        if size > limit:
            raise ValueError(f"{label} exceeds its byte budget")
    return size


def base64_size(text, limit, label):
    if not isinstance(text, str):
        raise ValueError(f"{label} must be a base64 string")
    if len(text) > ((limit + 2) // 3) * 4:
        raise ValueError(f"{label} exceeds body byte budget before base64 allocation")
    if len(text) % 4 or not BASE64.fullmatch(text):
        raise ValueError(f"{label} has invalid base64 encoding")
    size = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if size > limit:
        raise ValueError(f"{label} exceeds body byte budget before base64 allocation")
    return size


def canonical_base64_size(value, limit, label):
    size = base64_size(value, limit, label)
    # validate=True accepts nonzero unused pad bits. Admit one spelling of each
    # byte sequence, before decoding header patches or saved request facts.
    if value.endswith('==') and _BASE64_ALPHABET.index(value[-3]) & 15:
        raise ValueError(f'{label} must use canonical Base64')
    if value.endswith('=') and not value.endswith('==') and _BASE64_ALPHABET.index(value[-2]) & 3:
        raise ValueError(f'{label} must use canonical Base64')
    return size


def decode_base64(value, limit, label):
    canonical_base64_size(value, limit, label)
    return base64.b64decode(value, validate=True)


CONTENT_ENCODINGS = frozenset({"", "identity", "none", "gzip", "deflate", "deflateraw", "br", "zstd"})


def decoded_bytes(raw, encoding, limit=BODY_BYTES, *, strict=False):
    """Decode Content-Encoding once at its owning boundary, within a byte cap.

    Default callers preserve malformed wire bytes, matching the existing HAR
    display/import behavior. Strict consumers reject unsupported, incomplete or
    malformed representations instead of reinterpreting raw bytes as decoded.
    Resource-limit failures always raise in either mode.
    """
    if len(raw) > limit:
        raise ValueError("Body exceeds 32 MiB byte budget")
    encoding = encoding.lower().strip()
    if strict and encoding not in CONTENT_ENCODINGS:
        raise ValueError(f"Unsupported Content-Encoding: {encoding}")
    if not raw or encoding in ("", "identity", "none"):
        return raw

    def malformed(reason):
        if strict:
            raise ValueError(reason)
        return raw

    if encoding in ("gzip", "deflate", "deflateraw"):
        windows = [47] if encoding == "gzip" else [-15] if encoding == "deflateraw" else [15, -15]
        for window in windows:
            remaining = raw
            result = bytearray()
            try:
                while remaining:
                    decoder = zlib.decompressobj(window)
                    output = decoder.decompress(remaining, limit - len(result) + 1)
                    if len(result) + len(output) > limit or decoder.unconsumed_tail:
                        raise ValueError("Decoded body exceeds 32 MiB byte budget")
                    if not decoder.eof:
                        return malformed("Incomplete compressed body")
                    result.extend(output)
                    remaining = decoder.unused_data
                    # RFC 1952 permits concatenated members. Each member shares
                    # the same remaining output budget, including later bombs.
                    if not remaining:
                        return bytes(result)
                    if encoding != "gzip":
                        return malformed("Compressed body has trailing data")
                    # Preserve the historical lenient gzip padding behavior for
                    # display/import. A strict edit only accepts complete members.
                    if not remaining.strip(b"\0"):
                        return malformed("Gzip body has trailing padding") if strict else bytes(result)
                return bytes(result)
            except zlib.error:
                continue
        return malformed("Malformed compressed body")
    if encoding == "br":
        decoder = brotli.Decompressor()
        result = bytearray()
        try:
            for offset in range(0, len(raw), 4096):
                chunk = raw[offset:offset + 4096]
                while True:
                    output = decoder.process(chunk, output_buffer_limit=min(65536, limit - len(result) + 1))
                    if len(result) + len(output) > limit:
                        raise ValueError("Decoded body exceeds 32 MiB byte budget")
                    result.extend(output)
                    if decoder.can_accept_more_data():
                        break
                    chunk = b""
            return bytes(result) if decoder.is_finished() else malformed("Incomplete Brotli body")
        except brotli.error as exc:
            if strict:
                raise ValueError("Malformed Brotli body") from exc
            return raw
    if encoding == "zstd":
        try:
            # The pinned 0.25.0 bindings pass this value unchanged to
            # ZSTD_DCtx_setMaxWindowSize, which takes bytes. Its prose docs say
            # KiB; converting to KiB incorrectly rejects ordinary streaming frames.
            with zstandard.ZstdDecompressor(max_window_size=BODY_BYTES).stream_reader(io.BytesIO(raw), read_across_frames=True) as reader:
                result = reader.read(limit + 1)
            if len(result) > limit:
                raise ValueError("Decoded body exceeds 32 MiB byte budget")
            if strict:
                # stream_reader accepts truncated final frames. Its bounded
                # pass has proved the immutable input's total output ceiling;
                # only then validate each frame's completion with decompressobj.
                # The second pass cannot produce more output than examined above.
                remaining, validated = raw, 0
                while remaining:
                    decoder = zstandard.ZstdDecompressor(max_window_size=BODY_BYTES).decompressobj()
                    output = decoder.decompress(remaining)
                    validated += len(output)
                    if validated > limit or not decoder.eof:
                        raise ValueError("Incomplete or oversized Zstandard body")
                    remaining = decoder.unused_data
                if validated != len(result):
                    raise ValueError("Zstandard body has inconsistent decoded coverage")
            return result
        except zstandard.ZstdError as exc:
            # The explicit max_window_size option enforces allocation admission;
            # do not infer a resource guarantee from backend exception wording.
            raise ValueError("Zstandard body cannot be decoded within the window budget") from exc
    return raw


def message_content(message):
    return decoded_bytes(message.raw_content or b"", message.headers.get("content-encoding", ""))


def body_field(path):
    if len(path) == 1 and path[0] in ("_lensRawRequestBody", "_lensRawResponseBody"):
        return True
    if path in (("request", "postData", "text"), ("response", "content", "text")):
        return True
    return len(path) == 3 and path[0] == "_webSocketMessages" and isinstance(path[1], int) and path[2] == "data"


def metadata_size(value, limit, path=(), depth=0):
    if depth > 32:
        raise ValueError("HAR metadata nesting exceeds 32 levels")
    if body_field(path):
        return 0
    if isinstance(value, str):
        return text_size(value, limit, "HAR metadata", metadata=True)
    if isinstance(value, dict):
        total = 0
        for key, item in value.items():
            total += text_size(key, limit - total, "HAR metadata key", metadata=True) + 8
            if total > limit:
                raise ValueError("HAR metadata exceeds 16 MiB budget")
            total += metadata_size(item, limit - total, path + (key,), depth + 1)
            if total > limit:
                raise ValueError("HAR metadata exceeds 16 MiB budget")
        return total
    if isinstance(value, list):
        total = 0
        for index, item in enumerate(value):
            total += 8 + metadata_size(item, max(0, limit - total - 8), path + (index,), depth + 1)
            if total > limit:
                raise ValueError("HAR metadata exceeds 16 MiB budget")
        return total
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("HAR numbers must be finite")
        if type(value) is int:
            # An integer's decimal representation is unbounded. This upper bound
            # avoids allocating its string merely to perform budget admission.
            return max(16, value.bit_length() * 30103 // 100000 + 1 + (value < 0))
        return 16
    raise ValueError("Unsupported HAR metadata value")


@dataclass
class PreparedBody:
    raw: bytes | None
    decoded: bytes
    cost: int
    available: bool
    fields: dict


class ImportBudget:
    def __init__(self, max_flows, max_bytes, max_body_bytes=BODY_BYTES):
        self.max_flows, self.max_bytes, self.max_body_bytes = max_flows, max_bytes, max_body_bytes
        self.entries = self.bytes = self.metadata = 0

    def prepare(self, entry):
        self.entries += 1
        if self.entries > self.max_flows:
            raise ValueError(f"HAR must contain at most {self.max_flows} entries")
        self.metadata += metadata_size(entry, METADATA_BYTES - self.metadata)
        if self.metadata > METADATA_BYTES:
            raise ValueError("HAR metadata exceeds 16 MiB budget")
        prepared = {}
        for side, field, raw_key in (("request", "postData", "_lensRawRequestBody"),
                                     ("response", "content", "_lensRawResponseBody")):
            message = entry[side]
            body = message.get(field, {})
            if not isinstance(body, dict):
                raise ValueError(f"HAR {side}.{field} must be an object")
            if body.get("encoding") not in (None, "", "base64"):
                raise ValueError(f"Unsupported HAR {side} body encoding")
            for key in ("mimeType", "comment"):
                if key in body and not isinstance(body[key], str):
                    raise ValueError(f"HAR {side} body {key} must be a string")
            if field == "content":
                for key in ("size", "compression"):
                    if key in body and (type(body[key]) is not int or key == "size" and body[key] < -1):
                        raise ValueError(f"HAR response content {key} must be an integer" + (" at least -1" if key == "size" else ""))
            text = body.get("text", "")
            limit = min(self.max_body_bytes, self.max_bytes - self.bytes)
            size = base64_size(text, limit, "HAR body") if body.get("encoding") == "base64" else text_size(text, limit, "HAR body")
            raw_size = base64_size(entry[raw_key], limit, "HAR wire body") if raw_key in entry else 0
            cost = max(size, raw_size)
            if cost > limit:
                raise ValueError("HAR bodies exceed cumulative byte budget")
            raw = base64.b64decode(entry[raw_key], validate=True) if raw_key in entry else None
            decoded = base64.b64decode(text, validate=True) if body.get("encoding") == "base64" else text.encode("utf-8")
            if raw is not None:
                encoding = next((h["value"] for h in message.get("headers", []) if h["name"].lower() == "content-encoding"), "")
                actual = decoded_bytes(raw, encoding, limit)
                cost = max(cost, len(actual))
                if self.bytes + cost > self.max_bytes:
                    raise ValueError("HAR bodies exceed cumulative byte budget")
                del actual
            self.bytes += cost
            fields = {"sizes": {key: message[key] for key in ("headersSize", "bodySize") if key in message},
                      "present": field in message, "text_present": "text" in body,
                      "description": copy.deepcopy({key: value for key, value in body.items() if key != "text"})}
            for key, value in fields["sizes"].items():
                if type(value) is not int or value < -1:
                    raise ValueError(f"HAR {side}.{key} must be a nonnegative integer or -1")
            available = raw is not None or "text" in body or message.get("bodySize") == 0
            prepared[side] = PreparedBody(raw, decoded, cost, available, fields)
        # The WebSocket owner validates each fact and the combined payload
        # budget before decoding any message. HAR restoration consumes this parse.
        from websocket_capture import prepare
        prepared["websocket"] = prepare(entry, min(self.max_body_bytes, self.max_bytes - self.bytes))
        self.bytes += prepared["websocket"].size
        return prepared

    def account_encoded(self, flow, prepared):
        for side in ("request", "response"):
            message = getattr(flow, side)
            raw_size = len(message.raw_content or b"") if message else 0
            if raw_size > self.max_body_bytes:
                raise ValueError("Encoded HAR body exceeds 32 MiB byte budget")
            self.bytes += max(0, raw_size - prepared[side].cost)
            if self.bytes > self.max_bytes:
                raise ValueError("HAR bodies exceed cumulative byte budget")
