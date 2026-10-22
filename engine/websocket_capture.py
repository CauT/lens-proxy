"""WebSocket capture facts, bounded projections and HAR parsing owned here.

SDK messages own payload bytes. Imported message metadata records what the source
actually supplied; SDK placeholder opcodes/flags never become observed facts.
"""
import base64
import copy
from dataclasses import dataclass
import math

from bounds import BODY_BYTES, canonical_base64_size, text_size

MESSAGE_LIMIT = 2000
PREVIEW_LIMIT = 4096
PAGE_LIMIT = 50
MAX_GENERATION = (1 << 63) - 1
_SOURCE = "lens_websocket_source"
_GENERATION = "lens_websocket_generation"


@dataclass
class PreparedMessages:
    present: bool
    records: list
    generation: int
    generation_present: bool
    truncated: bool | None
    truncated_present: bool
    size: int


def prepare(entry, byte_limit):
    """Validate the entire message boundary before any payload decode/allocation."""
    present = "_webSocketMessages" in entry
    messages = entry.get("_webSocketMessages", [])
    if not isinstance(messages, list) or len(messages) > MESSAGE_LIMIT:
        raise ValueError("HAR WebSocket message count must be at most 2000")
    generation = entry.get("_lensWebSocketGeneration", 0)
    if type(generation) is not int or not 0 <= generation <= MAX_GENERATION:
        raise ValueError("HAR WebSocket generation must be an integer from 0 through 2^63-1")
    truncated = entry.get("_webSocketMessagesTruncated")
    if "_webSocketMessagesTruncated" in entry and type(truncated) is not bool:
        raise ValueError("HAR WebSocket truncation must be a boolean")
    if not present and ("_lensWebSocketGeneration" in entry or "_webSocketMessagesTruncated" in entry):
        raise ValueError("HAR WebSocket metadata requires a message list")
    size = 0
    for message in messages:
        if not isinstance(message, dict) or message.get("type") not in ("send", "receive"):
            raise ValueError("HAR WebSocket direction must be send or receive")
        timestamp = message.get("time")
        try:
            finite_timestamp = type(timestamp) in (int, float) and math.isfinite(timestamp)
        except OverflowError:
            finite_timestamp = False
        if not finite_timestamp:
            raise ValueError("HAR WebSocket timestamp must be finite")
        opcode = message.get("opcode")
        if opcode is not None and (type(opcode) is not int or opcode not in (1, 2)):
            raise ValueError("HAR WebSocket opcode must be 1, 2 or null")
        for flag in ("dropped", "injected"):
            if message.get(flag) is not None and type(message[flag]) is not bool:
                raise ValueError(f"HAR WebSocket {flag} must be boolean or null")
        encoding = message.get("encoding")
        if encoding not in (None, "", "base64"):
            raise ValueError("Unsupported HAR WebSocket message encoding")
        limit = min(BODY_BYTES, byte_limit) - size
        if encoding == "base64":
            size += canonical_base64_size(message.get("data"), limit, "HAR WebSocket message")
        else:
            size += text_size(message.get("data"), limit, "HAR WebSocket message")
    records = []
    for message in messages:
        payload = (base64.b64decode(message["data"], validate=True) if message.get("encoding") == "base64"
                   else message["data"].encode("utf-8"))
        records.append((payload, copy.deepcopy({k: v for k, v in message.items() if k != "data"})))
    return PreparedMessages(present, records, generation, "_lensWebSocketGeneration" in entry,
                            truncated, "_webSocketMessagesTruncated" in entry, size)


def restore(flow, prepared):
    if not prepared.present:
        return
    from mitmproxy.websocket import WebSocketData, WebSocketMessage
    flow.websocket = WebSocketData()
    sources = []
    for payload, source in prepared.records:
        # Unknown source facts require placeholders solely for the SDK container.
        # Every consumer below reads source facts rather than those placeholders.
        message = WebSocketMessage(source.get("opcode") or 2, source["type"] == "send", payload,
                                   dropped=source.get("dropped") or False,
                                   injected=source.get("injected") or False)
        message.timestamp = source["time"]  # SDK constructor changes a real zero to now.
        flow.websocket.messages.append(message)
        sources.append(source)
    flow.metadata[_SOURCE] = {"messages": sources, "generation_present": prepared.generation_present,
                              "truncated_present": prepared.truncated_present}
    flow.metadata[_GENERATION] = prepared.generation
    flow.metadata["websocket_messages_truncated"] = prepared.truncated


def generation(flow):
    return flow.metadata.get(_GENERATION, 0)


def retention_truncated(flow):
    # Imported omission is represented as None at restoration, once. Live
    # capture starts complete and records True only after known retention loss.
    return flow.metadata.get("websocket_messages_truncated", False)


def facts(flow, index, message):
    source = flow.metadata.get(_SOURCE)
    if source is not None:
        item = source["messages"][index]
        return {"opcode": item.get("opcode"), "dropped": item.get("dropped"), "injected": item.get("injected")}
    return {"opcode": int(message.type), "dropped": message.dropped, "injected": message.injected}


def retain(flow):
    """Bound capture before store accounting, without changing the forwarded message."""
    flow.metadata.pop(_SOURCE, None)
    flow.metadata[_GENERATION] = generation(flow) + 1
    messages = flow.websocket.messages
    original_count = len(messages)
    # A single oversized message is omitted from capture. Its SDK object is left
    # untouched: the protocol layer still owns and forwards that exact object.
    keep = [message for message in messages if len(message.content) <= BODY_BYTES]
    total = sum(len(message.content) for message in keep)
    start = max(0, len(keep) - MESSAGE_LIMIT)
    total -= sum(len(message.content) for message in keep[:start])
    while total > BODY_BYTES:
        total -= len(keep[start].content)
        start += 1
    messages[:] = keep[start:]
    if len(messages) != original_count:
        flow.metadata["websocket_messages_truncated"] = True


def page(flow, offset=0, limit=PAGE_LIMIT, expected_generation=None):
    if type(offset) is not int or offset < 0:
        raise ValueError("WebSocket offset must be a nonnegative integer")
    if type(limit) is not int or not 1 <= limit <= PAGE_LIMIT:
        raise ValueError("WebSocket page limit must be 1–50")
    current = generation(flow)
    if expected_generation is not None and (type(expected_generation) is not int or not 0 <= expected_generation <= MAX_GENERATION):
        raise ValueError("WebSocket generation must be an integer from 0 through 2^63-1")
    if expected_generation is not None and expected_generation != current:
        raise ValueError("WebSocket messages changed; reload from offset 0 with the current generation")
    messages = flow.websocket.messages if flow.websocket is not None else []
    if offset > len(messages):
        raise ValueError("WebSocket offset exceeds retained message count")
    result = []
    for index in range(offset, min(offset + limit, len(messages))):
        message = messages[index]
        preview = message.content[:PREVIEW_LIMIT]
        result.append({"index": index, "direction": "send" if message.from_client else "receive",
                       "timestamp": message.timestamp, "text": preview.decode("utf-8", "replace"),
                       "content_base64": base64.b64encode(preview).decode("ascii"),
                       "content_bytes": len(message.content), "preview_truncated": len(preview) < len(message.content),
                       **facts(flow, index, message)})
    return {"id": flow.id, "messages": result, "total": len(messages), "offset": offset, "limit": limit,
            "next_offset": offset + len(result) if offset + len(result) < len(messages) else None,
            "generation": current, "preview_limit": PREVIEW_LIMIT,
            "retention_truncated": retention_truncated(flow)}


def detail_fields(flow):
    value = page(flow)
    return {"messages": value["messages"], "messages_truncated": value["retention_truncated"],
            **{f"messages_{key}": value[key] for key in
               ("total", "offset", "limit", "next_offset", "generation", "preview_limit")}}


def export(flow):
    if flow.websocket is None:
        return {}
    source = flow.metadata.get(_SOURCE)
    messages = []
    for index, message in enumerate(flow.websocket.messages):
        if source is None:
            item = {"type": "send" if message.from_client else "receive", "time": message.timestamp,
                    "encoding": "base64", **facts(flow, index, message)}
        else:
            item = copy.deepcopy(source["messages"][index])
        item["data"] = (base64.b64encode(message.content).decode("ascii") if item.get("encoding") == "base64"
                        else message.content.decode("utf-8"))
        messages.append(item)
    result = {"_webSocketMessages": messages}
    if source is None or source["truncated_present"]:
        result["_webSocketMessagesTruncated"] = flow.metadata.get("websocket_messages_truncated", False)
    if source is None or source["generation_present"]:
        result["_lensWebSocketGeneration"] = generation(flow)
    return result


def preserve_copy(source, target):
    """SDK copying calls its constructor, which changes timestamp zero to now."""
    if source.websocket is not None:
        for original, copied in zip(source.websocket.messages, target.websocket.messages):
            copied.timestamp = original.timestamp
