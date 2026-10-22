"""Bounded, protocol-neutral TCP byte observations, separate from HTTP/HAR."""
import base64
from collections import OrderedDict
import math
import time
import uuid

from endpoints import canonical_host
from network import CHUNK_SIZE

STREAMS = 2000
STORE_BYTES = 32 * 1024 * 1024
STREAM_BYTES = 4 * 1024 * 1024
CHUNKS = 1024
# The pinned CPython shallow per-chunk estimate is 305 B (dict/scalars/bytes
# header/list slot), excluding shared keys/direction. Reserve 512 accounting
# bytes; this remains a capture budget, not a process RSS guarantee.
CHUNK_OVERHEAD = 512
FILE_BYTES = 96 * 1024 * 1024
STREAM_FIELDS = set("id listen_port target_host target_port dial_host peer peer_scope peer_flowinfo started ended state source_state error sent_bytes received_bytes retained_bytes observed_chunks truncated imported chunks".split())


class TCPStream:
    def __init__(self, owner, forward):
        self.owner, self.chunks, self.cost, self.last_emit = owner, [], 0, 0
        self.value = {"id": uuid.uuid4().hex, **forward.public(), "peer": None, "peer_scope": None, "peer_flowinfo": None,
            "started": time.time(), "ended": None, "state": "connecting", "source_state": None, "error": None,
            "sent_bytes": 0, "received_bytes": 0, "retained_bytes": 0,
            "observed_chunks": 0, "truncated": False, "imported": False}

    @property
    def retained(self):
        return self.owner.streams.get(self.value["id"]) is self

    def notify(self, force=False):
        now = time.monotonic()
        if self.retained and (force or now - self.last_emit >= .1):
            self.last_emit = now
            self.owner.emit("tcp_stream", stream=self.summary())

    def summary(self):
        return {**self.value, "retained_chunks": len(self.chunks)}

    def connected(self, peer):
        self.value.update(state="open", peer=tuple(peer[:2]), peer_scope=peer[3] if len(peer) > 3 else None,
                          peer_flowinfo=peer[2] if len(peer) > 2 else None)
        if self.retained:
            self.owner.changed()
        self.notify(True)

    def data(self, direction, content):
        field = "sent_bytes" if direction == "send" else "received_bytes"
        self.value[field] += len(content)
        self.value["observed_chunks"] += 1
        if not self.retained:
            return
        available = STREAM_BYTES - self.value["retained_bytes"]
        length = min(len(content), available) if len(self.chunks) < CHUNKS else 0
        if length:
            self.owner.make_room(length + CHUNK_OVERHEAD, self)
            length = min(length, max(0, self.owner.limit - self.owner.cost - CHUNK_OVERHEAD))
        if length:
            self.chunks.append({"sequence": self.value["observed_chunks"], "direction": direction,
                "timestamp": time.time(), "observed_bytes": len(content), "content": content[:length]})
            cost = length + CHUNK_OVERHEAD
            self.cost += cost
            self.owner.cost += cost
            self.value["retained_bytes"] += length
        if length < len(content):
            self.value["truncated"] = True
        self.owner.changed()
        self.notify()

    def finish(self, state, error=None):
        if self.value["state"] not in ("connecting", "open"):
            return
        self.value.update(state=state, error=error[:2000] if error else None, ended=time.time())
        if self.retained:
            self.owner.changed()
        self.notify(True)


class TCPRecorder:
    def __init__(self, emit, limit=STORE_BYTES, pool=None, changed=lambda: None):
        self.emit, self._limit, self.cost, self.pool = emit, limit, 0, pool
        self.changed = changed
        if pool is not None:
            pool.recorders.append(self)
        self.streams = OrderedDict()

    @property
    def limit(self):
        return self._limit if self.pool is None else min(self._limit, self.pool.available(self))

    @limit.setter
    def limit(self, value):
        self._limit = value

    def begin(self, forward):
        if self.pool is not None:
            self.pool.admit_record()
        while len(self.streams) >= STREAMS:
            self.discard(next(iter(self.streams)))
        stream = TCPStream(self, forward)
        self.streams[stream.value["id"]] = stream
        self.changed()
        stream.notify(True)
        return stream

    def discard(self, identity):
        stream = self.streams.pop(identity)
        self.cost -= stream.cost
        # Active relay closures may still reference this observation owner.
        # Release its retained bytes at eviction rather than waiting for EOF.
        stream.chunks.clear()
        stream.cost = 0
        self.changed()
        self.emit("tcp_removed", id=identity)

    def make_room(self, cost, current):
        if self.pool is not None:
            self.pool.make_room(cost, current)
            return
        while self.cost + cost > self.limit:
            oldest = next((key for key, stream in self.streams.items() if stream is not current), None)
            if oldest is None:
                break
            self.discard(oldest)

    def clear(self):
        modified = bool(self.streams)
        for stream in self.streams.values():
            stream.chunks.clear()
            stream.cost = 0
        self.streams.clear()
        self.cost = 0
        if modified:
            self.changed()
        self.emit("tcp_reset")

    def page(self, identity, offset=0, limit=32):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("TCP chunk page requires offset >= 0 and limit between 1 and 32")
        stream = self.streams[identity]
        values = stream.chunks[offset:offset + limit]
        return {"stream": stream.summary(), "offset": offset, "total": len(stream.chunks),
                "chunks": [encode_chunk(chunk) for chunk in values]}

    def snapshot(self):
        # Called on the event-loop owner; immutable bytes can be shared with the
        # file worker. Lists/scalars are frozen before later forwarding/eviction.
        return [{**stream.value, "chunks": list(stream.chunks)} for stream in self.streams.values()]

    def replace(self, values):
        self.clear()
        for value in values:
            stream = object.__new__(TCPStream)
            stream.owner, stream.last_emit = self, 0
            stream.chunks = list(value["chunks"])
            stream.cost = sum(len(chunk["content"]) + CHUNK_OVERHEAD for chunk in stream.chunks)
            stream.value = {key: item for key, item in value.items() if key != "chunks"}
            if stream.value["state"] in ("connecting", "open"):
                stream.value["source_state"] = stream.value["state"]
                stream.value["state"] = "incomplete"
            stream.value["imported"] = True
            self.streams[stream.value["id"]] = stream
            self.cost += stream.cost
            self.changed()
            stream.notify(True)


def encode_chunk(chunk):
    return {key: value for key, value in chunk.items() if key != "content"} | {
        "base64": base64.b64encode(chunk["content"]).decode("ascii")}


def save_streams(path, values):
    from persistence import atomic_text, LimitedWriter
    import json
    with atomic_text(path) as file:
        writer = LimitedWriter(file, FILE_BYTES, "TCP session")
        writer.write('{"format":"lens-tcp-streams","version":1,"streams":[')
        for index, value in enumerate(values):
            if index:
                writer.write(",")
            encoded = {**value, "chunks": [encode_chunk(chunk) for chunk in value["chunks"]]}
            json.dump(encoded, writer, ensure_ascii=True, allow_nan=False)
        writer.write("]}")
    return {"path": str(path), "streams": len(values)}


def load_streams(path):
    from persistence import read_document
    document = read_document(path, FILE_BYTES, "TCP session", unique_keys=True)
    if not isinstance(document, dict) or document.get("format") != "lens-tcp-streams" or type(document.get("version")) is not int or document["version"] != 1:
        raise ValueError("Unsupported TCP session format/version")
    if set(document) - {"format", "version", "streams"}:
        raise ValueError("Unsupported TCP document fields")
    return prepare_streams(document.get("streams"))


def prepare_streams(values, *, budget=STORE_BYTES):
    if not isinstance(values, list) or len(values) > STREAMS:
        raise ValueError("TCP session exceeds stream limit")
    result, identities, cost = [], set(), 0
    def integer(value):
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValueError("Invalid TCP count")
        return value
    def timestamp(value):
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("Invalid TCP timestamp")
    for value in values:
        if not isinstance(value, dict) or set(value) - STREAM_FIELDS:
            raise ValueError("TCP stream must be an object")
        identity = value.get("id")
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity) or identity in identities:
            raise ValueError("Invalid/duplicate TCP stream identity")
        identities.add(identity)
        from forwarding import parse_forwards
        endpoint = parse_forwards([value], [])[0]
        if value.get("dial_host") != endpoint.dial_host:
            raise ValueError("TCP target source/lookup disagree")
        peer = value.get("peer")
        if peer is not None:
            if not isinstance(peer, list) or len(peer) != 2 or canonical_host(peer[0]) != peer[0] or type(peer[1]) is not int or not 1 <= peer[1] <= 65535:
                raise ValueError("Invalid TCP peer")
        for key in ("peer_scope", "peer_flowinfo"):
            if value.get(key) is not None and (peer is None or integer(value[key]) > 2**32 - 1):
                raise ValueError("Invalid TCP peer scope/flow information")
        timestamp(value.get("started"))
        if value.get("ended") is not None:
            timestamp(value["ended"])
        state = value.get("state")
        if state not in ("connecting", "open", "closed", "cancelled", "error", "incomplete"):
            raise ValueError("Unknown TCP state")
        source_state = value.get("source_state")
        if source_state is not None and (state != "incomplete" or source_state not in ("connecting", "open")):
            raise ValueError("Invalid historical TCP source state")
        if state in ("closed", "cancelled", "error") and value.get("ended") is None:
            raise ValueError("Terminal TCP stream lacks an end observation")
        error = value.get("error")
        if error is not None and (not isinstance(error, str) or len(error) > 2000):
            raise ValueError("Invalid TCP error")
        sent, received, retained, observed = (integer(value.get(key)) for key in ("sent_bytes", "received_bytes", "retained_bytes", "observed_chunks"))
        if type(value.get("truncated")) is not bool or type(value.get("imported")) is not bool:
            raise ValueError("Invalid TCP capture flags")
        chunks = value.get("chunks")
        if not isinstance(chunks, list) or len(chunks) > CHUNKS:
            raise ValueError("TCP session exceeds chunk limit")
        prepared, sizes, seen, sequence = [], {"send": 0, "receive": 0}, {"send": 0, "receive": 0}, 0
        for chunk in chunks:
            if not isinstance(chunk, dict) or set(chunk) - {"sequence", "direction", "timestamp", "observed_bytes", "base64"} or chunk.get("direction") not in sizes:
                raise ValueError("Invalid TCP chunk direction")
            number, length = integer(chunk.get("sequence")), integer(chunk.get("observed_bytes"))
            if not sequence < number <= observed or not 1 <= length <= CHUNK_SIZE:
                raise ValueError("Invalid TCP chunk sequence/size")
            sequence = number
            timestamp(chunk.get("timestamp"))
            encoded = chunk.get("base64")
            # Admission before base64 allocation; actual retained data is at
            # most one relay chunk and shares the aggregate metadata allowance.
            if not isinstance(encoded, str) or len(encoded) > ((min(length, STREAM_BYTES - sum(sizes.values())) + 2) // 3) * 4:
                raise ValueError("TCP chunk exceeds retained-byte budget")
            content = base64.b64decode(encoded, validate=True)
            if not 1 <= len(content) <= min(length, STREAM_BYTES - sum(sizes.values())):
                raise ValueError("Invalid retained TCP chunk length")
            sizes[chunk["direction"]] += len(content)
            seen[chunk["direction"]] += length
            cost += len(content) + CHUNK_OVERHEAD
            if cost > budget:
                raise ValueError("TCP session exceeds aggregate capture budget")
            prepared.append({"sequence": number, "direction": chunk["direction"],
                "timestamp": chunk["timestamp"], "observed_bytes": length, "content": content})
        if sum(sizes.values()) != retained or seen["send"] > sent or seen["receive"] > received:
            raise ValueError("TCP byte counts disagree")
        if not value["truncated"] and (retained != sent + received or len(chunks) != observed or sum(seen.values()) != retained):
            raise ValueError("Incomplete TCP capture cannot claim completeness")
        result.append({"id": identity, **endpoint.public(), "peer": tuple(peer) if peer else None, "peer_scope": value.get("peer_scope"),
            "peer_flowinfo": value.get("peer_flowinfo"),
            "started": value["started"], "ended": value.get("ended"), "state": state, "source_state": source_state, "error": error,
            "sent_bytes": sent, "received_bytes": received, "retained_bytes": retained,
            "observed_chunks": observed, "truncated": value["truncated"], "imported": True, "chunks": prepared})
    return result
