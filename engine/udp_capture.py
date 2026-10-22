"""Bounded atomic UDP datagram observations, separate from HTTP/HAR and TCP."""
import asyncio
import base64
from collections import OrderedDict
import ipaddress
import math
import time
import uuid

from forwarding import parse_forwards

ASSOCIATIONS = 2000
STORE_BYTES = 32 * 1024 * 1024
ASSOCIATION_BYTES = 4 * 1024 * 1024
DATAGRAMS = 1024
# Reserve metadata/scalar/list costs even for empty UDP payloads. This capture
# accounting budget is not a guarantee about total interpreter RSS.
DATAGRAM_OVERHEAD = 512
DATAGRAM_BYTES = 65535
FILE_BYTES = 96 * 1024 * 1024
EMIT_INTERVAL = .1
ACTIVE = ("resolving", "open")
TERMINAL = ("idle", "cancelled", "error")
FIELDS = set("id listen_port target_host target_port dial_host client listener_address peer peer_scope peer_flowinfo started ended state source_state error sent_datagrams received_datagrams sent_bytes received_bytes retained_bytes observed_datagrams truncated imported dropped_client_datagrams dropped_client_bytes dropped_upstream_datagrams dropped_upstream_bytes datagrams".split())
DATAGRAM_FIELDS = {"sequence", "direction", "timestamp", "observed_bytes"}


def integer(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("Invalid UDP count")
    return value


def timestamp(value):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("Invalid UDP timestamp")
    return value


def address(value, *, encoded=False):
    if not isinstance(value, list if encoded else (tuple, list)) or len(value) != 2:
        raise ValueError("Invalid numeric UDP address")
    host, port = value
    if not isinstance(host, str) or len(host) > 64 or "%" in host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid numeric UDP address")
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Invalid numeric UDP address") from exc
    # These are observed numeric source values, not names to resolve or display
    # normalizations to reinterpret. Keep their spelling through persistence.
    return host, port


def direction_fields(direction):
    if direction not in ("send", "receive"):
        raise ValueError("UDP direction must be send or receive")
    return ("sent_datagrams", "sent_bytes") if direction == "send" else ("received_datagrams", "received_bytes")


class UDPAssociation:
    def __init__(self, owner, forward, client, listener):
        client, listener = address(client), address(listener)
        if listener[1] != forward.listen_port:
            raise ValueError("UDP listener source/configured port disagree")
        self.owner, self.datagrams, self.cost, self.last_emit = owner, [], 0, 0
        self.pending_emit = None
        self.value = {"id": uuid.uuid4().hex, **forward.public(), "client": client,
            "listener_address": listener, "peer": None, "peer_scope": None, "peer_flowinfo": None,
            "started": time.time(), "ended": None, "state": "resolving", "source_state": None, "error": None,
            "sent_datagrams": 0, "received_datagrams": 0, "sent_bytes": 0, "received_bytes": 0,
            "retained_bytes": 0, "observed_datagrams": 0, "truncated": False, "imported": False,
            "dropped_client_datagrams": 0, "dropped_client_bytes": 0,
            "dropped_upstream_datagrams": 0, "dropped_upstream_bytes": 0}

    @property
    def retained(self):
        return self.owner.associations.get(self.value["id"]) is self

    def cancel_pending(self):
        if self.pending_emit is not None:
            self.pending_emit.cancel()
            self.pending_emit = None

    def flush_pending(self):
        self.pending_emit = None
        if self.retained and self.value["state"] in ACTIVE:
            self.notify(True)

    def notify(self, force=False):
        if not self.retained:
            self.cancel_pending()
            return
        now = time.monotonic()
        remaining = EMIT_INTERVAL - (now - self.last_emit)
        if not force and remaining > 0 and self.value["state"] in ACTIVE:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                pass  # Synchronous capture callers have no later loop to flush.
            else:
                if self.pending_emit is None:
                    # One owner and one timer coalesce a short burst into its
                    # latest summary even when no more datagrams arrive.
                    self.pending_emit = loop.call_later(remaining, self.flush_pending)
                return
        self.cancel_pending()
        self.last_emit = now
        self.owner.emit("udp_association", association=self.summary())

    def summary(self):
        return {**self.value, "retained_datagrams": len(self.datagrams)}

    def connected(self, peer):
        if self.value["state"] != "resolving":
            return
        if not isinstance(peer, (tuple, list)) or len(peer) not in (2, 4):
            raise ValueError("Invalid numeric UDP peer")
        endpoint = address(peer[:2])
        flowinfo, scope = (peer[2], peer[3]) if len(peer) == 4 else (None, None)
        if len(peer) == 4 and (ipaddress.ip_address(endpoint[0]).version != 6 or
                              any(integer(value) > 2**32 - 1 for value in (flowinfo, scope))):
            raise ValueError("Invalid UDP peer scope/flow information")
        self.value.update(state="open", peer=endpoint, peer_scope=scope, peer_flowinfo=flowinfo)
        if self.retained:
            self.owner.changed()
        self.notify(True)

    def data(self, direction, content):
        count, size = direction_fields(direction)
        if not isinstance(content, bytes) or len(content) > DATAGRAM_BYTES:
            raise ValueError("UDP observation must be one bounded bytes datagram")
        if self.value["state"] != "open":
            return
        self.value[count] += 1
        self.value[size] += len(content)
        self.value["observed_datagrams"] += 1
        if not self.retained:
            self.value["truncated"] = True
            return
        cost = len(content) + DATAGRAM_OVERHEAD
        fits = len(self.datagrams) < DATAGRAMS and self.value["retained_bytes"] + len(content) <= ASSOCIATION_BYTES
        if fits and self.cost + cost > self.owner.capacity:
            fits = False
        if fits:
            self.owner.make_room(cost, self)
            fits = self.owner.cost + cost <= self.owner.limit
        if fits:
            # Never split a UDP packet into TCP-like byte chunks or retain a
            # prefix. An empty packet is still an observed atomic datagram.
            self.datagrams.append({"sequence": self.value["observed_datagrams"], "direction": direction,
                "timestamp": time.time(), "observed_bytes": len(content), "content": content})
            self.cost += cost
            self.owner.cost += cost
            self.value["retained_bytes"] += len(content)
        else:
            self.value["truncated"] = True
        self.owner.changed()
        self.notify()

    def dropped(self, direction, count, bytes):
        direction_fields(direction)
        integer(count)
        integer(bytes)
        if bytes > count * DATAGRAM_BYTES:
            raise ValueError("UDP dropped byte/datagram counts disagree")
        if self.value["state"] not in ACTIVE:
            return
        prefix = "dropped_client" if direction == "send" else "dropped_upstream"
        self.value[prefix + "_datagrams"] += count
        self.value[prefix + "_bytes"] += bytes
        if self.retained and (count or bytes):
            self.owner.changed()
        # This accounts only for a forwarder's explicit unforwarded packets;
        # it makes no claim about unknown losses elsewhere on the network.
        self.notify()

    def finish(self, state, error=None):
        if state not in TERMINAL:
            raise ValueError("Invalid terminal UDP state")
        if error is not None and not isinstance(error, str):
            raise ValueError("Invalid UDP error")
        if self.value["state"] not in ACTIVE:
            return
        if state == "idle" and self.value["peer"] is None:
            raise ValueError("Unconnected UDP association cannot become idle")
        self.value.update(state=state, error=error[:2000] if error else None, ended=time.time())
        if self.retained:
            self.owner.changed()
        self.notify(True)


class UDPRecorder:
    def __init__(self, emit, limit=STORE_BYTES, pool=None, changed=lambda: None):
        if type(limit) is not int or not 0 <= limit <= STORE_BYTES:
            raise ValueError("UDP store budget must be between 0 and 32 MiB")
        self.emit, self._limit, self.cost, self.pool = emit, limit, 0, pool
        self.changed = changed
        if pool is not None:
            pool.recorders.append(self)
        self.associations = OrderedDict()

    @property
    def capacity(self):
        return self._limit if self.pool is None else min(self._limit, self.pool.limit)

    @property
    def limit(self):
        return self._limit if self.pool is None else min(self._limit, self.pool.available(self))

    @limit.setter
    def limit(self, value):
        self._limit = value

    def begin(self, forward, clientTuple, listenerTuple):
        # Validate before evicting an existing capture on a rejected address.
        association = UDPAssociation(self, forward, clientTuple, listenerTuple)
        if self.pool is not None:
            self.pool.admit_record()
        while len(self.associations) >= ASSOCIATIONS:
            self.discard(next(iter(self.associations)))
        self.associations[association.value["id"]] = association
        self.changed()
        association.notify(True)
        return association

    def discard(self, identity):
        association = self.associations.pop(identity)
        association.cancel_pending()
        self.cost -= association.cost
        association.datagrams.clear()
        association.cost = 0
        association.value["retained_bytes"] = 0
        if association.value["observed_datagrams"]:
            association.value["truncated"] = True
        self.changed()
        self.emit("udp_removed", id=identity)

    def make_room(self, cost, current):
        if self.pool is not None:
            self.pool.make_room(cost, current)
            return
        while self.cost + cost > self.limit:
            oldest = next((key for key, value in self.associations.items() if value is not current), None)
            if oldest is None:
                break
            self.discard(oldest)

    def clear(self):
        modified = bool(self.associations)
        for association in self.associations.values():
            association.cancel_pending()
            association.datagrams.clear()
            association.cost = 0
            association.value["retained_bytes"] = 0
            if association.value["observed_datagrams"]:
                association.value["truncated"] = True
        self.associations.clear()
        self.cost = 0
        if modified:
            self.changed()
        self.emit("udp_reset")

    def page(self, identity, offset=0, limit=32):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("UDP datagram page requires offset >= 0 and limit between 1 and 32")
        association = self.associations[identity]
        return {"association": association.summary(), "offset": offset, "total": len(association.datagrams),
            "datagrams": [encode_datagram(value) for value in association.datagrams[offset:offset + limit]]}

    def snapshot(self):
        # Immutable payload bytes may be shared with the file worker; every
        # mutable dictionary/list is copied before capture, clear or eviction.
        return [{**association.value, "datagrams": [dict(value) for value in association.datagrams]}
                for association in self.associations.values()]

    def replace(self, values):
        # Even direct callers cannot partially clear the current capture before
        # a later malformed record or aggregate budget failure is discovered.
        prepared = prepare_associations(values, imported=True, budget=self.limit)
        self.clear()
        for value in prepared:
            association = object.__new__(UDPAssociation)
            association.owner, association.last_emit = self, 0
            association.pending_emit = None
            association.datagrams = value.pop("datagrams")
            association.cost = sum(len(item["content"]) + DATAGRAM_OVERHEAD for item in association.datagrams)
            association.value = value
            self.associations[value["id"]] = association
            self.cost += association.cost
            self.changed()
            association.notify(True)


def encode_datagram(value):
    return {key: item for key, item in value.items() if key != "content"} | {
        "base64": base64.b64encode(value["content"]).decode("ascii")}


def prepare_associations(values, *, encoded=False, imported=False, budget=STORE_BYTES):
    if not isinstance(values, list) or len(values) > ASSOCIATIONS:
        raise ValueError("UDP session exceeds association limit")
    result, identities, cost = [], set(), 0
    for value in values:
        if not isinstance(value, dict) or set(value) != FIELDS:
            raise ValueError("UDP association has missing or unsupported fields")
        identity = value["id"]
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity) or identity in identities:
            raise ValueError("Invalid/duplicate UDP association identity")
        identities.add(identity)
        endpoint = parse_forwards([value], [], transport="UDP")[0]
        if value["dial_host"] != endpoint.dial_host:
            raise ValueError("UDP target source/lookup disagree")
        client = address(value["client"], encoded=encoded)
        listener = address(value["listener_address"], encoded=encoded)
        if listener[1] != endpoint.listen_port:
            raise ValueError("UDP listener source/configured port disagree")
        peer = None if value["peer"] is None else address(value["peer"], encoded=encoded)
        for key in ("peer_scope", "peer_flowinfo"):
            if value[key] is not None and (peer is None or ipaddress.ip_address(peer[0]).version != 6 or integer(value[key]) > 2**32 - 1):
                raise ValueError("Invalid UDP peer scope/flow information")
        if (value["peer_scope"] is None) != (value["peer_flowinfo"] is None):
            raise ValueError("UDP peer scope/flow information must be jointly observed")
        timestamp(value["started"])
        if value["ended"] is not None:
            timestamp(value["ended"])
        state, source_state = value["state"], value["source_state"]
        if state not in (*ACTIVE, *TERMINAL, "incomplete"):
            raise ValueError("Unknown UDP state")
        if state == "incomplete":
            if source_state not in ACTIVE or value["ended"] is not None or value["imported"] is not True:
                raise ValueError("Invalid historical UDP source state")
        elif source_state is not None:
            raise ValueError("Invalid historical UDP source state")
        if state in TERMINAL and value["ended"] is None:
            raise ValueError("Terminal UDP association lacks an end observation")
        if state in ACTIVE and value["ended"] is not None:
            raise ValueError("Active UDP association has an end observation")
        effective = source_state if state == "incomplete" else state
        if (effective == "resolving" and peer is not None) or (effective in ("open", "idle") and peer is None):
            raise ValueError("UDP state disagrees with resolved peer")
        error = value["error"]
        if error is not None and (not isinstance(error, str) or len(error) > 2000 or effective in ACTIVE):
            raise ValueError("Invalid UDP error")
        if type(value["truncated"]) is not bool or type(value["imported"]) is not bool:
            raise ValueError("Invalid UDP capture flags")
        counts = {key: integer(value[key]) for key in ("sent_datagrams", "received_datagrams", "sent_bytes", "received_bytes",
            "retained_bytes", "observed_datagrams", "dropped_client_datagrams", "dropped_client_bytes",
            "dropped_upstream_datagrams", "dropped_upstream_bytes")}
        for prefix, count_key, byte_key in (("sent", "sent_datagrams", "sent_bytes"),
                ("received", "received_datagrams", "received_bytes"),
                ("dropped client", "dropped_client_datagrams", "dropped_client_bytes"),
                ("dropped upstream", "dropped_upstream_datagrams", "dropped_upstream_bytes")):
            if counts[byte_key] > counts[count_key] * DATAGRAM_BYTES:
                raise ValueError(f"UDP {prefix} byte/datagram counts disagree")
        if counts["sent_datagrams"] + counts["received_datagrams"] != counts["observed_datagrams"]:
            raise ValueError("UDP forwarded datagram counts disagree")
        if counts["retained_bytes"] > ASSOCIATION_BYTES:
            raise ValueError("UDP session exceeds association payload budget")
        datagrams = value["datagrams"]
        if not isinstance(datagrams, list) or len(datagrams) > DATAGRAMS:
            raise ValueError("UDP session exceeds datagram limit")
        prepared, sizes, seen, sequence = [], {"send": 0, "receive": 0}, {"send": 0, "receive": 0}, 0
        for item in datagrams:
            content_key = "base64" if encoded else "content"
            if not isinstance(item, dict) or set(item) != DATAGRAM_FIELDS | {content_key} or not isinstance(item["direction"], str) or item["direction"] not in sizes:
                raise ValueError("Invalid UDP datagram fields/direction")
            number, length = integer(item["sequence"]), integer(item["observed_bytes"])
            if not sequence < number <= counts["observed_datagrams"] or length > DATAGRAM_BYTES:
                raise ValueError("Invalid UDP datagram sequence/size")
            sequence = number
            timestamp(item["timestamp"])
            # Admit declared lengths and total accounting before allocating any
            # decoded payload, including 512 B for every zero-byte datagram.
            cost += length + DATAGRAM_OVERHEAD
            if cost > budget or sum(sizes.values()) + length > ASSOCIATION_BYTES:
                raise ValueError("UDP session exceeds capture budget")
            content = item[content_key]
            if encoded:
                if not isinstance(content, str) or len(content) != ((length + 2) // 3) * 4:
                    raise ValueError("UDP datagram encoded size disagrees")
                try:
                    content = base64.b64decode(content, validate=True)
                except ValueError as exc:
                    raise ValueError("Invalid UDP datagram base64") from exc
            if not isinstance(content, bytes) or len(content) != length:
                raise ValueError("UDP datagram must retain its complete atomic payload")
            sizes[item["direction"]] += length
            seen[item["direction"]] += 1
            prepared.append({"sequence": number, "direction": item["direction"], "timestamp": item["timestamp"],
                "observed_bytes": length, "content": content})
        if sum(sizes.values()) != counts["retained_bytes"]:
            raise ValueError("UDP retained-byte counts disagree")
        for direction in sizes:
            count_key, byte_key = direction_fields(direction)
            missing_count = counts[count_key] - seen[direction]
            missing_bytes = counts[byte_key] - sizes[direction]
            if missing_count < 0 or not 0 <= missing_bytes <= missing_count * DATAGRAM_BYTES:
                raise ValueError("UDP retained/forwarded counts disagree")
        if not value["truncated"] and (len(datagrams) != counts["observed_datagrams"] or
                counts["retained_bytes"] != counts["sent_bytes"] + counts["received_bytes"]):
            raise ValueError("Incomplete UDP capture cannot claim completeness")
        if peer is None and counts["observed_datagrams"]:
            raise ValueError("UDP association without an observed peer cannot have forwarded datagrams")
        if imported and state in ACTIVE:
            state, source_state = "incomplete", state
        result.append({"id": identity, **endpoint.public(), "client": client, "listener_address": listener,
            "peer": peer, "peer_scope": value["peer_scope"], "peer_flowinfo": value["peer_flowinfo"],
            "started": value["started"], "ended": value["ended"], "state": state, "source_state": source_state,
            "error": error, **counts, "truncated": value["truncated"], "imported": True if imported else value["imported"],
            "datagrams": prepared})
    return result


def save_associations(path, values):
    from persistence import atomic_text, LimitedWriter
    import json
    prepared = prepare_associations(values)
    with atomic_text(path) as file:
        writer = LimitedWriter(file, FILE_BYTES, "UDP session")
        writer.write('{"format":"lens-udp-datagrams","version":1,"associations":[')
        for index, value in enumerate(prepared):
            if index:
                writer.write(",")
            encoded = {**value, "datagrams": [encode_datagram(item) for item in value["datagrams"]]}
            json.dump(encoded, writer, ensure_ascii=True, allow_nan=False)
        writer.write("]}")
    return {"path": str(path), "associations": len(prepared)}


def load_associations(path):
    from persistence import read_document
    document = read_document(path, FILE_BYTES, "UDP session", unique_keys=True)
    if not isinstance(document, dict) or set(document) != {"format", "version", "associations"} or document["format"] != "lens-udp-datagrams" or type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("Unsupported UDP session format/version/fields")
    return prepare_associations(document["associations"], encoded=True, imported=True)
