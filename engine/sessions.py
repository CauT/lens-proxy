"""Capture session ownership and one atomic workspace snapshot.

A session owns its flow map. Capture selects a destination; viewing a different
session does not retarget in-flight requests. Public HAR remains session-local.
"""
from collections import OrderedDict
from dataclasses import dataclass, field
import json
import re
import uuid
from weakref import WeakKeyDictionary, WeakSet, ref

from bounds import ImportBudget, METADATA_BYTES, STORE_BYTES, metadata_size, text_size
from har import export_flow, import_entry, snapshot_flow
from har_metadata import document_metadata, uses_live_connection_timing
from persistence import atomic_text, LimitedWriter, read_document
from tcp_capture import TCPRecorder, STREAMS, STORE_BYTES as TCP_BYTES, CHUNK_OVERHEAD, encode_chunk, prepare_streams
from udp_capture import UDPRecorder, ASSOCIATIONS, STORE_BYTES as UDP_BYTES, DATAGRAM_OVERHEAD, encode_datagram, prepare_associations

SESSION_ID = re.compile(r"(?:default|[0-9a-f]{32})\Z")


def validate_name(name):
    text_size(name, 4096, "Session name")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Session name must be valid Unicode text") from exc
    if not name.strip() or any(value in name for value in "\0\r\n"):
        raise ValueError("Session name must contain visible text without NUL or line breaks")


class RawCapturePool:
    """One transport's retention allowance across all session owners."""
    def __init__(self, field, limit, count):
        self.field, self.limit, self.count = field, limit, count
        self.recorders = []

    def records(self):
        return ((recorder, key, value) for recorder in self.recorders
                for key, value in getattr(recorder, self.field).items())

    def available(self, owner):
        return max(0, self.limit - sum(recorder.cost for recorder in self.recorders if recorder is not owner))

    def discard_oldest(self, current=None):
        oldest = min((item for item in self.records() if item[2] is not current),
                     key=lambda item: item[2].value["started"], default=None)
        if oldest is None:
            return False
        oldest[0].discard(oldest[1])
        return True

    def admit_record(self):
        while sum(len(getattr(recorder, self.field)) for recorder in self.recorders) >= self.count:
            if not self.discard_oldest():
                break

    def make_room(self, cost, current):
        while sum(recorder.cost for recorder in self.recorders) + cost > self.limit:
            if not self.discard_oldest(current):
                break

    def admit_replacement(self, owner, count, cost):
        if (sum(len(getattr(recorder, self.field)) for recorder in self.recorders if recorder is not owner) + count > self.count
                or cost > self.available(owner)):
            raise ValueError("Raw session exceeds the shared workspace capture budget")


@dataclass(eq=False)
class CaptureSession:
    id: str
    number: int
    name: str | None = None
    closed: bool = False
    flows: OrderedDict = field(default_factory=OrderedDict)
    tcp: object = None
    udp: object = None

    def public(self):
        return {"id": self.id, "number": self.number, "name": self.name if self.name is not None else f"Untitled Session {self.number}"}


class CaptureSessions:
    def __init__(self, emit=lambda *args, **kwargs: None, changed=lambda: None):
        self.emit = emit
        self.changed = changed
        self.tcp_pool = RawCapturePool("streams", TCP_BYTES, STREAMS)
        self.udp_pool = RawCapturePool("associations", UDP_BYTES, ASSOCIATIONS)
        first = self.make_room("default", 1)
        self.items = OrderedDict([(first.id, first)])
        self.capture = first
        self.last_number = 1
        self.owners = WeakKeyDictionary()
        self.client_flows = {}

    def make_room(self, identity, number, name=None):
        room = CaptureSession(identity, number, name)
        def notify(event, **values):
            if not room.closed:
                self.emit(event, session_id=identity, **values)
        def mutated():
            if self.items.get(identity) is room:
                self.changed()
        room.tcp = TCPRecorder(notify, pool=self.tcp_pool, changed=mutated)
        room.udp = UDPRecorder(notify, pool=self.udp_pool, changed=mutated)
        return room

    def lookup(self, identity=None):
        if identity is None:
            return self.capture
        if not isinstance(identity, str) or identity not in self.items:
            raise ValueError("capture session is no longer available")
        return self.items[identity]

    def create(self, activate=True):
        number = self.last_number + 1
        if number > 2147483647:
            raise ValueError("capture session numbering exceeds the native integer contract")
        room = CaptureSession(uuid.uuid4().hex, number)
        # Bound catalog representation before admitting another independent map.
        metadata_size({"sessions": [item.public() for item in self.items.values()] + [room.public()]}, METADATA_BYTES)
        room = self.make_room(room.id, number)
        self.items[room.id] = room
        self.last_number = number
        if activate:
            self.capture = room
        self.changed()
        return room

    def rename(self, room, name):
        validate_name(name)
        previous = room.name
        if previous == name:
            return
        room.name = name
        try:
            metadata_size(self.public(), METADATA_BYTES)
        except Exception:
            room.name = previous
            raise
        self.changed()

    def activate(self, room):
        if self.capture is not room:
            self.capture = room
            self.changed()

    def begin_close(self, room):
        # Preserve at least one recording destination, without moving any live
        # HTTP/raw transaction's already-selected owner.
        if self.capture is room:
            other = next((item for item in reversed(self.items.values()) if item is not room), None)
            self.activate(other or self.create())
        room.closed = True

    def discard(self, room):
        if not room.closed or self.capture is room:
            raise ValueError("Capture session must stop retaining before it closes")
        room.flows.clear()
        room.tcp.clear(); room.udp.clear()
        self.tcp_pool.recorders.remove(room.tcp)
        self.udp_pool.recorders.remove(room.udp)
        del self.items[room.id]
        self.changed()

    def owner(self, flow, room=None):
        previous = self.owners.get(flow)
        if previous is not None:
            if room is not None and previous is not room:
                raise ValueError("A captured request cannot move between capture sessions")
            return previous
        room = room or self.capture
        self.owners[flow] = room
        if uses_live_connection_timing(flow):
            self.index_client_flow(flow)
        # Runtime routing identity is not source HAR evidence. export_flow does
        # not serialize this metadata; workspace stores the owning map explicitly.
        flow.metadata["lens_session_id"] = room.id
        return room

    def index_client_flow(self, flow):
        client = flow.client_conn
        identity = id(client)
        group = self.client_flows.get(identity)
        if group is None or group[0]() is not client:
            # SDK Connection equality compares UUID values. A weak-key map
            # would merge distinct equal-valued clients and could lose the
            # survivor when its original equal key is collected.
            owner = ref(self)
            def collected(reference):
                sessions = owner()
                if sessions is not None:
                    current = sessions.client_flows.get(identity)
                    if current is not None and current[0] is reference:
                        del sessions.client_flows[identity]
            group = (ref(client, collected), WeakSet())
            self.client_flows[identity] = group
        group[1].add(flow)

    def connection_timing_changed(self, client, server=None):
        # The client identity is stable even when the SDK replaces/reuses a
        # flow's upstream connection. Weak membership does not retain evicted
        # records; the owning map, not an equal-looking ID, proves applicability.
        group = self.client_flows.get(id(client))
        if group is None or group[0]() is not client:
            return
        for flow in group[1]:
            room = self.owners.get(flow)
            if (room is not None and room.flows.get(flow.id) is flow and flow.client_conn is client
                    and (server is None or flow.server_conn is server) and uses_live_connection_timing(flow)):
                self.changed()
                return

    def all_flows(self):
        return (flow for room in self.items.values() for flow in room.flows.values())

    def public(self):
        return {"capture_session_id": self.capture.id, "sessions": [room.public() for room in self.items.values()]}

    def has_content(self):
        return (self.last_number != 1 or len(self.items) != 1 or self.capture.id != "default"
                or any(room.name is not None or room.number != 1 or room.flows or room.tcp.streams or room.udp.associations
                       for room in self.items.values()))

    def snapshot(self):
        def freeze(flow):
            copied = snapshot_flow(flow)
            copied.id = flow.id  # SDK copy creates an identity; workspace retains its actual owner.
            return copied
        return self.capture.id, self.last_number, [(room.id, room.number, room.name, [freeze(flow) for flow in room.flows.values()], room.tcp.snapshot(), room.udp.snapshot())
                                 for room in self.items.values()]


def save_workspace(path, snapshot):
    capture, last_number, rooms = snapshot
    budget = ImportBudget(2000, STORE_BYTES)
    catalog = {"format": "lens-workspace", "version": 2, "capture_session_id": capture, "last_number": last_number,
               "sessions": [{"id": identity, "number": number, "name": name, "flow_ids": [flow.id for flow in flows]} for identity, number, name, flows, tcp, udp in rooms]}
    budget.metadata = metadata_size(catalog, METADATA_BYTES)
    with atomic_text(path) as file:
        stream = LimitedWriter(file, label="Lens workspace")
        stream.write('{"format":"lens-workspace","version":2,"last_number":'); json.dump(last_number, stream)
        stream.write(',"capture_session_id":')
        json.dump(capture, stream, ensure_ascii=True)
        stream.write(',"sessions":[')
        for index, (identity, number, name, flows, tcp, udp) in enumerate(rooms):
            if index:
                stream.write(',')
            stream.write('{"id":'); json.dump(identity, stream, ensure_ascii=True)
            stream.write(',"number":'); json.dump(number, stream)
            stream.write(',"name":'); json.dump(name, stream, ensure_ascii=True)
            stream.write(',"flow_ids":'); json.dump([flow.id for flow in flows], stream, ensure_ascii=True)
            header = document_metadata()
            budget.metadata += metadata_size({"log": header}, METADATA_BYTES)
            if budget.metadata > METADATA_BYTES:
                raise ValueError("Lens workspace metadata exceeds the shared budget")
            stream.write(',"har":{"log":{')
            for field_index, (key, value) in enumerate(header.items()):
                if field_index:
                    stream.write(',')
                json.dump(key, stream, ensure_ascii=True); stream.write(':')
                json.dump(value, stream, ensure_ascii=True, allow_nan=False)
            stream.write(',"entries":[')
            for flow_index, flow in enumerate(flows):
                if flow_index:
                    stream.write(',')
                entry = export_flow(flow)
                budget.prepare(entry)
                json.dump(entry, stream, ensure_ascii=True, allow_nan=False)
            stream.write(']}},"tcp":')
            json.dump([{**value, "chunks": [encode_chunk(chunk) for chunk in value["chunks"]]} for value in tcp], stream, ensure_ascii=True, allow_nan=False)
            stream.write(',"udp":')
            json.dump([{**value, "datagrams": [encode_datagram(item) for item in value["datagrams"]]} for value in udp], stream, ensure_ascii=True, allow_nan=False)
            stream.write('}')
        stream.write(']}')
    return {"path": str(path), "sessions": len(rooms), "entries": sum(len(flows) for _, _, _, flows, _, _ in rooms)}


def load_workspace(path, emit=lambda *args, **kwargs: None):
    document = read_document(path, label="Lens workspace", unique_keys=True)
    if (not isinstance(document, dict) or set(document) != ({"format", "version", "capture_session_id", "sessions"} | ({"last_number"} if document.get("version") == 2 else set()))
            or document["format"] != "lens-workspace" or type(document["version"]) is not int or document["version"] not in (1, 2)
            or not isinstance(document["sessions"], list) or not document["sessions"]):
        raise ValueError("Unsupported Lens workspace")
    rooms = document["sessions"]
    version = document["version"]
    catalog = {**document, "sessions": [{key: value for key, value in room.items() if key not in {"har", "tcp", "udp"}}
                                       if isinstance(room, dict) else room for room in rooms]}
    budget = ImportBudget(2000, STORE_BYTES)
    budget.metadata = metadata_size(catalog, METADATA_BYTES)
    prepared = CaptureSessions()
    prepared.tcp_pool.recorders.clear()
    prepared.udp_pool.recorders.clear()
    prepared.items.clear()
    numbers = set()
    for room in rooms:
        if (not isinstance(room, dict) or set(room) != ({"id", "number", "har", "flow_ids", "tcp", "udp"} | ({"name"} if version == 2 else set()))
                or not isinstance(room["id"], str) or not SESSION_ID.fullmatch(room["id"])
                or type(room["number"]) is not int or not 1 <= room["number"] <= 2147483647
                or room["id"] in prepared.items or room["number"] in numbers):
            raise ValueError("Invalid or duplicate Lens workspace session")
        name = room.get("name")
        if name is not None:
            validate_name(name)
        har = room["har"]
        if not isinstance(har, dict) or not isinstance(har.get("log"), dict) or not isinstance(har["log"].get("entries"), list):
            raise ValueError("Lens workspace session must contain a HAR document")
        identities = room["flow_ids"]
        if not isinstance(identities, list) or any(not isinstance(identity, str) for identity in identities) or len(identities) != len(har["log"]["entries"]) or len(set(identities)) != len(identities):
            raise ValueError("Lens workspace flow identities do not match its entries")
        for identity in identities:
            if not isinstance(identity, str):
                raise ValueError("Invalid Lens workspace flow identity")
            try:
                if str(uuid.UUID(identity)) != identity:
                    raise ValueError("Invalid Lens workspace flow identity")
            except (ValueError, AttributeError) as exc:
                raise ValueError("Invalid Lens workspace flow identity") from exc
        budget.metadata += metadata_size({**har, "log": {key: value for key, value in har["log"].items() if key != "entries"}}, METADATA_BYTES)
        if budget.metadata > METADATA_BYTES:
            raise ValueError("Lens workspace metadata exceeds the shared budget")
        target = prepared.make_room(room["id"], room["number"], name)
        tcp = prepare_streams(room["tcp"], budget=prepared.tcp_pool.available(target.tcp))
        tcp_cost = sum(len(chunk["content"]) + CHUNK_OVERHEAD for value in tcp for chunk in value["chunks"])
        prepared.tcp_pool.admit_replacement(target.tcp, len(tcp), tcp_cost)
        target.tcp.replace(tcp)
        udp = prepare_associations(room["udp"], encoded=True, imported=True, budget=prepared.udp_pool.available(target.udp))
        udp_cost = sum(len(item["content"]) + DATAGRAM_OVERHEAD for value in udp for item in value["datagrams"])
        prepared.udp_pool.admit_replacement(target.udp, len(udp), udp_cost)
        target.udp.replace(udp)
        numbers.add(target.number)
        prepared.items[target.id] = target
        for identity, entry in zip(identities, har["log"]["entries"], strict=True):
            facts = budget.prepare(entry)
            flow = import_entry(entry, facts)
            budget.account_encoded(flow, facts)
            flow.id = identity
            if flow.id in target.flows:
                raise ValueError("Duplicate flow identity in an Lens workspace session")
            prepared.owner(flow, target)
            target.flows[flow.id] = flow
    identity = document["capture_session_id"]
    if not isinstance(identity, str) or identity not in prepared.items:
        raise ValueError("Lens workspace capture session is missing")
    last_number = document.get("last_number", max(numbers))
    if type(last_number) is not int or not max(numbers) <= last_number <= 2147483647:
        raise ValueError("Invalid Lens workspace session numbering")
    prepared.last_number = last_number
    prepared.capture = prepared.items[identity]
    prepared.emit = emit
    return prepared
