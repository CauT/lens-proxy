"""Opt-in host TCP socket ownership. PID reuse/ambiguity never becomes a match."""
import asyncio
import base64
import json
import math
import os
import re
import time

from endpoints import socket_endpoint
from owned_commands import OwnedCommands

LOOKUP_SECONDS = 1.5
COMMAND_BYTES = 256 * 1024
IDENTITY_BYTES = 16 * 1024


def unknown(reason):
    return {"version": 1, "state": "unknown", "scope": "host_tcp_socket", "reason": reason, "observed_at": time.time()}


def endpoint(value):
    text = value.decode("ascii")
    if text.startswith("["):
        host, port = text[1:].split("]:", 1)
    else:
        host, port = text.rsplit(":", 1)
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid socket port")
    return socket_endpoint((host, int(port)))


def socket_records(payload):
    """Parse lsof's NUL fields and record hierarchy, not display columns/lines."""
    records, process, record = [], None, None
    def flush():
        if process and record and record.get("state") == b"ESTABLISHED" and "endpoint" in record:
            records.append({**process, **record})
    for item in payload.split(b"\0"):
        field = item.lstrip(b"\n")  # lsof's separator between NUL field sets
        if not field:
            continue
        kind, value = field[:1], field[1:]
        if kind == b"p":
            flush(); record = None
            process = {"pid": int(value), "name": None} if value.isdigit() and 0 < int(value) < 2**31 else None
        elif kind == b"c" and process is not None:
            process["name"] = value
        elif kind == b"f":
            flush()
            record = {"descriptor": int(value)} if value.isdigit() else None
        elif kind == b"n" and record is not None:
            try:
                left, right = value.split(b"->")
                record["endpoint"] = (endpoint(left), endpoint(right))
            except (ValueError, UnicodeError):
                record.pop("endpoint", None)
        elif kind == b"T" and record is not None and value.startswith(b"ST="):
            record["state"] = value[3:]
    flush()
    return records




class PeerProcesses:
    def __init__(self, helper, lsof="/usr/sbin/lsof"):
        self.helper, self.lsof = str(helper), str(lsof)
        self.commands = OwnedCommands()
        self.slots = asyncio.Semaphore(2)
        self.closed = False

    async def identities(self, pids):
        raw = await self.commands.run([self.helper, *map(str, sorted(pids))], IDENTITY_BYTES)
        value = json.loads(raw)
        if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1 or not isinstance(value.get("results"), list):
            raise ValueError("identity_protocol")
        result = {}
        for item in value["results"]:
            if not isinstance(item, dict) or type(item.get("pid")) is not int or item["pid"] not in pids or item["pid"] in result:
                raise ValueError("identity_protocol")
            identity = item.get("identity")
            if item.get("state") != "readable" or not isinstance(identity, str) or not re.fullmatch(r"[0-9]{1,20}:[0-9]{1,6}", identity):
                raise ValueError("identity_unavailable")
            result[item["pid"]] = identity
        if set(result) != set(pids): raise ValueError("identity_protocol")
        return result

    async def observe(self, source, descriptor):
        try:
            async with asyncio.timeout(LOOKUP_SECONDS):
                async with self.slots:
                    if self.closed: return unknown("lookup_stopped")
                    return await self.lookup(source, descriptor)
        except asyncio.TimeoutError:
            return unknown("lookup_deadline")
        except (ValueError, OSError, UnicodeError) as exc:
            # Fixed error categories, not raw command stderr/ambient details.
            if isinstance(exc, ValueError) and str(exc) == "command_cleanup_pending":
                return unknown("lookup_cleanup_pending")
            return unknown(str(exc) if isinstance(exc, ValueError) and str(exc) in {
                "command_output_limit", "command_failed", "identity_protocol", "identity_unavailable",
                "identity_changed", "lookup_cleanup_pending"} else "lookup_unavailable")

    async def lookup(self, source, descriptor):
        peer, local = socket_endpoint(source.peer), socket_endpoint(source.listener_address)
        arguments = [self.lsof, "-nP", "+c", "0", "-a", f"-iTCP:{peer[1]}", "-sTCP:ESTABLISHED", "-F0pcfnT"]
        first = socket_records(await self.commands.run(arguments, COMMAND_BYTES))
        def matches(records):
            # The accepted listener FD belongs to our still-held socket object.
            if not any(row["pid"] == os.getpid() and row["descriptor"] == descriptor and row["endpoint"] == (local, peer) for row in records):
                return []
            return [row for row in records if row["endpoint"] == (peer, local)]
        candidates = matches(first)
        pids = {row["pid"] for row in candidates}
        if len(pids) != 1:
            return unknown("ambiguous_local_owner" if pids else "no_visible_local_owner")
        before = await self.identities(pids)
        second = matches(socket_records(await self.commands.run(arguments, COMMAND_BYTES)))
        if {row["pid"] for row in second} != pids:
            return unknown("socket_owner_changed")
        observed_at = time.time()
        after = await self.identities(pids)
        if before != after: return unknown("identity_changed")
        names = {row["name"] for row in second}
        if len(names) != 1: return unknown("process_name_ambiguous")
        name = next(iter(names))
        if name is None: return unknown("process_name_unavailable")
        try: text, encoded = name.decode("utf-8", "strict"), None
        except UnicodeError: text, encoded = None, base64.b64encode(name).decode("ascii")
        pid = next(iter(pids))
        return {"version": 1, "state": "identified", "scope": "host_tcp_socket", "reason": None,
                "observed_at": observed_at, "pid": pid, "start_identity": before[pid],
                "name": text, "name_bytes_base64": encoded, "socket_descriptor": min(row["descriptor"] for row in second),
                "method": "lsof+rea-start-identity"}

    async def close(self):
        self.closed = True
        await self.commands.close()


def import_process(value):
    if value is None: return None
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1 or value.get("scope") != "host_tcp_socket":
        raise ValueError("Unsupported peer process observation")
    stamp = value.get("observed_at")
    try: valid = type(stamp) in (int, float) and math.isfinite(stamp) and stamp >= 0
    except OverflowError: valid = False
    if not valid: raise ValueError("Invalid peer process observation time")
    if value.get("state") == "unknown":
        if not isinstance(value.get("reason"), str) or not 1 <= len(value["reason"]) <= 128:
            raise ValueError("Unknown peer process requires a reason")
        if any(value.get(key) is not None for key in ("pid", "start_identity", "name", "name_bytes_base64")):
            raise ValueError("Unknown peer process cannot claim an identity")
    elif value.get("state") == "identified":
        if type(value.get("pid")) is not int or not 0 < value["pid"] < 2**31 or not isinstance(value.get("start_identity"), str) or not re.fullmatch(r"[0-9]{1,20}:[0-9]{1,6}", value["start_identity"]):
            raise ValueError("Invalid peer process identity")
        if value.get("method") != "lsof+rea-start-identity" or value.get("reason") is not None:
            raise ValueError("Invalid peer process evidence method")
        name, encoded = value.get("name"), value.get("name_bytes_base64")
        if name is not None:
            if not isinstance(name, str) or len(name) > 1024 or encoded is not None: raise ValueError("Invalid peer process name")
            name.encode("utf-8", "strict")
        elif not isinstance(encoded, str) or len(encoded) > 1400 or not base64.b64decode(encoded, validate=True):
            raise ValueError("Missing peer process name bytes")
        if type(value.get("socket_descriptor")) is not int or value["socket_descriptor"] < 0:
            raise ValueError("Invalid peer process socket descriptor")
    else: raise ValueError("Unknown peer process state")
    return value
