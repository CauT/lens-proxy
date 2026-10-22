"""Observed public TCP peer facts, independent from HTTP headers and dial routes."""
import copy
from dataclasses import dataclass
import ipaddress
import math
import uuid
from peer_process import import_process

LISTENERS = {"proxy_port", "lan_proxy_port", "socks_port", "reverse_port"}


def address(value):
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError("Client connection address must contain an IP and port")
    host, port = value
    if not isinstance(host, str) or len(host) > 256 or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid client connection IP/port")
    ipaddress.ip_address(host)
    return host, port


def import_client_connection(value):
    if value is None:
        return None
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("Unsupported client connection observation version")
    identity = value.get("id")
    if not isinstance(identity, str) or len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity):
        raise ValueError("Invalid client connection observation identity")
    if not isinstance(value.get("listener"), str) or value["listener"] not in LISTENERS:
        raise ValueError("Unsupported client connection listener")
    address(value.get("peer")); address(value.get("listener_address"))
    accepted = value.get("accepted_at")
    try:
        valid = type(accepted) in (int, float) and math.isfinite(accepted) and accepted >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("Invalid client connection acceptance timestamp")
    if "process" in value:
        import_process(value["process"])
    # Unknown, budget-admitted extension metadata remains source evidence.
    # Never share caller-owned mutable values with the retained capture.
    return copy.deepcopy(value)


@dataclass(frozen=True)
class ClientConnection:
    id: str
    listener: str
    peer: tuple
    listener_address: tuple
    accepted_at: float
    process: dict | None = None

    @classmethod
    def observed(cls, listener, peer, local, accepted_at):
        return cls(uuid.uuid4().hex, listener, address(peer), address(local), accepted_at)

    def public(self):
        result = {"version": 1, "id": self.id, "listener": self.listener, "peer": list(self.peer),
                "listener_address": list(self.listener_address), "accepted_at": self.accepted_at}
        if self.process is not None:
            result["process"] = copy.deepcopy(self.process)
        return result
