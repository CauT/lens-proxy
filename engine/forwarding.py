"""Prepare bounded TCP/UDP ranges once, into exact dial/listener endpoints."""
from dataclasses import dataclass

from endpoints import canonical_host


@dataclass(frozen=True)
class ForwardEndpoint:
    listen_port: int
    target_host: str
    target_port: int
    dial_host: str

    def public(self):
        return {"listen_port": self.listen_port, "target_host": self.target_host,
                "target_port": self.target_port, "dial_host": self.dial_host}


def parse_forwards(values, used_ports, transport="TCP"):
    if transport not in ("TCP", "UDP"):
        raise ValueError("Unsupported forwarding transport")
    if not isinstance(values, list) or len(values) > 32:
        raise ValueError(f"{transport} forwarding must be an array of at most 32 endpoints")
    result, occupied = [], set(used_ports)
    for value in values:
        if not isinstance(value, dict):
            raise ValueError(f"{transport} forward must be an object")
        local, remote = value.get("listen_port"), value.get("target_port")
        end = value.get("listen_port_end", local)
        if any(type(port) is not int or not 1 <= port <= 65535 for port in (local, end, remote)):
            raise ValueError(f"{transport} forwarding ports must be integers between 1 and 65535")
        if end < local:
            raise ValueError(f"{transport} forwarding end port must not precede its start port")
        count = end - local + 1
        # Count expansion before allocating endpoints, parsing the hostname or
        # iterating a caller-selected interval. The bound is on actual sockets.
        if count > 32 - len(result):
            raise ValueError(f"{transport} forwarding ranges must total at most 32 listener ports")
        if remote + count - 1 > 65535:
            raise ValueError(f"{transport} forwarding target range exceeds port 65535")
        if any(port in occupied for port in range(local, end + 1)):
            raise ValueError(f"{transport} forwarding listeners must use distinct {transport} ports")
        host = canonical_host(value.get("target_host"))
        for offset, port in enumerate(range(local, end + 1)):
            result.append(ForwardEndpoint(port, value["target_host"], remote + offset, host))
            occupied.add(port)
    return tuple(result)
