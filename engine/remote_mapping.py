"""Compile selected destinations once; map captured request-target bytes directly."""
from dataclasses import dataclass
from urllib.parse import urlsplit

from http_urls import URL_BYTES, HTTPDestination, mapping_path_prefix, prepare_url, prepare_destination
from bounds import text_size
from endpoints import canonical_host


@dataclass(frozen=True)
class RemoteMapping:
    scheme: str | None
    host: str | None
    port: int | None
    authority: str | None
    path: bytes
    query: bytes | None
    prefix: bytes | None
    mode: str
    partial: bool = False

    @classmethod
    def prepare(cls, value, pattern, mode="append"):
        if mode not in ("append", "relative"):
            raise ValueError("Map Remote path_mode must be append or relative")
        prepared = prepare_url(value)
        target = urlsplit(prepared.value)
        return cls(target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80),
                   prepared.authority, target.path.encode("ascii"),
                   target.query.encode("ascii") if "?" in prepared.source else None,
                   mapping_path_prefix(pattern).encode("utf-8", "surrogateescape") if mode == "relative" else None,
                   mode)

    @classmethod
    def prepare_parts(cls, value, pattern, mode="append"):
        if mode not in ("append", "relative"):
            raise ValueError("Map Remote path_mode must be append or relative")
        if not isinstance(value, dict) or set(value) - {"scheme", "host", "port", "path", "query", "query_mode"}:
            raise ValueError("Map Remote destination must contain supported individual fields")
        fields = {}
        for name in ("scheme", "host", "path", "query", "query_mode"):
            field = value.get(name, "preserve" if name == "query_mode" else "")
            text_size(field, URL_BYTES, "Map Remote " + name)
            fields[name] = field
        scheme, host = fields["scheme"], fields["host"]
        if scheme and scheme not in ("http", "https"):
            raise ValueError("Map Remote protocol must be blank, http or https")
        host = canonical_host(host) if host else None
        port = value.get("port", "")
        if port == "":
            port = None
        elif isinstance(port, str) and 1 <= len(port) <= 5 and port.isascii() and port.isdecimal():
            port = int(port)
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("Map Remote port must be blank or an integer from 1 through 65535")
        path, query_mode = fields["path"], fields["query_mode"]
        if path and (not path.startswith("/") or "?" in path):
            raise ValueError("Map Remote path must begin with / and use the separate query field")
        if query_mode not in ("preserve", "replace"):
            raise ValueError("Map Remote query_mode must be preserve or replace")
        query = fields["query"] if query_mode == "replace" else None
        # Reuse HTTP URL admission for URI path/query characters. This fixed
        # placeholder is never a dial target; host inputs have their own owner.
        target = prepare_url("http://mapping.invalid" + path + ("?" + query if query is not None else ""))
        parsed = urlsplit(target.value)
        return cls(scheme or None, host, port, None, parsed.path.encode("ascii"),
                   parsed.query.encode("ascii") if query is not None else None,
                   mapping_path_prefix(pattern).encode("utf-8", "surrogateescape") if mode == "relative" else None,
                   mode, True)

    def apply(self, request):
        destination = None
        if self.partial:
            if any(value is not None for value in (self.scheme, self.host, self.port)):
                destination = prepare_destination(self.scheme or request.scheme, self.host or request.host,
                    self.port if self.port is not None else request.port)
        else:
            destination = HTTPDestination(self.scheme, self.host, self.port, self.authority)
        original = request.data.path
        if original == b"*":
            # An asterisk denotes the server, not a file or directory.
            mapped = original
        else:
            path, marker, query = original.partition(b"?")
            suffix = b"?" + self.query if self.query is not None else marker + query
            if self.mode == "append":
                mapped_path = self.path.rstrip(b"/") + path
            elif not self.path:
                mapped_path = path
            elif self.path.endswith(b"/"):
                if not path.startswith(self.prefix):
                    raise ValueError("Map Remote current path no longer has the selected source directory")
                mapped_path = self.path + path[len(self.prefix):]
            else:
                mapped_path = self.path
            if len(mapped_path) + len(suffix) > URL_BYTES:
                raise ValueError("Map Remote request target exceeds 64 KiB")
            mapped = mapped_path + suffix
        # Setters own SDK destination facts. Explicit authority repairs the pinned
        # SDK's unbracketed IPv6 rendering for both HTTP Host and H2 :authority.
        if destination is not None:
            request.scheme, request.host, request.port = destination.scheme, destination.host, destination.port
            request.host_header = destination.authority
        request.data.path = mapped
