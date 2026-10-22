#!/usr/bin/env python3
"""Lens loopback proxy. stdout is the JSONL control transport; stderr is logging."""
import argparse
import base64
import asyncio
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
import fnmatch
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import sys
import time
import public_bootstrap
from types import MappingProxyType, SimpleNamespace
import uuid
from weakref import WeakKeyDictionary, WeakSet
from urllib.parse import urlsplit

# Lens has no implicit TLS-secret logging capability. Inherited development
# variables must not turn private session secrets into files.
for _keylog_variable in ("SSLKEYLOGFILE", "MITMPROXY_SSLKEYLOGFILE"):
    os.environ.pop(_keylog_variable, None)

from mitmproxy import http, options, version
from mitmproxy.tools.dump import DumpMaster
from har import export_flow, snapshot_flow, displayed_request_url, request_target_source
from har_metadata import flow_duration, flow_state, document_metadata
from network import ProxyRelays, network_settings, LANAccess
from sdk_connections import SDKConnections, listener_servers
from routing import install_routing_layer
from upstream_proxy import HTTPUpstreamProxy, require_http_only
from persistence import selected_path, prepare_import, save_snapshot, load_snapshot, cleanup_pending_stages
from sessions import CaptureSessions, save_workspace, load_workspace
from workspace_revision import WorkspaceRevision
from local_mapping import local_response, local_url, selected_local_path
from client_certificates import ClientCertificates, UpstreamTrust
from certificate_inputs import CertificateInputs
from forwarding import parse_forwards
from tcp_capture import CHUNK_OVERHEAD, save_streams, load_streams
from udp_capture import DATAGRAM_OVERHEAD, save_associations, load_associations
from udp_forwarding import UDPRelays
from access_policy import parse_access_policy
from breakpoint_edit import prepare_edit
from http_urls import request_url, prepare_url
from remote_mapping import RemoteMapping
from http_method import normalize_response, request_method
from outgoing_transport import send_via_proxy
from outgoing import RequestSnapshot, prepare_compose, snapshot_request, operation_facts, PendingRequest, RequestTokens, REPLAY_HEADER, request_fingerprint, validate_source_fingerprint
from bounds import message_content, BODY_BYTES, STORE_BYTES, metadata_size, METADATA_BYTES
import websocket_capture
from rewrite_sets import expand_rules
from rewrite import REWRITE_KINDS, RewriteAction, prepare as prepare_rewrite, parse_error as parse_rewrite_error
from http_headers import headers_base64
from native_json import encode_native_message
from mitmproxy.proxy.mode_specs import ProxyMode

BODY_DISPLAY_LIMIT = 2 * 1024 * 1024
BODY_LIMIT = BODY_BYTES
MAX_FLOWS = 2000
MAX_STORED_BYTES = STORE_BYTES
RULE_KINDS = {"map_remote", "map_local", "block", "breakpoint_request",
              "breakpoint_response", "delay", "no_cache", "block_cookies", "dns_spoof"} | REWRITE_KINDS
RESPONSE_RULE_KINDS = {"rewrite_response_header", "rewrite_response_body", "rewrite_response_status", "breakpoint_response"}
TWO_SIDED_RULE_KINDS = {"no_cache", "block_cookies"}
DEFAULT_BREAKPOINT_TIMEOUT_SECONDS = 60
MAX_BREAKPOINT_TIMEOUT_SECONDS = 3600
NATIVE_JSON = False


def emit(event, **values):
    message = {"event": event, **values}
    encoded = encode_native_message(message) if NATIVE_JSON else json.dumps(message, ensure_ascii=True, allow_nan=False)
    print(encoded, flush=True)


def body_available(message):
    return message is not None and message.raw_content is not None


def body_text(message):
    if not message:
        return "", False
    raw = message_content(message)
    return raw[:BODY_DISPLAY_LIMIT].decode("utf-8", "replace"), len(raw) > BODY_DISPLAY_LIMIT


def summary(flow):
    req, res = flow.request, flow.response
    optional = {name: flow.metadata[key] for name, key in (("pause_id", "lens_pause_id"), ("breakpoint_url", "lens_breakpoint_url"), ("request_operation", "lens_request_operation")) if key in flow.metadata}
    return {"id": flow.id, "session_id": flow.metadata.get("lens_session_id"), "url": displayed_request_url(flow), "host": req.host, "path": req.path,
            "routed_url": request_url(req), "request_target_source": request_target_source(flow),
            "original_url": flow.metadata.get("lens_original_url"),
            "effective_url": request_url(req, pretty=True), "dns_address": flow.metadata.get("lens_dns_address"),
            "client_connection": flow.metadata.get("lens_client_connection"),
            "access_decision": flow.metadata.get("lens_access_decision"),
            "dns_dial_address": flow.metadata.get("lens_dns_dial_address"),
            "method": request_method(req), "status": res.status_code if res else None,
            "scheme": req.scheme, "http_version": req.http_version, "started": req.timestamp_start,
            "duration_ms": flow_duration(flow),
            "request_size": len(req.raw_content or b""), "response_size": len(res.raw_content or b"") if res else 0,
            "request_body_available": body_available(req), "response_body_available": body_available(res),
            "state": flow_state(flow),
            "content_type": res.headers.get("content-type", "") if res else "",
            "error": flow.metadata.get("lens_rewrite_error") or flow.metadata.get("lens_breakpoint_error") or (flow.error.msg if flow.error else None),
            "pause_stage": flow.metadata.get("lens_pause_stage"),
            "pause_deadline": flow.metadata.get("lens_pause_deadline"),
            "pause_timeout_seconds": flow.metadata.get("lens_pause_timeout_seconds"),
            "is_websocket": flow.websocket is not None,
            "replayed": flow.metadata.get("lens_replayed", False),
            "imported": flow.metadata.get("imported", False),
            "websocket_messages_truncated": websocket_capture.retention_truncated(flow), **optional}


def binary_detail(message):
    if not body_available(message):
        return None, False
    raw = message_content(message)
    try:
        raw.decode("utf-8", "strict")
        binary = False
    except UnicodeDecodeError:
        binary = True
    return base64.b64encode(raw[:BODY_DISPLAY_LIMIT]).decode(), binary


def request_wire_detail(request):
    # These are current SDK-owned facts, not a reconstruction of the original
    # request line. The SDK normalizes HTTP/1 target form before request hooks.
    try:
        routed_url = request_url(request, pretty=False).encode("utf-8", "surrogateescape")
        encoded_url, unavailable = base64.b64encode(routed_url).decode("ascii"), None
    except (UnicodeError, ValueError) as exc:
        encoded_url = None
        unavailable = f"Routed request URL bytes are unavailable: {exc}"
    return {"request_method_base64": base64.b64encode(request.data.method).decode("ascii"),
            "request_target_base64": base64.b64encode(request.data.path).decode("ascii"),
            "request_url_base64": encoded_url, "request_url_unavailable_reason": unavailable,
            "request_port": request.port,
            "request_target_form": "asterisk" if request.data.path == b"*" else request.first_line_format}


def detail(flow):
    req_body, req_cut = body_text(flow.request)
    res_body, res_cut = body_text(flow.response)
    req_base64, req_binary = binary_detail(flow.request)
    res_base64, res_binary = binary_detail(flow.response)
    return {**summary(flow), **request_wire_detail(flow.request), "request_fingerprint": request_fingerprint(flow.request), "response_reason": flow.response.reason if flow.response else None,
            "request_headers_base64": headers_base64(flow.request.headers),
            "response_headers_base64": headers_base64(flow.response.headers) if flow.response else [],
            "response_reason_base64": base64.b64encode(flow.response.data.reason).decode("ascii") if flow.response else None,
            "request_headers": list(flow.request.headers.items(multi=True)),
            "response_headers": list(flow.response.headers.items(multi=True)) if flow.response else [],
            "request_body": req_body, "response_body": res_body,
            "request_body_base64": req_base64, "response_body_base64": res_base64,
            "request_binary": req_binary, "response_binary": res_binary,
            "request_truncated": req_cut, "response_truncated": res_cut,
            **websocket_capture.detail_fields(flow)}


def abort_paused(flow):
    # mitmproxy.kill clears intercepted without waking wait_for_resume. Resume first
    # and kill synchronously, before the waiting hook can be scheduled again.
    flow.resume()
    flow.kill()


def internal_tcp_address(instance, name):
    # 12.2.1 reverse:https owns TCP and UDP sockets, so listen_addrs flattens
    # two transports (often the same numeric address). Relays must select the
    # actual TCP owner, never infer transport from address count or ordering.
    servers = listener_servers(instance)
    if any(server.getsockname()[0] != "127.0.0.1" for server in servers.udp):
        raise RuntimeError(f"Internal UDP listener must remain on loopback for {name}")
    sockets = [sock for server in servers.tcp for sock in (server.sockets or ())]
    if len(sockets) != 1 or sockets[0].family != socket.AF_INET:
        raise RuntimeError(f"No verified loopback TCP listener for {name}")
    address = sockets[0].getsockname()
    if address[0] != "127.0.0.1" or not address[1]:
        raise RuntimeError(f"No verified loopback TCP listener for {name}")
    return address


def ssl_ignore_pattern(hosts):
    if hosts.strip() == "*":
        return []
    patterns = [h.strip() for h in hosts.split(",") if h.strip()]
    if not patterns:
        return [".*"]
    # mitmproxy tests ignore_hosts against host:port. Do not let :port become part of glob *.
    expressions = [fnmatch.translate(h).removeprefix("(?s:").removesuffix(")\\Z").removesuffix(")\\z") for h in patterns]
    return [r"^(?!(?:" + "|".join(expressions) + r"):\d+$).*"]


@dataclass(frozen=True)
class PreparedRule:
    parameters: Mapping[str, object]
    remote: RemoteMapping | None = None
    rewrite: RewriteAction | None = None
    scope: object = None

    def matches(self, url, scopes):
        if self.scope is not None:
            identity = id(self.scope)
            if identity not in scopes:
                scopes[identity] = self.scope.matches(url)
            if not scopes[identity]:
                return False
        return fnmatch.fnmatchcase(url, self.parameters['match'])

    @property
    def enabled(self):
        return self.parameters.get('enabled', True) and (self.scope is None or self.scope.enabled)


@dataclass(frozen=True, eq=False)
class RulePlan:
    snapshot: tuple
    snapshot_bytes: int
    request_rules: tuple
    two_sided_indices: frozenset

    @classmethod
    def select(cls, snapshot, snapshot_bytes, original_url):
        request_rules, two_sided, scopes = [], set(), {}
        for index, action in enumerate(snapshot):
            rule = action.parameters
            if not action.enabled or rule["kind"] in RESPONSE_RULE_KINDS:
                continue
            match_url = local_url(original_url) if rule["kind"] == "map_local" else original_url
            if action.matches(match_url, scopes):
                request_rules.append(action)
                if rule["kind"] in TWO_SIDED_RULE_KINDS:
                    two_sided.add(index)
        return cls(snapshot, snapshot_bytes, tuple(request_rules), frozenset(two_sided))

    def response_rules(self, effective_url):
        # Merge by the one original order, without re-matching two-sided tools
        # or changing response-only rules' effective-destination semantics.
        scopes = {}
        return tuple(action for index, action in enumerate(self.snapshot)
            if index in self.two_sided_indices or (action.parameters["kind"] in RESPONSE_RULE_KINDS
                and action.enabled and action.matches(effective_url, scopes)))


@dataclass
class RepeatJob:
    id: str
    total: int
    concurrency: int
    interval_ms: int
    request: RequestSnapshot | None
    source_id: str
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    state: str = "running"
    cursor: int = 0
    task: asyncio.Task | None = None
    children: set = field(default_factory=set)
    finalized: bool = False
    session: object = None

    def event(self):
        return {"job_id": self.id, "session_id": self.session.id if self.session else None, "source_id": self.source_id, "total": self.total, "completed": self.completed,
                "failed": self.failed, "cancelled": self.cancelled, "state": self.state}

    def finish(self):
        if self.finalized:
            return
        self.finalized = True
        self.cancelled = self.total - self.completed - self.failed
        self.state = "cancelled" if self.cancelled else "completed"
        self.request = None
        emit("repeat_done", **self.event())


class Lens:
    def __init__(self, master, data_dir, port, socks_port=0, reverse_port=0, reverse_url=None, lan=None, upstream_proxy=None):
        self.master, self.data_dir, self.port = master, data_dir, port
        self.finished = asyncio.Event()
        self.workspace_revision = WorkspaceRevision(emit)
        self.sessions = CaptureSessions(self.emit_capture, changed=self.workspace_revision.changed)
        self.workspace_base_revision = None
        self.workspace_base_has_content = False
        self.recording = True
        self.rules = ()
        self.rules_metadata_bytes = 0
        self.rule_plans = WeakKeyDictionary()
        self.active_rule_plans = WeakSet()
        self.access_policy = parse_access_policy()
        self.tasks = set()
        self.pending_requests = {}
        self.prepared_capture = WeakKeyDictionary()
        self.request_tokens = RequestTokens()
        self.repeat_jobs = OrderedDict()
        self.closed = False
        self.capture_stopped = False
        self.semaphore = asyncio.Semaphore(4)
        # One bounded pattern worker; input snapshot/Unicode/output copies can
        # together occupy up to the shared 256 MiB body allowance. Waiting
        # requests acquire this slot before making any additional body copies.
        self.rewrite_worker = asyncio.Semaphore(max(1, STORE_BYTES // (BODY_BYTES * 8)))
        self.stdin_transport = None
        self.command_reader = None
        self.client_certificates = ClientCertificates()
        self.certificate_inputs = CertificateInputs()
        self.pending_startup_command = None
        self.upstream_trust = None
        self.network = ProxyRelays()
        self.sdk_connections = SDKConnections(self.network)
        self.tcp_forwards = ()
        self.initial_tcp = None
        self.udp_forwards = ()
        self.udp_network = UDPRelays(self.network.upload, self.network.download)
        self.initial_udp = None
        self.inspect_only = False
        self.initial_workspace = None
        self.file_tasks = set()
        self.startup_error = None
        self.socks_port, self.reverse_port, self.reverse_url = socks_port, reverse_port, reverse_url
        self.lan = lan
        self.upstream_proxy = upstream_proxy

    @property
    def flows(self):
        return self.sessions.capture.flows

    @property
    def tcp(self):
        return self.sessions.capture.tcp

    @property
    def udp(self):
        return self.sessions.capture.udp

    def request_shutdown(self):
        if self.master is not None:
            self.master.shutdown()
        self.finished.set()

    def proxy_server(self):
        return self.master.addons.get("proxyserver") if self.master is not None else None

    async def server_connect(self, data):
        self.sessions.connection_timing_changed(data.client, data.server)
        # The mitmproxy guard covers its internal sockets; the owned public relay
        # endpoints are additional routes back into this same engine.
        own_hosts = {"localhost", "127.0.0.1"} | ({self.lan.address} if self.lan else set())
        if data.server.address and data.server.address[0] in own_hosts:
            port = data.server.address[1]
            if any(sock.getsockname()[1] == port for server in self.network.servers.values()
                   for sock in (server.sockets or [])):
                data.server.error = "Lens cannot proxy a request back into its own public listeners"
        if not data.server.error:
            await self.sdk_connections.server_connect(data, self.network.settings["connect_timeout_seconds"])

    def server_connect_error(self, data):
        self.sessions.connection_timing_changed(data.client, data.server)
        self.sdk_connections.server_connect_error(data)

    def next_layer(self, data):
        install_routing_layer(data)

    def client_connected(self, client):
        self.sdk_connections.client_connected(self.proxy_server(), client)
        self.network.observe_client(client.id, client.peername, client.sockname)

    async def client_disconnected(self, client):
        self.sessions.connection_timing_changed(client)
        self.network.forget_client(client.id)
        await self.sdk_connections.disconnected(client)

    def server_connected(self, data):
        self.sessions.connection_timing_changed(data.client, data.server)
        self.sdk_connections.server_connected(data, self.proxy_server())

    async def server_disconnected(self, data):
        self.sessions.connection_timing_changed(data.client, data.server)
        await self.sdk_connections.disconnected(data.client, data.server)

    def tls_start_server(self, data):
        try:
            self.client_certificates.apply(data, self.master.options)
        except Exception:
            # Hook failures must not continue with the original context and
            # silently omit an identity the caller explicitly selected.
            data.ssl_conn = None
            raise

    def tls_established_client(self, data):
        self.sessions.connection_timing_changed(data.context.client)

    def tls_established_server(self, data):
        self.sessions.connection_timing_changed(data.context.client, data.conn)

    def tls_start_client(self, data):
        # Pinned mitmproxy 12.2.1 TlsConfig has already created this per-connection
        # SSL object. Its ALPN callback otherwise follows client offer order when
        # lazy mode has no upstream result (generated requests use HTTP/1.1).
        # Prefer supported h2 independently on this leg, preserving any explicit
        # choice, upstream negotiation, HTTP/1-only clients, and TLS verification.
        if data.is_dtls:
            return
        policy = data.ssl_conn.get_app_data() if data.ssl_conn else None
        # This adapter intentionally binds the internal AppData shape of 12.2.1.
        # Refuse the handshake on drift instead of silently reporting HTTP/2 support.
        valid_policy = (isinstance(policy, dict) and {"http2", "client_alpn", "server_alpn"} <= policy.keys()
                        and isinstance(policy["http2"], bool)
                        and all(policy[k] is None or isinstance(policy[k], bytes)
                                for k in ("client_alpn", "server_alpn")))
        if not valid_policy:
            data.ssl_conn = None  # mitmproxy closes TLS when the hook supplies no context
            raise RuntimeError("Lens ALPN adapter requires mitmproxy 12.2.1 TlsConfig AppData")
        if (policy["http2"] and policy.get("client_alpn") is None
                and policy.get("server_alpn") is None and b"h2" in data.conn.alpn_offers):
            data.ssl_conn.set_app_data({**policy, "client_alpn": b"h2"})

    async def running(self):
        self.prepare_workspace_baseline()
        if self.inspect_only:
            stopped_command, stopped_value = self.pending_startup_command, None
            if stopped_command is not None:
                # Complete the real Stop cleanup before claiming stopped Ready.
                # TLS work may have completed just as the command arrived.
                stopped_value = await self.command(stopped_command)
                self.pending_startup_command = None
            self.capture_stopped = True
            self.emit_ready(**self.sessions.public(), capture_stopped=True, tcp_forwards=[], udp_forwards=[], ca_cert="", ca_sha256="", client_certificates=[])
            self.publish_sessions()
            if stopped_command is not None:
                emit("result", command_id=stopped_command["command_id"], value=stopped_value)
            self.spawn(self.read_commands())
            return
        # The pinned proxy server supports port 0 and exposes actual listen_addrs.
        # Its option validator rejects multiple specs on :0 as duplicates, so add
        # optional ephemeral modes through the same owned Servers manager directly.
        proxy = self.proxy_server()
        specs = [ProxyMode.parse(self.upstream_proxy.mode if self.upstream_proxy else "regular@127.0.0.1:0")]
        modes = [("proxy_port", self.port, specs[0])]
        if self.socks_port:
            spec = ProxyMode.parse("socks5@127.0.0.1:0")
            specs.append(spec)
            modes.append(("socks_port", self.socks_port, spec))
        if self.reverse_port:
            spec = ProxyMode.parse(f"reverse:{self.reverse_url}@127.0.0.1:0")
            specs.append(spec)
            modes.append(("reverse_port", self.reverse_port, spec))
        try:
            if not await proxy.servers.update(specs):
                raise RuntimeError("Unable to start all internal proxy listeners")
            listeners = []
            for name, port, spec in modes:
                listeners.append((name, port, internal_tcp_address(proxy.servers[spec], name)))
            public_ports = await self.network.start(listeners, lan=self.lan, forwards=self.tcp_forwards,
                observe=lambda forward: self.tcp.begin(forward) if self.recording else None)
            blocked_udp = [server.getsockname() for instance in proxy.servers
                           for server in listener_servers(instance).udp]
            await self.udp_network.start(self.udp_forwards,
                observe=lambda forward, client, local: self.udp.begin(forward, client, local) if self.recording else None,
                blocked_addresses=blocked_udp)
            self.port = public_ports["proxy_port"]
            certificate = self.data_dir / "mitmproxy-ca-cert.pem"
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            fingerprint = x509.load_pem_x509_certificate(certificate.read_bytes()).fingerprint(hashes.SHA256()).hex()
            public_ports = {name: port for name, port in public_ports.items() if not name.startswith("tcp_")}
            self.emit_ready(**self.sessions.public(), **public_ports, ca_cert=str(certificate), ca_sha256=fingerprint,
                 tcp_forwards=[forward.public() for forward in self.tcp_forwards],
                 udp_forwards=[forward.public() for forward in self.udp_forwards],
                 client_certificates=self.client_certificates.public(),
                 client_process=self.network.peer_processes is not None,
                 upstream_ca=self.upstream_trust.source if self.upstream_trust else None,
                 http_upstream_proxy=self.upstream_proxy.url if self.upstream_proxy else "",
                 lan_address=self.lan.address if self.lan else None)
            self.publish_sessions()
            self.spawn(self.read_commands())
        except Exception as exc:
            self.startup_error = str(exc)
            emit("fatal", message=str(exc))
            try:
                await self.close_networks()
            finally:
                self.request_shutdown()

    async def close_networks(self):
        # Both admission owners must stop even when one cleanup needs retry.
        results = await asyncio.gather(self.network.close(), self.udp_network.close(), return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result

    async def quiesce_network_work(self):
        # Close admissions/relays first so tasks cannot strand a proxy socket.
        # Their finalizers can register additional failed outgoing closes: join
        # all children, then recheck the network cleanup owner before success.
        self.sdk_connections.closed = True
        await asyncio.gather(self.close_networks(), self.sdk_connections.close(self.proxy_server()), return_exceptions=True)
        current = asyncio.current_task()
        pending = [task for task in self.tasks if task is not current]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        results = await asyncio.gather(self.close_networks(), self.sdk_connections.close(self.proxy_server()), return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def announce_sessions(self, viewed):
        value = {**self.sessions.public(), "view_session_id": viewed.id, "recording": self.recording}
        self.emit_capture("session_catalog", **value)
        return value

    def emit_capture(self, event, **values):
        # Keep the visible mutation and document status in one frame. A separate
        # coalesced state event is needed only when raw summaries are throttled.
        if self.workspace_revision.enabled:
            values["workspace_revision"] = self.workspace_revision.published_frame()
        emit(event, **values)

    def use_workspace(self, prepared):
        self.sessions = prepared
        # Raw callbacks dereference their session owner's current callback;
        # importing a prepared workspace must not strand an old revision owner.
        self.sessions.changed = self.workspace_revision.changed

    def prepare_workspace_baseline(self):
        if self.workspace_base_revision is not None:
            return
        notify = self.sessions.emit
        self.sessions.emit = lambda *args, **kwargs: None
        try:
            if self.initial_tcp is not None:
                self.tcp.replace(self.initial_tcp)
            if self.initial_udp is not None:
                self.udp.replace(self.initial_udp)
        finally:
            self.sessions.emit = notify
        self.workspace_base_revision = self.workspace_revision.current()
        self.workspace_base_has_content = bool(self.sessions.has_content())

    def emit_ready(self, **fields):
        self.workspace_revision.enable()
        emit("ready", **fields, workspace_revision=self.workspace_revision.current(),
             workspace_base_revision=self.workspace_base_revision,
             workspace_base_has_content=self.workspace_base_has_content)

    def publish_sessions(self):
        for room in self.sessions.items.values():
            for stream in room.tcp.streams.values():
                room.tcp.emit("tcp_stream", stream=stream.summary())
            for association in room.udp.associations.values():
                room.udp.emit("udp_association", association=association.summary())
            for flow in room.flows.values():
                self.emit_capture("flow", flow=summary(flow))

    def remember(self, flow):
        room = self.sessions.owner(flow)
        if room.closed or (flow.id not in room.flows and not flow.metadata.get("lens_capture", self.recording)):
            return
        room.flows[flow.id] = flow
        self.workspace_revision.changed()
        self.trim()
        if flow.id in room.flows:
            self.emit_capture("flow", flow=summary(flow))

    def trim(self):
        def cost(f):
            return len(f.request.raw_content or b"") + (len(f.response.raw_content or b"") if f.response else 0) + (
                sum(len(m.content) for m in f.websocket.messages) if f.websocket else 0) + f.metadata.get("lens_har_metadata_bytes", 0)
        entries = [(room, identifier, flow) for room in self.sessions.items.values() for identifier, flow in room.flows.items()]
        total, count = sum(cost(flow) for _, _, flow in entries), len(entries)
        # Global budgets span all sessions. An old session cannot hide retained
        # bodies from the application budget; paused owners remain addressable.
        for room, identifier, flow in entries:
            if count <= MAX_FLOWS and total <= MAX_STORED_BYTES:
                break
            if not flow.intercepted:
                total -= cost(flow); count -= 1
                del room.flows[identifier]
                self.workspace_revision.changed()
                flow.metadata["lens_capture"] = False
                self.emit_capture("removed", id=identifier, session_id=room.id)

    def requestheaders(self, flow):
        admitted = self.prepare_capture(flow)
        source = self.network.client_source(flow.client_conn.id)
        if source is not None:
            previous = {"lens_client_connection": flow.metadata["lens_client_connection"]} if "lens_client_connection" in flow.metadata else {}
            old_cost = metadata_size(previous, METADATA_BYTES) if previous else 0
            source_cost = metadata_size({"lens_client_connection": source}, METADATA_BYTES)
            flow.metadata["lens_client_connection"] = source
            flow.metadata["lens_har_metadata_bytes"] = max(0, flow.metadata.get("lens_har_metadata_bytes", 0) - old_cost) + source_cost

        if admitted:
            self.remember(flow)

    def prepare_capture(self, flow):
        if flow in self.prepared_capture:
            return self.prepared_capture[flow]
        self.prepared_capture[flow] = False
        flow.metadata["lens_capture"] = self.recording
        # Authentication proves ownership even after cancellation releases the
        # pending entry. Never reinterpret a late owned request as external, or
        # strip an unrelated caller's same-named header merely by its spelling.
        fields = flow.request.headers.fields
        owned = [value for name, value in fields
                 if name.lower() == REPLAY_HEADER.lower() and self.request_tokens.owns(value)]
        if owned:
            owned_values = set(owned)
            flow.request.headers.fields = tuple((name, value) for name, value in fields
                if not (name.lower() == REPLAY_HEADER.lower() and value in owned_values))
            flow.metadata["lens_replayed"] = True
            pending = self.pending_requests.get(owned[0].decode('ascii')) if len(owned) == 1 else None
            if pending is None or pending.flow is not None:
                abort_paused(flow)
                self.remember(flow)
                return False
            self.sessions.owner(flow, pending.session)
            pending.flow = flow
            flow.metadata["lens_request_operation"] = dict(pending.facts)
            flow.metadata["lens_har_metadata_bytes"] = flow.metadata.get("lens_har_metadata_bytes", 0) + metadata_size({"lens_request_operation": pending.facts}, METADATA_BYTES)
        if self.sessions.owner(flow).closed:
            abort_paused(flow)
            return False
        self.prepared_capture[flow] = True
        return True

    async def request(self, flow):
        if not self.prepare_capture(flow):
            return
        flow.metadata["lens_original_url"] = request_url(flow.request, pretty=True)
        # Freeze one configuration/order. Two-sided tools select their original
        # client scope once; response-only rules still select the effective URL.
        # Executable plans never enter capture metadata or HAR.
        original_url = flow.metadata["lens_original_url"]
        plan = RulePlan.select(self.rules, self.rules_metadata_bytes, original_url)
        self.rule_plans[flow] = plan
        self.active_rule_plans.add(plan)
        try:
            self.remember(flow)
            if flow.request.host == "lens.invalid" and flow.request.port == 80:
                flow.metadata["lens_certificate_bootstrap"] = True
                flow.response = public_bootstrap.response(flow.request.path, self.data_dir / "mitmproxy-ca-cert.pem")
                return
            # One immutable policy owns this request, including time spent paused.
            # Updating settings affects subsequent requests, never half a decision.
            policy = self.access_policy
            if not self.deny_access(flow, policy):
                await self.apply(flow, "request", rules=plan.request_rules, access_policy=policy)
                if not flow.error:
                    self.deny_access(flow, policy)
            self.remember(flow)
        except asyncio.CancelledError:
            # A cancelled SDK hook need not receive a later response/error hook.
            self.rule_plans.pop(flow, None)
            raise
        if flow.error:
            self.rule_plans.pop(flow, None)


    async def response(self, flow):
        # The response coroutine now owns its plan, including response pauses.
        # Completed retained rows must not keep obsolete rule generations alive.
        plan = self.rule_plans.pop(flow, None)
        rules = plan.response_rules(request_url(flow.request, pretty=True)) if plan is not None else ()
        if not flow.metadata.get("lens_certificate_bootstrap") and not flow.metadata.get("lens_access_decision"):
            await self.apply(flow, "response", rules=rules)
        if flow.error:
            self.remember(flow)
            return
        # Response presence alone is insufficient: Map Local creates one in
        # request(), and resume() can publish between multiple response rules.
        # Only the response-hook owner can declare the final rewritten body.
        try:
            normalize_response(flow)
        except ValueError as exc:
            # SDK addon exceptions are logged and swallowed. Fail at the flow
            # owner so invalid framing cannot escape as a completed response.
            flow.metadata["lens_breakpoint_error"] = f"Edited-method response framing failed: {exc}"
            abort_paused(flow)
            self.remember(flow)
            return
        flow.metadata["lens_response_complete"] = True
        self.remember(flow)

    def error(self, flow):
        self.rule_plans.pop(flow, None)
        self.remember(flow)

    def websocket_message(self, flow):
        websocket_capture.retain(flow)
        self.remember(flow)

    def websocket_end(self, flow):
        self.remember(flow)

    def deny_access(self, flow, policy):
        if flow.metadata.get("lens_access_decision"):
            return True
        decision = policy.deny(flow.metadata["lens_original_url"], request_url(flow.request, pretty=True))
        if decision is None:
            return False
        flow.metadata["lens_access_decision"] = decision
        flow.metadata["lens_har_metadata_bytes"] = flow.metadata.get("lens_har_metadata_bytes", 0) + metadata_size(
            {"lens_access_decision": decision}, METADATA_BYTES)
        if decision["action"] == "close":
            flow.kill()
        else:
            # Access denial is terminal: later mappings/rewrites and response
            # rules must not convert it into an allowed request or success page.
            flow.response = http.Response.make(403, b"Blocked by Lens access list", {
                "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"})
        return True

    async def apply(self, flow, stage, *, rules, access_policy=None):
        original_url = request_url(flow.request, pretty=True)
        for action in rules:
            rule = action.parameters
            kind, name, value = rule["kind"], rule.get("name", ""), rule.get("value", "")
            message = flow.request if stage == "request" else flow.response
            if kind == "no_cache" and message:
                if stage == "request":
                    message.headers.pop("If-Modified-Since", None)
                    message.headers.pop("If-None-Match", None)
                    message.headers["Pragma"] = "no-cache"
                    message.headers["Cache-Control"] = "no-cache"
                else:
                    message.headers.pop("ETag", None)
                    message.headers.pop("Last-Modified", None)
                    message.headers["Expires"] = "0"
                    message.headers["Cache-Control"] = "no-store"
            elif kind == "block_cookies" and message:
                message.headers.pop("Cookie" if stage == "request" else "Set-Cookie", None)
            elif action.rewrite is not None and message:
                try:
                    if getattr(action.rewrite, 'threaded', False):
                        async with self.rewrite_worker:
                            if flow.error or self.capture_stopped:
                                return
                            frozen = SimpleNamespace(request=flow.request.copy(),
                                response=flow.response.copy() if flow.response else None,
                                metadata={key: flow.metadata[key] for key in ('lens_frontend_method',) if key in flow.metadata})
                            # Reuse the existing shield-and-join worker owner so
                            # Stop/cancellation cannot abandon an executing job.
                            edit = await self.file_work(action.rewrite.edit, frozen, stage)
                            if flow.error or self.capture_stopped:
                                return
                    else:
                        edit = action.rewrite.edit(flow, stage)
                    edit.apply(flow)
                except ValueError as exc:
                    # Preserve the SDK kill sentinel until its protocol layer has
                    # observed it. The explicit reason is retained separately.
                    # Terminate before formatting/admitting diagnostics: reporting
                    # must never turn a failed rewrite into forwarded traffic.
                    abort_paused(flow)
                    reason = parse_rewrite_error(f"{stage.title()} rewrite failed: {exc}")
                    flow.metadata["lens_rewrite_error"] = reason
                    flow.metadata["lens_har_metadata_bytes"] = flow.metadata.get("lens_har_metadata_bytes", 0) + metadata_size({"lens_rewrite_error": reason}, METADATA_BYTES)
                    self.remember(flow)
                    return
                if stage == "request" and kind == "rewrite_request_url" and access_policy is not None and self.deny_access(flow, access_policy):
                    return
            elif kind == f"breakpoint_{stage}" and not flow.metadata.get("lens_skip_breakpoints"):
                await self.pause_at_breakpoint(flow, stage, rule.get("timeout_seconds", DEFAULT_BREAKPOINT_TIMEOUT_SECONDS))
                if flow.error:
                    break
            elif stage == "request":
                if kind == "dns_spoof":
                    flow.metadata["lens_dns_address"] = str(ipaddress.ip_address(value))
                elif kind == "map_remote":
                    try:
                        action.remote.apply(flow.request)
                    except ValueError as exc:
                        flow.response = http.Response.make(502, str(exc).encode(), {"Content-Type": "text/plain; charset=utf-8"})
                        return
                    if access_policy is not None and self.deny_access(flow, access_policy):
                        return
                elif kind == "map_local":
                    try:
                        response = local_response(original_url, rule["match"], value)
                        if response is not None:
                            flow.response = response
                    except (OSError, ValueError) as exc:
                        flow.response = http.Response.make(502, str(exc).encode())
                elif kind == "block":
                    flow.response = http.Response.make(403, b"Blocked by Lens rule", {"Content-Type": "text/plain"})
                elif kind == "delay":
                    await asyncio.sleep(float(value) / 1000)

    async def pause_at_breakpoint(self, flow, stage, seconds):
        flows = self.sessions.owner(flow).flows
        if flow.id not in flows:
            flow.metadata["lens_capture"] = True
            flows[flow.id] = flow
        flow.metadata["lens_pause_stage"] = stage
        flow.metadata["lens_pause_id"] = uuid.uuid4().hex
        flow.metadata["lens_pause_timeout_seconds"] = seconds
        # Wall time is presentation evidence; asyncio's monotonic clock owns expiration.
        flow.metadata["lens_pause_deadline"] = time.time() + seconds
        flow.intercept()
        self.remember(flow)
        try:
            # timeout() creates no waiter task. Exiting this context cancels its
            # scheduled callback on Continue, Abort, Clear, or hook cancellation.
            async with asyncio.timeout(seconds):
                await flow.wait_for_resume()
        except TimeoutError:
            if flow.intercepted:
                flow.metadata["lens_breakpoint_error"] = f"{stage.title()} breakpoint timed out after {seconds} seconds; request aborted."
                abort_paused(flow)
        except asyncio.CancelledError:
            if flow.intercepted:
                flow.metadata["lens_breakpoint_error"] = f"{stage.title()} breakpoint wait was cancelled; request aborted."
                abort_paused(flow)
            raise
        finally:
            for key in ("lens_pause_stage", "lens_pause_id", "lens_pause_timeout_seconds", "lens_pause_deadline"):
                flow.metadata.pop(key, None)
            self.remember(flow)

    async def connect_commands(self):
        if self.command_reader is None:
            self.command_reader = asyncio.StreamReader(limit=512 * 1024 * 1024)
            self.stdin_transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(self.command_reader), sys.stdin)

    @staticmethod
    def decode_command(line):
        command = json.loads(line)
        if not isinstance(command, dict):
            raise ValueError("Command must be a JSON object")
        if not isinstance(command.get("command_id"), str):
            raise ValueError("command_id must be a string")
        return command

    async def prepare_tls(self, selections, upstream_ca):
        """Keep the sole stdin reader responsive while selected files may wait."""
        async def load():
            if upstream_ca:
                self.upstream_trust = UpstreamTrust()
                await self.upstream_trust.load(upstream_ca, self.data_dir, self.certificate_inputs)
                self.master.options.update(ssl_verify_upstream_trusted_ca=str(self.upstream_trust.path))
            await self.client_certificates.load(selections, self.certificate_inputs)

        await self.connect_commands()
        work = asyncio.create_task(load())
        read = asyncio.create_task(self.command_reader.readline())
        try:
            while True:
                done, _ = await asyncio.wait((work, read), return_when=asyncio.FIRST_COMPLETED)
                if read in done:
                    line = read.result()
                    command_id = None
                    try:
                        if not line:
                            # EOF is consumed by the normal command owner after
                            # startup admission, including listener bind errors.
                            # It must not turn a failed startup into success.
                            await work
                            return
                        command = self.decode_command(line)
                        command_id = command["command_id"]
                        if command.get("command") in {"stop_capture", "shutdown"}:
                            work.cancel()
                            try:
                                await work
                            except asyncio.CancelledError:
                                pass
                            if command["command"] == "shutdown":
                                emit("result", command_id=command_id, value={"stopping": True})
                                self.request_shutdown()
                            else:
                                # Workspace/configuration loading has completed.
                                # Keep that owner, skip all listener creation and
                                # let the normal Stop transaction retain it.
                                self.inspect_only = True
                                self.pending_startup_command = command
                            return
                        raise ValueError("TLS startup is pending; wait for Ready or stop startup")
                    except (ValueError, TypeError) as exc:
                        emit("error", command_id=command_id, message=str(exc))
                    read = asyncio.create_task(self.command_reader.readline())
                if work in done:
                    await work
                    return
        finally:
            for task in (work, read):
                if not task.done():
                    task.cancel()
            # No reader can consume a later frame after handing ownership to
            # read_commands. Failed child cleanup stays owned for close/retry.
            await asyncio.gather(work, read, return_exceptions=True)

    async def initialize_from_stdin(self):
        await self.connect_commands()
        emit("initializing")
        command = json.loads(await self.command_reader.readline())
        if not isinstance(command, dict) or command.get("command") != "initialize" or not isinstance(command.get("command_id"), str):
            raise ValueError("Expected an initialize command before starting listeners")
        identify = command.get("client_process", False)
        if type(identify) is not bool:
            raise ValueError("client_process must be a boolean")
        if identify:
            from peer_process import PeerProcesses
            self.network.peer_processes = PeerProcesses(Path(__file__).resolve().parents[1] / "peer-process-identities")
        self.tcp_forwards = parse_forwards(command.get("tcp_forwards", []),
                                         [port for port in (self.port, self.socks_port, self.reverse_port) if port])
        self.udp_forwards = parse_forwards(command.get("udp_forwards", []), [], transport="UDP")
        require_http_only(self.upstream_proxy, socks=self.socks_port, reverse=self.reverse_port,
                          tcp=self.tcp_forwards, udp=self.udp_forwards)
        if command.get("workspace_path") is not None and any(command.get(key) is not None for key in ("tcp_session_path", "udp_session_path")):
            raise ValueError("Choose the workspace or separate transport imports, not both")
        if command.get("tcp_session_path") is not None:
            self.initial_tcp = await self.file_work(load_streams, selected_path(command["tcp_session_path"]))
        if command.get("udp_session_path") is not None:
            self.initial_udp = await self.file_work(load_associations, selected_path(command["udp_session_path"]))
        if command.get("workspace_path") is not None:
            self.use_workspace(await self.file_work(load_workspace, selected_path(command["workspace_path"]), self.emit_capture))
        await self.command({**command, "command": "configure"})
        await self.command({"command": "recording", "enabled": command.get("recording", True)})
        return command["command_id"], command.get("client_certificates", [])

    async def read_commands(self):
        await self.connect_commands()
        reader = self.command_reader
        try:
            while True:
                command_id = None
                try:
                    line = await reader.readline()
                    if not line:
                        break
                    command = self.decode_command(line)
                    command_id = command.get("command_id")
                    value = await self.command(command)
                    emit("result", command_id=command_id, value=value)
                except Exception as exc:
                    emit("error", command_id=command_id, message=str(exc))
        except (asyncio.CancelledError, BrokenPipeError):
            pass
        finally:
            self.request_shutdown()

    async def command(self, cmd):
        name = cmd["command"]
        room = self.sessions.lookup(cmd.get("session_id"))
        flows = room.flows
        if name == "new_session":
            created = self.sessions.create()
            self.recording = True
            return self.announce_sessions(created)
        if name == "activate_session":
            self.sessions.activate(room)
            self.recording = True
            return self.announce_sessions(room)
        if name == "open_session":
            imported = await self.file_work(load_snapshot, selected_path(cmd["path"]), MAX_FLOWS, MAX_STORED_BYTES)
            created = self.sessions.create(activate=False)
            result = self.announce_sessions(created)
            self.adopt_flows(imported, created)
            return result
        if name == "rename_session":
            self.sessions.rename(room, cmd.get("name"))
            return self.announce_sessions(room)
        if name == "close_session":
            backup = selected_path(cmd["backup_path"]) if "backup_path" in cmd else None
            if backup is None and cmd.get("discard") is not True:
                raise ValueError("Close requires a workspace backup path or explicit discard")
            self.sessions.begin_close(room)
            self.announce_sessions(room)
            try:
                for flow, owner in list(self.sessions.owners.items()):
                    if owner is room:
                        flow.metadata["lens_skip_breakpoints"] = True
                        if flow.intercepted:
                            flow.metadata["lens_breakpoint_error"] = "Breakpoint cancelled because its session closed; request aborted."
                            abort_paused(flow)
                jobs = [job for job in self.repeat_jobs.values() if job.session is room and not job.finalized]
                for job in jobs:
                    job.state = "cancelling"; job.task.cancel()
                await asyncio.gather(*(job.task for job in jobs), return_exceptions=True)
                for job in jobs:
                    job.finish()
                if backup is not None:
                    # Freeze all HTTP/raw sessions once. The explicit copy is
                    # complete at this close boundary, not a promise to record
                    # future bytes from transfers that continue forwarding.
                    await self.file_work(save_workspace, backup, self.sessions.snapshot())
            except BaseException:
                room.closed = False
                self.announce_sessions(room)
                self.publish_sessions()
                raise
            self.sessions.discard(room)
            return self.announce_sessions(self.sessions.capture)
        if name == "session_status":
            return self.sessions.public()
        if name == "save_workspace":
            revision = self.workspace_revision.current()
            snapshot = self.sessions.snapshot()
            saved = await self.file_work(save_workspace, selected_path(cmd["path"]), snapshot)
            self.workspace_revision.flush()
            return {**saved, "workspace_revision": revision,
                    "current_workspace_revision": self.workspace_revision.current()}
        if name == "stop_capture":
            if not self.capture_stopped:
                for flow in list(self.sessions.all_flows()):
                    if flow.intercepted:
                        flow.metadata["lens_breakpoint_error"] = "Breakpoint cancelled because Lens stopped; request aborted."
                        abort_paused(flow)
                        self.remember(flow)
                await self.quiesce_network_work()
                self.client_certificates.clear()
                if self.upstream_trust is not None:
                    self.upstream_trust.close()
                self.capture_stopped = True
                self.rule_plans.clear()
            await self.file_work(cleanup_pending_stages)
            self.workspace_revision.flush()
            return {"capture_stopped": True, "workspace_revision": self.workspace_revision.current()}
        if (self.capture_stopped or self.network.closed) and name in {"compose", "replay", "repeat", "resume"}:
            raise ValueError("Capture is stopped; start the proxy before sending traffic")
        if name == "network_status":
            proxy = self.proxy_server()
            return {**self.network.status(), **self.network.settings,
                "udp": self.udp_network.status(),
                "sdk": self.sdk_connections.status(proxy),
                "public_listeners": [{"name": name, "address": sock.getsockname()} for name, server in self.network.servers.items() for sock in (server.sockets or ())],
                "internal_listeners": [{"addresses": instance.listen_addrs} for instance in proxy.servers] if proxy else []}
        if name == "access_policy_status":
            return self.access_policy.public()
        if name == "client_certificate_status":
            return {"identities": self.client_certificates.public()}
        if name == "websocket_messages":
            return websocket_capture.page(flows[cmd["id"]], cmd.get("offset", 0), cmd.get("limit", 50), cmd.get("generation"))
        if name == "tcp_detail":
            return room.tcp.page(cmd["id"], cmd.get("offset", 0), cmd.get("limit", 32))
        if name == "tcp_status":
            return {"forwards": [forward.public() for forward in self.tcp_forwards],
                    "streams": [stream.summary() for stream in room.tcp.streams.values()]}
        if name == "clear_tcp":
            room.tcp.clear()
            return True
        if name == "save_tcp":
            return await self.file_work(save_streams, selected_path(cmd["path"]), room.tcp.snapshot())
        if name == "load_tcp":
            if not self.capture_stopped:
                raise ValueError("Stop capture before replacing a TCP session")
            values = await self.file_work(load_streams, selected_path(cmd["path"]))
            self.sessions.tcp_pool.admit_replacement(room.tcp, len(values), sum(len(chunk["content"]) + CHUNK_OVERHEAD for value in values for chunk in value["chunks"]))
            room.tcp.replace(values)
            return {"streams": len(values)}
        if name == "udp_detail":
            return room.udp.page(cmd["id"], cmd.get("offset", 0), cmd.get("limit", 32))
        if name == "udp_status":
            return {"forwards": [forward.public() for forward in self.udp_forwards],
                    "associations": [association.summary() for association in room.udp.associations.values()],
                    "network": self.udp_network.status()}
        if name == "clear_udp":
            room.udp.clear()
            return True
        if name == "save_udp":
            return await self.file_work(save_associations, selected_path(cmd["path"]), room.udp.snapshot())
        if name == "load_udp":
            if not self.capture_stopped:
                raise ValueError("Stop capture before replacing a UDP session")
            values = await self.file_work(load_associations, selected_path(cmd["path"]))
            self.sessions.udp_pool.admit_replacement(room.udp, len(values), sum(len(item["content"]) + DATAGRAM_OVERHEAD for value in values for item in value["datagrams"]))
            room.udp.replace(values)
            return {"associations": len(values)}
        if name == "detail":
            return detail(flows[cmd["id"]])
        if name == "export_body":
            side = cmd["side"]
            if side not in ("request", "response"):
                raise ValueError("side must be request or response")
            decoded = cmd.get("decoded", True)
            if not isinstance(decoded, bool):
                raise ValueError("decoded must be a boolean")
            flow = flows[cmd["id"]]
            if "request_fingerprint" in cmd:
                if side != "request":
                    raise ValueError("request_fingerprint is only valid for request body export")
                validate_source_fingerprint(flow.request, cmd["request_fingerprint"])
            message = getattr(flow, side)
            if message is None:
                raise ValueError(f"No {side} available")
            if not body_available(message):
                raise ValueError(f"Captured {side} body is unavailable; the HAR did not include body bytes")
            raw = (message_content(message) if decoded else message.raw_content) or b""
            return {"base64": base64.b64encode(raw).decode(), "bytes": len(raw),
                    "mime_type": message.headers.get("content-type", "application/octet-stream")}
        if name == "clear":
            selected = tuple(flows.items())
            if "backup_path" in cmd:
                # A failed/cancelled copy must leave the selected records and
                # paused requests untouched. New arrivals during the atomic
                # write are outside this snapshot and remain in the session.
                backup = selected_path(cmd["backup_path"])
                await self.file_work(save_workspace, backup, self.sessions.snapshot())
            # A user clearing captures must not strand intercepted connections.
            for identity, flow in selected:
                flow.metadata["lens_capture"] = False
                # Clear is an explicit continuation of these flows, including
                # later matching breakpoint rules in either stage.
                flow.metadata["lens_skip_breakpoints"] = True
                if flow.intercepted:
                    flow.resume()
                if flows.get(identity) is flow:
                    del flows[identity]
                    self.workspace_revision.changed()
                    self.emit_capture("removed", id=identity, session_id=room.id)
            return True
        if name == "recording":
            if not isinstance(cmd["enabled"], bool):
                raise ValueError("enabled must be a boolean")
            self.recording = cmd["enabled"]
            return self.recording
        if name == "configure":
            if self.inspect_only:
                raise ValueError("Inspection-only file sessions cannot configure capture")
            rules = cmd.get("rules", [])
            if not isinstance(rules, list) or len(rules) > 500:
                raise ValueError("rules must be an array of at most 500 rules")
            # Admit the whole caller representation before compiling/encoding
            # any per-action values. Defaults are applied to copies only.
            rule_bytes = metadata_size({"rules": rules}, METADATA_BYTES)
            prepared_rules = []
            for source_rule, scope in expand_rules(rules):
                if not isinstance(source_rule, dict):
                    raise ValueError("Unknown rule kind")
                rule = dict(source_rule)
                remote = None
                if not isinstance(rule, dict) or rule.get("kind") not in RULE_KINDS:
                    raise ValueError("Unknown rule kind")
                if type(rule.get("enabled", True)) is not bool:
                    raise ValueError("Rule enabled must be a boolean")
                for key in ("match", "name", "value", "rewrite_find", "rewrite_new_name"):
                    if not isinstance(rule.get(key, ""), str):
                        raise ValueError(f"Rule {key} must be a string")
                rule.setdefault("match", "*")
                if rule["kind"] in ("breakpoint_request", "breakpoint_response"):
                    seconds = rule.get("timeout_seconds", DEFAULT_BREAKPOINT_TIMEOUT_SECONDS)
                    if type(seconds) is not int or not 1 <= seconds <= MAX_BREAKPOINT_TIMEOUT_SECONDS:
                        raise ValueError("Breakpoint timeout_seconds must be an integer between 1 and 3600")
                if rule["kind"] == "dns_spoof":
                    ipaddress.ip_address(rule.get("value", ""))
                if rule["kind"] == "map_remote":
                    destination = rule.get("map_destination")
                    remote = (RemoteMapping.prepare_parts(destination, rule["match"], rule.get("path_mode", "append"))
                              if destination is not None else RemoteMapping.prepare(rule.get("value", ""), rule["match"], rule.get("path_mode", "append")))
                    if destination is not None:
                        rule["map_destination"] = MappingProxyType(dict(destination))
                if rule["kind"] == "map_local":
                    selected_local_path(rule.get("value", ""))
                if rule["kind"] == "delay" and not 0 <= float(rule.get("value", "")) <= 60000:
                    raise ValueError("Delay must be between 0 and 60000 ms")
                rewrite = prepare_rewrite(rule)
                prepared_rules.append(PreparedRule(MappingProxyType(rule), remote, rewrite, scope))
            policy = parse_access_policy(cmd.get("access_policy", self.access_policy.public()))
            rates = network_settings(cmd.get("network", self.network.settings),
                                     connect_timeout=self.network.settings["connect_timeout_seconds"])
            ignore = ssl_ignore_pattern(cmd.get("ssl_hosts", "*"))
            retained = {id(plan.snapshot): plan.snapshot_bytes for plan in self.active_rule_plans}
            if sum(retained.values()) + rule_bytes > STORE_BYTES:
                raise ValueError("Active requests retain the 256 MiB rule-generation budget; wait for them to finish before changing rules")
            self.master.options.update(ignore_hosts=ignore)
            self.rules = tuple(prepared_rules)
            self.rules_metadata_bytes = rule_bytes
            self.access_policy = policy
            self.network.configure(rates)
            return {"rules": len(rules), "ssl_hosts": cmd.get("ssl_hosts", "*"), "network": self.network.settings, "access_policy": self.access_policy.public()}
        if name in ("replay", "compose"):
            if len(self.tasks) >= 17:
                raise ValueError("Too many queued requests (maximum 16)")
            if name == "replay":
                source_id = cmd["id"]
                snapshot = snapshot_request(flows[source_id].request)
                facts = operation_facts('replay', cmd['command_id'], source_id)
            else:
                composed = prepare_compose(cmd, flows)
                snapshot = composed.snapshot
                facts = operation_facts('compose', cmd['command_id'], composed.source_id, composed.url_input)
            token = self.request_tokens.new()
            self.spawn(self.send_request(snapshot, token, cmd["command_id"], operation=facts, session=room))
            return {"queued": True}
        if name == "repeat":
            values = {}
            for key, default, low, high in (("count", 1, 1, 1000), ("concurrency", 1, 1, 16),
                                           ("interval_ms", 0, 0, 60000)):
                value = cmd.get(key, default)
                if type(value) is not int or not low <= value <= high:
                    raise ValueError(f"{key} must be an integer between {low} and {high}")
                values[key] = value
            request = flows[cmd["id"]].request
            if not body_available(request):
                raise ValueError("Cannot repeat: captured request body is unavailable; compose an explicit replacement")
            snapshot = snapshot_request(request)
            # Completed job snapshots need not retain request bodies indefinitely.
            for identifier, previous in list(self.repeat_jobs.items()):
                if previous.finalized:
                    del self.repeat_jobs[identifier]
            job = RepeatJob(uuid.uuid4().hex, values["count"], values["concurrency"], values["interval_ms"], snapshot, cmd["id"])
            job.session = room
            self.repeat_jobs[job.id] = job
            job.task = self.spawn(self.run_repeat(job))
            job.task.add_done_callback(lambda task: job.finish())
            return {"job_id": job.id}
        if name == "cancel_repeat":
            job = self.repeat_jobs[cmd["job_id"]]
            if not job.finalized:
                job.state = "cancelling"
                job.task.cancel()
                await asyncio.gather(job.task, return_exceptions=True)
                job.finish()  # also handles cancellation before the coroutine first runs
            return job.event()
        if name == "export_har":
            return {"log": {**document_metadata(), "entries": [export_flow(f) for f in flows.values()]}}
        if name == "save_har":
            path = selected_path(cmd["path"])
            # Freeze completion evidence before copy() clears live state; mutable
            # headers/messages are copied, immutable body bytes are shared safely.
            snapshot = [snapshot_flow(flow) for flow in flows.values()]
            return await self.file_work(save_snapshot, path, snapshot)
        if name == "load_har":
            path = selected_path(cmd["path"])
            imported = await self.file_work(load_snapshot, path, MAX_FLOWS, MAX_STORED_BYTES)
            self.adopt_flows(imported, room)
            return {"path": str(path), "imported": len(imported), "entries": len(imported)}
        if name == "import_har":
            imported = prepare_import(cmd["har"], MAX_FLOWS, MAX_STORED_BYTES)
            self.adopt_flows(imported, room)
            return {"imported": len(imported)}
        if name == "resume":
            flow = flows[cmd["id"]]
            if not flow.intercepted:
                raise ValueError("Flow is not paused")
            pause = flow.metadata.get("lens_pause_id")
            if "pause_id" in cmd and (not isinstance(cmd["pause_id"], str) or cmd["pause_id"] != pause):
                raise ValueError("Breakpoint pause changed; refresh before continuing")
            if ("request_edit" in cmd or "response_edit" in cmd) and (not pause or cmd.get("pause_id") != pause):
                raise ValueError("Message edits require the current pause_id")
            if "stage" in cmd and cmd["stage"] != flow.metadata.get("lens_pause_stage"):
                raise ValueError("Breakpoint stage changed; refresh before continuing")
            if cmd["action"] == "abort":
                abort_paused(flow)
            elif cmd["action"] == "continue":
                # Prepare every field and transformed representation on a copy.
                # Only the validated owner can replace the live paused message.
                edit = prepare_edit(flow, cmd)
                metadata, cost = {}, flow.metadata.get("lens_har_metadata_bytes", 0)
                if edit.original_url is not None:
                    metadata["lens_breakpoint_url"] = edit.original_url
                if edit.side == "request" and request_method(edit.message) != request_method(flow.request):
                    metadata["lens_frontend_method"] = flow.metadata.get("lens_frontend_method", request_method(flow.request))
                if metadata:
                    old = {key: flow.metadata[key] for key in metadata if key in flow.metadata}
                    cost = max(0, cost - (metadata_size(old, METADATA_BYTES) if old else 0)) + metadata_size(metadata, METADATA_BYTES)
                edit.apply(flow)
                flow.metadata.update(metadata)
                flow.metadata["lens_har_metadata_bytes"] = cost
                flow.resume()
            elif cmd["action"] == "discard":
                # Drafts stay native until Execute. Discard leaves exact message
                # bytes and headers untouched, even if the draft was malformed.
                flow.resume()
            else:
                raise ValueError("action must be continue, discard or abort")
            self.remember(flow)
            return True
        if name == "shutdown":
            self.request_shutdown()
            return True
        raise ValueError(f"Unknown command: {name}")

    def adopt_flows(self, flows, room=None):
        for flow in flows:
            self.sessions.owner(flow, room)
            flow.metadata["lens_capture"] = True
            self.sessions.owner(flow).flows[flow.id] = flow
            self.remember(flow)

    async def file_work(self, function, *args):
        # A Python file worker cannot be forcibly cancelled. Shield and join it
        # even during shutdown so an atomic save never finishes behind our back.
        worker = asyncio.create_task(asyncio.to_thread(function, *args))
        self.file_tasks.add(worker)
        cancelled = False
        try:
            # Repeated cancellation during finalization cannot abandon a Python
            # thread or release its caller's bounded execution slot early.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    cancelled = True
                except Exception:
                    break
            if cancelled:
                # Observe a late worker failure even though the caller retains
                # cancellation; no abandoned Task exception may outlive its owner.
                if not worker.cancelled():
                    worker.exception()
                raise asyncio.CancelledError()
            return worker.result()
        finally:
            if worker.done():
                self.file_tasks.discard(worker)

    async def send_request(self, snapshot, token, command_id, emit_completion=True, *, operation, session=None):
        pending = PendingRequest(operation, session=session or self.sessions.capture)
        # Create the token owner inside the coroutine, before its first await.
        # Cancellation before coroutine entry cannot leave a provisional token.
        self.pending_requests[token] = pending
        try:
            async with self.semaphore:
                context = ssl.create_default_context(cafile=str(self.data_dir / "mitmproxy-ca-cert.pem"))
                await send_via_proxy(snapshot, token, proxy_port=self.port,
                                     ssl_context=context, close_streams=self.network.close_streams)
                if emit_completion:
                    emit("request_finished", command_id=command_id, session_id=pending.session.id, flow_id=pending.flow.id if pending.flow and pending.flow.id in self.sessions.owner(pending.flow).flows else None)
                return True
        except Exception as exc:
            if emit_completion:
                emit("request_failed", command_id=command_id, session_id=pending.session.id, flow_id=pending.flow.id if pending.flow and pending.flow.id in self.sessions.owner(pending.flow).flows else None, message=str(exc))
            return False
        finally:
            self.pending_requests.pop(token, None)
            flow = pending.flow
            if flow and flow.intercepted:
                abort_paused(flow)
                self.remember(flow)

    async def run_repeat(self, job):
        pace = asyncio.Lock()
        next_start = 0.0

        async def worker():
            nonlocal next_start
            while job.cursor < job.total:
                # No await between claiming an index and advancing it.
                job.cursor += 1
                attempt = job.cursor
                async with pace:
                    loop = asyncio.get_running_loop()
                    await asyncio.sleep(max(0, next_start - loop.time()))
                    next_start = loop.time() + job.interval_ms / 1000
                token = self.request_tokens.new()
                facts = operation_facts('repeat', job.id, job.source_id, attempt=attempt)
                success = await self.send_request(job.request, token, None, emit_completion=False, operation=facts, session=job.session)
                if success:
                    job.completed += 1
                else:
                    job.failed += 1
                emit("repeat_progress", **job.event())

        emit("repeat_progress", **job.event())
        try:
            job.children = {asyncio.create_task(worker()) for _ in range(min(job.concurrency, job.total))}
            await asyncio.gather(*job.children)
        finally:
            for task in job.children:
                task.cancel()
            await asyncio.gather(*job.children, return_exceptions=True)
            job.children.clear()
            job.request = None
            job.finish()

    async def close(self):
        self.closed = True
        for flow in self.sessions.all_flows():
            if flow.intercepted:
                flow.metadata["lens_breakpoint_error"] = "Breakpoint cancelled because Lens stopped; request aborted."
                abort_paused(flow)
        await self.quiesce_network_work()
        await self.certificate_inputs.close()
        if self.stdin_transport:
            self.stdin_transport.close()
        await asyncio.gather(*(asyncio.shield(worker) for worker in list(self.file_tasks)), return_exceptions=True)
        await self.file_work(cleanup_pending_stages)
        self.workspace_revision.close()
        self.rule_plans.clear()
        self.client_certificates.clear()
        if self.upstream_trust is not None:
            self.upstream_trust.close()


async def main():
    global NATIVE_JSON
    if version.VERSION != "12.2.1":
        raise RuntimeError("Lens TLS adapter requires pinned mitmproxy 12.2.1")
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-port", type=int, default=8890)
    parser.add_argument("--native-json", action="store_true", help="Use lossless Unicode-safe native JSONL envelopes; legacy CLI output is unchanged by default")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--socks-port", type=int, default=0)
    parser.add_argument("--reverse-port", type=int, default=0)
    parser.add_argument("--reverse-url")
    parser.add_argument("--lan-bind", help="Explicit private IPv4 LAN interface; off by default")
    parser.add_argument("--upstream-ca", type=Path, help="Selected PEM CA bundle for strict upstream TLS; replaces the default public roots")
    parser.add_argument("--http-upstream-proxy", help="Explicit unauthenticated HTTP proxy for HTTP/HTTPS; no direct fallback")
    parser.add_argument("--initialize-from-stdin", action="store_true", help="Apply one initialize JSONL command before opening public listeners")
    parser.add_argument("--inspect-tcp", type=Path, help="Open a TCP session with control stdin only; no public/internal listeners")
    parser.add_argument("--inspect-udp", type=Path, help="Open a UDP session with control stdin only; no public/internal listeners")
    parser.add_argument("--inspect-workspace", type=Path, help="Open an Lens workspace without listeners or TLS initialization")
    parser.add_argument("--inspect-empty", action="store_true", help="Open an empty workspace without listeners or TLS initialization")
    args = parser.parse_args()
    NATIVE_JSON = args.native_json
    if sum((bool(args.inspect_tcp), bool(args.inspect_udp), bool(args.inspect_workspace), args.inspect_empty)) > 1:
        parser.error("Select one session to inspect")
    inspect_only = args.inspect_tcp is not None or args.inspect_udp is not None or args.inspect_workspace is not None or args.inspect_empty
    if inspect_only and (args.initialize_from_stdin or args.socks_port or args.reverse_port or args.reverse_url or args.lan_bind or args.upstream_ca or args.http_upstream_proxy):
        parser.error("Inspection-only mode cannot be combined with listener, TLS or initialization options")
    try:
        lan = LANAccess.parse(args.lan_bind)
        upstream_proxy = HTTPUpstreamProxy.parse(args.http_upstream_proxy)
        require_http_only(upstream_proxy, socks=args.socks_port, reverse=args.reverse_port)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.proxy_port <= 65535:
        parser.error("proxy port must be between 1 and 65535")
    for name in ("socks_port", "reverse_port"):
        if not 0 <= getattr(args, name) <= 65535:
            parser.error(f"{name} must be between 0 and 65535 (0 disables)")
    selected_ports = [p for p in (args.proxy_port, args.socks_port, args.reverse_port) if p]
    if len(set(selected_ports)) != len(selected_ports):
        parser.error("Enabled listeners must use distinct ports")
    if bool(args.reverse_port) != bool(args.reverse_url):
        parser.error("--reverse-port and --reverse-url must be provided together")
    if args.reverse_url:
        try:
            target = urlsplit(prepare_url(args.reverse_url).value)
        except ValueError as exc:
            parser.error(str(exc))
        if target.path not in ("", "/") or target.query or target.fragment:
            parser.error("Reverse URL must be an origin URL without a base path, query, or fragment")
    data_dir = args.data_dir.expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # A stopped file inspector has no protocol server or TLS authority. Even
    # DumpMaster(mode=[]) configures TlsConfig and creates a CA on construction.
    # Keep file/control ownership in Lens without constructing that SDK owner.
    master = None
    if not inspect_only:
        opts = options.Options(listen_host="127.0.0.1", listen_port=0,
                               mode=[upstream_proxy.mode if upstream_proxy else "regular@127.0.0.1:0"], confdir=str(data_dir))
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.options.update(body_size_limit="32m", connection_strategy="lazy")
    lens = Lens(master, data_dir, args.proxy_port, args.socks_port, args.reverse_port, args.reverse_url,
                lan=lan, upstream_proxy=upstream_proxy)
    if master is not None:
        master.addons.add(lens)
    loop = asyncio.get_running_loop()
    initializing, signal_requested = True, False
    main_task = asyncio.current_task()
    def stop_for_signal():
        nonlocal signal_requested
        signal_requested = True
        lens.request_shutdown()
        if initializing:
            main_task.cancel()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_for_signal)
    try:
        if args.inspect_workspace:
            lens.use_workspace(await lens.file_work(load_workspace, args.inspect_workspace.expanduser().absolute(), lens.emit_capture))
        if inspect_only:
            lens.inspect_only = True
        if args.inspect_tcp:
            lens.inspect_only = True
            lens.initial_tcp = await lens.file_work(load_streams, args.inspect_tcp.expanduser().absolute())
        if args.inspect_udp:
            lens.inspect_only = True
            lens.initial_udp = await lens.file_work(load_associations, args.inspect_udp.expanduser().absolute())
        if not inspect_only:
            initialization_id, selections = await lens.initialize_from_stdin() if args.initialize_from_stdin else (None, [])
            await lens.prepare_tls(selections, args.upstream_ca)
            del selections
            if initialization_id is not None:
                emit("result", command_id=initialization_id, value={"initialized": not (lens.inspect_only or lens.finished.is_set())})
            if lens.finished.is_set():
                return
        initializing = False
        if lens.inspect_only:
            await lens.running()
            await lens.finished.wait()
        else:
            await master.run()
    except asyncio.CancelledError:
        if not signal_requested:
            raise
    finally:
        initializing = False
        await lens.close()
    if lens.startup_error:
        raise SystemExit(1)


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    try:
        asyncio.run(main())
    except Exception as exc:
        emit("fatal", message=str(exc))
        sys.exit(1)
