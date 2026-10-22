# Lens proxy engine

Run with the project runtime:

```sh
.runtime/bin/python engine/engine.py --proxy-port 8890 --data-dir /absolute/private/directory
.runtime/bin/python -m unittest discover -s engine -v
.runtime/bin/python engine/smoke.py
```

The engine binds **127.0.0.1 only**. `data-dir` contains the independently generated
mitmproxy CA and its private key. No trust store, system proxy, or Charles settings
are changed. Upstream TLS verification remains enabled; `--upstream-ca PATH`
explicitly provides a custom upstream CA bundle, useful for local TLS fixtures.
The caller must opt clients into this proxy and trust the CA for HTTPS interception.

stdin is JSONL commands with `command` and `command_id`; stdout contains JSONL
events only. Every command responds `result {command_id,value}` or
`error {command_id,message}`. The initial `ready` event contains `proxy_port` and
`ca_cert`. Captures emit `flow {flow}`; eviction emits `removed {id}`. Replays and
Compose return `{queued:true}` immediately so a breakpoint can still be resumed;
a later `request_finished` or `request_failed` event shares the initiating
`command_id`. Fatal startup failures emit `fatal {message}` and exit nonzero.

Supported commands: `detail`, `clear`, `recording`, `configure`, `replay`, `compose`,
`export_har`, `import_har`, `resume`, `stop_capture`, `shutdown`,
`client_certificate_status`, `tcp_status`, `tcp_detail`, `clear_tcp`, `save_tcp`,
`load_tcp`. `stop_capture`
idempotently closes public/internal listeners, aborts paused requests and drains
owned traffic tasks, retaining the bounded session and JSONL reader for `detail`
and exports. It rejects Compose/Replay/Repeat/Resume until a new engine is started.
`shutdown` ends the session process and completes its cleanup. Rule kinds follow the parent
application protocol. Rules use case-sensitive shell globs and run in list order
at their applicable stage. Request rules select by original client URL before
pauses or mappings; response-only rules select by effective URL once when the
response enters. The two-sided cache/cookie controls keep their original-request
selection for both halves. One immutable configuration/order owns the whole
transaction; traffic-rule changes affect new requests only, including when an
older request is paused. Shared bandwidth updates still apply immediately.

Workspace status uses an engine-owned `{epoch,generation}` revision. `epoch` is
a UUID and `generation` an opaque canonical decimal **string**, so clients must
not round it through a JSON/JavaScript number. Ordinary capture/catalog frames
include `workspace_revision`; throttled raw mutations emit a coalesced
`workspace_state {workspace_revision}` at most every 100 ms. Mutations advance
the revision immediately, before that notification delay. Read-only queries and
republishing existing captures do not advance it.

Ready also reports `workspace_base_revision` and `workspace_base_has_content`
for the fully loaded input before opening public listeners. Its current
`workspace_revision` can be newer if traffic arrived while listeners started.
`save_workspace {path}` atomically saves every room/protocol and returns
`{path,sessions,entries,workspace_revision,current_workspace_revision}`: the first
revision identifies the frozen snapshot, the second the current owner after the
write. They can differ. `stop_capture` returns
`{capture_stopped:true,workspace_revision}` only after producer cleanup joins.
Saving private retention files does not itself establish a public document's
saved baseline; the native document owner chooses that explicitly. Workspace
file format versions remain unchanged. Native clients need their matching
bundled engine; these protocol additions are separate from source HAR facts.

Request delay is
0–60000 milliseconds. Map Remote `path_mode` is `relative` or `append`; omission
retains legacy append semantics. Relative mode maps source-glob directories to
destination directories ending `/`, replaces an exact destination file path,
and preserves the path when the destination has none. Destination query
presence replaces the original query, including a final empty `?`; otherwise
the original query marker and bytes survive. Compiled destination and captured
target bytes have separate owners; mapping never reparses a captured URL.
Host/authority and upstream TLS hostname use the selected destination.
Invalid URL/mode configuration is rejected atomically; mapped targets beyond
64 KiB or invalidated by an earlier relative mapping return 502 before dialing.
See [Map Remote tests](../tests/test_map_remote.py).
Map Local accepts an absolute file/directory path, with a guessed MIME type.
Its matching and lookup ignore the query. A directory uses the URL path relative
to the directory before the first path wildcard (or the containing directory
for an exact path). Missing files and directory requests leave the existing
response/upstream pipeline intact. No index lookup or listing is implied.
Descendant links are not followed: descriptor-relative, no-follow opens own the
root boundary through the read. Only regular files are read, nonblocking and
bounded to 32 MiB even if a file grows. Invalid percent/UTF-8 components, dot
segments, decoded separators and NULs fail explicitly. Selected roots may be
symlinks; case follows the filesystem. See the parent Map Local verification.
A breakpoint retains the flow even with recording paused, making the
connection addressable for resume. `clear` releases paused connections and prevents
already-cleared in-flight captures from returning. Recording is decided at request
start and does not stop forwarding or rule application.

`ssl_hosts` is `*` for all hosts, an empty string to tunnel TLS, or comma-separated
host globs (without scheme, path, or port). Unselected hosts tunnel without
inspection. Existing connections retain their already-negotiated TLS behavior.

Body previews are capped at 2 MiB of decoded bytes, independently for each side.
`request_truncated` and `response_truncated` identify incomplete previews.
`request_body_base64` and `response_body_base64` contain the same preview bytes;
`request_binary` and `response_binary` indicate invalid UTF-8. The text preview
uses UTF-8 replacement and must not be used to export binary payloads. HAR standard body fields hold complete decoded content: UTF-8 text remains readable,
and binary response content uses standard `encoding:base64`. Binary request
postData uses an `encoding:base64` extension, while ordinary text requests remain
plain text. Entry extensions `_lensRawRequestBody` and `_lensRawResponseBody`
preserve original wire bytes as base64, including exact compression. Import
prefers those extensions for Lens captures; ordinary external HAR decoded bodies
are re-encoded according to Content-Encoding and framing is recalculated.
Duplicate headers survive both paths.

Capture retention is 2000 flows / 256 MiB of body bytes, evicting oldest nonpaused
captures. Each HTTP body has a 32 MiB proxy limit; exceeding it fails the request,
rather than silently claiming a complete capture. WebSockets retain the most
recent 2000 messages / 32 MiB; discarded messages are explicitly flagged by
`websocket_messages_truncated`, detail `messages_truncated`, and the HAR extension
`_webSocketMessagesTruncated`. HAR includes `_webSocketMessages` binary messages.
No captures are automatically persisted by the engine.

## Prepared TLS identities

`--initialize-from-stdin` waits before public listeners open. The first JSONL
message must be `initialize` with `command_id`, ordinary `rules`/`ssl_hosts`/
`network`/`recording`, and `client_certificates` (default `[]`). Each selection is
`{host,port,path,password}`: exact DNS/IP, target port (default 443), absolute
PKCS#12 (`.p12`/`.pfx`) or combined PEM, and optional password. It emits
`initializing`, then a result and `ready` only after successful preparation.
`ready.client_certificates` and `client_certificate_status.identities` contain
public loaded facts (including selected source host/path); never key/password.
Selections cannot change within a running engine. Stop clears identity/context
owners while retaining captured bodies. Standalone callers omitting this flag
retain the existing empty-identity startup workflow.

`--upstream-ca PATH` selects a PEM trust bundle instead of the default public
roots. A bounded regular-file read creates a private certificate-only snapshot;
the source is preserved in `ready.upstream_ca`. Stop/Quit cleans its owner.
Certificate chains and TLS hostnames remain verified. The native app uses this
startup contract without putting passwords in argv, environment or persistence.
Inherited TLS-keylog environment flags are disabled. See
[client-certificate tests](../tests/test_client_certificates.py).

API basis: mitmproxy 12.2.1 installed sources (`DumpMaster`, async HTTP hooks,
`Flow.intercept/wait_for_resume/resume`, `Options.ignore_hosts`,
`ssl_verify_upstream_trusted_ca`) and official
[HTTP](https://docs.mitmproxy.org/stable/api/mitmproxy/http.html) /
[Flow](https://docs.mitmproxy.org/stable/api/mitmproxy/flow.html) APIs.

## Repeat jobs and cache/cookie controls

`repeat {id,count,concurrency,interval_ms}` snapshots the selected request and
returns `{job_id}` immediately. Integer ranges are count 1–1000, concurrency 1–16,
and interval 0–60000 ms. A job uses at most its selected number of workers and
spaces request attempts by interval_ms; the shared outgoing ceiling is four active
requests across jobs, Replay, and Compose, so effective concurrency is at most
`min(concurrency,4)`. Requests go through this engine's proxy, normal rules and
recording, and retain the replay marker. No response body is duplicated into the
job result.

Top-level `repeat_progress` and final `repeat_done` events contain `job_id`,
`total`, `completed`, `failed`, `cancelled`, `state`. Completed counts successful
HTTP transactions regardless of status (including HTTP 403); failed counts
transport failures. At finalization, completed + failed + cancelled = total.
States are `running`, `completed`, `cancelled`. `cancel_repeat {job_id}` cancels
that job's queued/running workers and returns final counters after cleanup;
other jobs and unrelated client traffic continue. Owned paused replay requests
are aborted so cancellation cannot strand a breakpoint. Shutdown cancels all owned
job workers. Completed request snapshots are released; terminal job counters are
retained until another job is submitted.

Rule `no_cache` removes all request If-Modified-Since/If-None-Match and sets
Pragma:no-cache and Cache-Control:no-cache. It removes response ETag/Last-Modified,
sets Expires:0 and Cache-Control:no-store, replacing duplicate values. This
deliberately preserves Lens's stricter no-store behavior. Rule `block_cookies`
removes request Cookie and all response Set-Cookie headers. Both use the ordinary
URL match, enabled flag, and list ordering. No DNS or bandwidth policy is implied.
Later rewrites or breakpoint edits can explicitly restore a removed field.
Existing browser caches/cookie jars are not cleared, and encrypted opaque
tunnels have no HTTP headers to edit. `enabled` must be a JSON boolean when
provided; invalid configurations leave the old rules intact.

Configure copies fields into immutable rule mappings once. A weak flow binding
owns each active request plan. Response-only rules and already-selected two-sided
controls merge in their original order. Response takes its plan into its coroutine
before pausing, and error/cancelled-request/Stop/close release remaining bindings.
Cancellation cleanup does not depend on a subsequent SDK error hook. Ordinary
addon exceptions, which the SDK can swallow before forwarding, retain the plan
for their eventual response/error. A weak registry
accounts for plans held by both request and response coroutines. Each configuration
has a 16 MiB logical metadata budget; active unique generations plus a proposed
configuration must fit a separate 256 MiB logical budget. Capacity rejection is
atomic; finish/abort active requests before retrying. Completed retained captures
do not hold obsolete rule generations, and Clear does not change an active plan.
Executable rule plans are neither flow metadata nor HAR history. See
[HTTP control tests](../tests/test_http_controls.py).

## Full body export and HTTP/2 negotiation

`export_body {id,side,decoded}` returns `{base64,bytes,mime_type}` for the complete
retained request or response body. Side is `request` or `response`; decoded
(default true) removes Content-Encoding, while false exports exact wire bytes.
This command is independent of the 2 MiB preview window.

The engine keeps mitmproxy's lazy connection strategy so Map Local and blocking
rules do not contact an origin before the request can be inspected. For clients
that offer h2 and HTTP/1.1, it prefers h2 on the intercepted client leg when there
is no explicit protocol choice or already-negotiated upstream ALPN. This uses the
pinned mitmproxy 12.2.1 TlsConfig per-connection SSL app-data policy, verified
against installed source; upgrading mitmproxy requires rechecking this boundary.
HTTP/1-only clients retain their offer, shared TLS contexts are unchanged, and
upstream certificate verification stays enabled. The frontend protocol and
upstream protocol can differ, as supported by mitmproxy's HTTP protocol adapter.

## Bandwidth simulation and optional listeners

`configure` accepts an optional `network` object:
`{upload_kbps:0,download_kbps:0}`. Values are finite nonnegative numbers in decimal
**kB/s (1000 bytes per second)**; zero means unlimited. Omitting `network` preserves
the current rates. Each direction has its own shared aggregate budget across all
public HTTP, SOCKS5, and reverse connections, including replayed traffic. A private
loopback TCP relay delivers 4 KiB chunks progressively using asynchronous waits;
it does not sleep the event loop, alter captured bodies, or replace transfer time
with an end-of-request delay. Headers, CONNECT negotiation, TLS framing and
WebSocket frames count toward wire-byte throughput, not just decoded body bytes.
The proxy still buffers HTTP bodies for rewriting/capture, so an inspected HTTP
origin may receive a request body after the proxy finishes buffering it; excluded
TLS tunnels expose wire-level progressive upload directly. Network settings apply
to existing relay connections and all newly accepted ones.

Optional startup arguments:

- `--socks-port PORT`: start a SOCKS5 listener; `0` disables it.
- `--reverse-port PORT --reverse-url http[s]://host[:port]`: start a reverse HTTP
  listener; port `0` disables it. The target must be an origin URL, without a base
  path, query, fragment, or embedded credentials. Request paths/queries are kept;
  the reverse mode selects the target origin and its Host header.

Internal listeners and default public listeners bind only `127.0.0.1`. The
explicit LAN HTTP option below adds one restricted interface. Enabled public ports must
be distinct. The engine uses mitmproxy 12.2.1 `Proxyserver.Servers.update` and each
mode server's actual typed TCP owner for internal ephemeral ports; no free-port
probe is reported as a live listener. `ready` follows successful binding of **all**
public listeners and includes `proxy_port`, `ca_cert`, and enabled `socks_port` /
`reverse_port`. A failed bind emits `fatal`, closes already-owned listeners and
exits nonzero. Shutdown first stops new accepts, then cancels and joins owned
relay connections, then awaits server closure. This ordering matters on Python
3.13, where `Server.wait_closed` also waits for active transports.

## Per-request DNS override

Rule `dns_spoof` takes an IP literal in `value` and an ordinary case-sensitive URL
glob in `match`. It overrides only that request's upstream dial address; its URL,
Host, TLS SNI, and upstream certificate hostname verification retain the selected
HTTP hostname. It neither changes system DNS nor reports an actual DNS resolution.
`original_url` / `effective_url` preserve URL provenance; `dns_address` records the
rule-selected IP and `dns_dial_address` records the attempted socket destination.
The latter is not proof that a connection succeeded. DNS rules cannot inspect
URLs inside excluded TLS tunnels, which intentionally remain opaque.

A pinned `HttpLayer` subclass changes the internal `GetHttpConnection` target at
the owning stream, before pool admission. DNS-overridden requests get independent
connections to prevent another URL/host's pooled connection from bypassing or
mixing their route decision. Original request objects are never rewritten to IP
URLs. Upstream TLS verifies the original hostname even when the socket targets an
IP. Layer instances are installed while fresh through `next_layer`; shared classes
and global functions are unchanged. The 12.2.1 layer contracts must be rechecked
when upgrading mitmproxy.

## LAN HTTP/HTTPS entry

`--lan-bind PRIVATE_IPV4` explicitly adds the main HTTP/HTTPS proxy port on one
assigned private/link-local IPv4 interface. All clients that can reach that
address can connect, without device IP registration. Wildcard, CIDR,
public and loopback bind addresses are rejected. Default remains loopback-only.
SOCKS and reverse mode do not gain LAN listeners.

LAN shares the existing aggregate rate/connection budgets. A failed LAN bind
closes any already-bound loopback endpoint and cannot emit ready. Self-loop
protection includes the configured LAN address. Stop closes/joins both entries.

Ready adds `lan_address`, optional `lan_proxy_port` and
`ca_sha256` (SHA-256 of the public CA DER). The reserved HTTP proxy target
`http://lens.invalid/certificate.cer` serves that exact public DER with certificate
MIME/download headers and no-store caching. This bootstrap target bypasses traffic
rules. `http://lens.invalid/` serves a local device setup page with the same
public fingerprint, CA download link and Android/iOS instructions. It confirms
HTTP connectivity, not certificate installation or HTTPS trust. Other paths
return 404. Both routes read only the public certificate; neither reads/serves
the CA private key or accepts
arbitrary filesystem paths. It does not install certificate trust.

This implements the Mac proxy boundary. A Mac client reaching its own LAN address
does not prove physical Wi-Fi reachability or an iOS TLS trust workflow. See
`docs/ios-device-verification.md` for actual execution and environment gaps.

## File-backed HAR sessions

`save_har {path}` and `load_har {path}` accept an explicitly selected absolute
path. Save returns `{path,entries}`; load returns `{path,imported,entries}`. Full
HAR documents and body base64 do not traverse the GUI JSONL pipe on these paths.
The original `export_har` / `import_har` commands remain supported.

Saving freezes the live flow's completion evidence before `flow.copy()` clears
its `live` flag. A worker then serializes copied entries
one at a time into a private mode-0600 stage in the destination directory. It
flushes/fsyncs, then atomically replaces the selected target. Failed serialization
or writing removes only the owned stage and preserves the previous target. Loading
parses and validates all entries in a worker before adding them to the capture
store, using the same 2000-entry / 256 MiB body checks as JSON import. Normal
retention eviction still applies when combining an imported session with captures.
No other directory is enumerated or modified.

The command reader waits for each file command, while the event loop continues
forwarding traffic. Python worker threads cannot be forcibly cancelled: shutdown
joins an in-progress file transaction, which can complete its atomic replacement
before shutdown returns. This is a deliberate completion guarantee; neither a
cancelled command nor shutdown leaves a background stage writer running later.

HAR file and expansion budgets are explicit application resource limits, not HAR
format requirements: files are at most **512 MiB serialized UTF-8**, each wire and
decoded body at most **32 MiB**, aggregate per-side `max(wire,decoded)` body cost
(including WebSocket data) at most **256 MiB**, at most 2000 flows, and aggregate
metadata accounting at most **16 MiB** / nesting at most 32 levels. The standard
library JSON parser is used; input size is checked with `fstat` and a bounded read
before parsing. The 512 MiB file budget bounds input, not total Python memory;
JSON objects and accepted body storage require additional memory. Full parser
peak memory has not been benchmarked.

Before allocating decoded base64 or whole UTF-8 payloads, the shared HAR owner
checks their predicted byte sizes against remaining per-body and aggregate
budgets. Entries are normalized and accounted progressively rather than decoding
an entire flow list before measuring it. Raw gzip/deflate/Brotli/Zstandard
extensions also pass bounded-output decompression checks; small compressed data
cannot request an unbounded decoded allocation. The same bounded content decoder
owns body previews, rewrites and exports. Oversized decoded captures report a
resource error instead of silently presenting an incomplete body as complete.

Save validates each entry under these same budgets and counts actual serialized
bytes before each write; any overrun retains the previous file and removes its
private stage. A capture store near its 256 MiB body ceiling can require more than
512 MiB when HAR text escaping and duplicate wire representations are included;
such a save explicitly fails and leaves the previous target intact. Accepted
self-produced files use the same importer limits. Imported summaries expose
`imported:true`; future network captures expose false, allowing GUI auto-save or
mirror features to distinguish imported evidence from newly observed responses.

Public relay admission is bounded to **256 simultaneous connections in total**
across all enabled listeners. The nominal admission buffer allowance is about
64 MiB (two 64 KiB reader limits plus two roughly 64 KiB writer watermarks per
connection). This is a configuration estimate, not a process-memory ceiling:
reader pause thresholds, Python objects, captured flows and OS buffers add cost.
Admission reserves a slot synchronously before creating the owned connection task.
Excess clients are closed immediately without a queued task or internal dial;
finished/cancelled connections release the slot for retry. Shutdown closes admission
before cancelling those tasks. `network_status` returns `active_connections`,
`max_connections`, `rejected_connections` and current rates. Cumulative rejection
counts are logged to stderr at powers of two to remain visible without log flooding.

Gzip decoding covers all concatenated RFC 1952 members under one output budget;
a later-member expansion cannot bypass it. The pinned Zstandard 0.25.0 bindings
pass `max_window_size` unchanged to the byte-based `ZSTD_DCtx_setMaxWindowSize`,
so the 32 MiB ceiling is passed as **33554432**. The library's prose documentation
incorrectly says KiB. Real positive 4 MiB streaming-window frames and rejected
64 MiB frames, including later concatenated frames, verify the byte boundary;
all frames also share one decoded-output limit. Brotli's bounded-output API requires the explicitly
pinned `Brotli==1.2.0` already present in the runtime lock.

File commands share the serial stdin command reader: network forwarding continues
during worker I/O, while later **control commands wait** until that file command
finishes. No concurrent command pool is created. Shutdown via process signal still
waits for an owned file transaction to finish.

HAR entry extensions `_lensOriginalUrl`, `_lensDnsAddress`, `_lensDialAddress`
preserve original URL and DNS route provenance when present. They count toward the
shared metadata budget and are type checked by the HAR owner on import. The HAR
request URL remains the effective URL. Missing original URL / DNS evidence stays
`null` in summaries rather than being reconstructed from the effective URL.

## HAR observations and compatibility profile

`har_metadata.py` owns timing/cookie interpretation. Both JSONL and file exports
declare the same `_lensProfile`. This is HAR 1.2 with explicit Lens extensions,
not a claim of strict schema conformity for incomplete captures. The
[original HAR text](https://www.softwareishard.com/blog/har-12-spec/) requires
nonnegative send/wait/receive; the author's
[HARViewer schema](https://github.com/janodvarko/harviewer/blob/master/webapp/scripts/preview/harSchema.js)
permits `-1` for those phases, but still requires nonnegative entry time. Lens
uses `-1` for unknown phases **and unknown total time** rather than inventing a
zero or normal completion. Strict consumers may reject such entries.

For ordered observed messages, send is request headers received to its last
byte, wait is that byte to upstream response headers, and receive is upstream
headers to its last byte. These are **proxy receive** intervals, not browser or
proxy-to-origin sending times. Connection establishment can overlap them, so
blocked/DNS/connect/SSL slots remain unknown. `_lensTiming` version 1 retains raw
request/response, client/server connection and error timestamps, explicit nulls,
capture state and overlap notes. A reused connection's setup is not charged to
every request. An early response can make a phase unavailable without invalidating
the capture. Error elapsed time ends at its recorded error; missing normal
response phases remain unknown. Pending/paused snapshots retain unknown total
time, and reopen as historical incomplete records rather than live resumable waits.

Imported source startedDateTime/time/timings, cookie arrays and body metadata
remain source facts. No request-end/response-start observation is inferred from
a source total. Source byte counts can differ from restored compressed bytes;
they are preserved, while Lens raw extensions describe actual retained bytes.
Missing text/raw bytes remain unavailable; explicit `bodySize=0` establishes known
empty wire bytes. Replay, Repeat and body export reject unavailable bytes;
Compose accepts an explicit replacement. Browser page groups/timings are not
imported: a source `pageref` becomes `_lensSourcePageRef` evidence only, without
claiming a relationship to an absent page. Other unsupported document fields
are not promised to survive this request-record import.

Cookie parsing reuses mitmproxy's ordered, case-insensitive attribute parser.
Request cookies provide only name/value; response attributes are included only
when present. Original repeated headers remain intact. Valid Expires is expressed
in UTC; unparsed values retain `_lensAttributes` and an issue, without deriving
an expiry from the import clock. Max-Age remains a raw attribute. SameSite uses
`_sameSite` because HAR 1.2 has no such standard field. Parsed candidates do not
prove acceptance by a browser, cookie store or policy implementation.

Retained source metadata is normalized and measured once at import, including
URL/error/body extensions, and participates in the shared 256 MiB retention budget
across repeated imports. Large integers count their representation expansion
before decimal allocation. Surrogateescaped raw HTTP header bytes remain ASCII
JSON escapes and round-trip through the header owner instead of making an entire
session unsavable; broad native display interoperability for those bytes is not
established by the persistence test.

## Breakpoint deadlines

Request/response breakpoint rules accept `timeout_seconds`: integer 1–3600,
default 60 for old rules. Expiration aborts the request and records
`_lensBreakpointError`; it never silently forwards it. The inspector's wall-clock
deadline is presentation only; `asyncio.timeout` owns expiration with its
monotonic clock and creates no separate waiter task. Continue, Abort, Clear,
hook cancellation and shutdown release the wait. Clear explicitly continues
affected flows and suppresses their subsequent breakpoint rules. Shutdown releases
paused waits before joining relays. A Map Local response does not change a request
breakpoint into a response breakpoint: the hook owns the explicit pause stage.

## Raw TCP forwarding and byte observations

Prepared `initialize.tcp_forwards` is an array of at most 32
`{listen_port,target_host,target_port,listen_port_end?}` entries. The optional end
is an integer defining a closed local interval; target ports increment from the
base by local offset. Missing means one port. Reversed/overlapping ranges, remote
overflow and more than 32 total expanded ports reject before listeners open.
Prepared facts contain each actual endpoint. Public TCP ports must be distinct
from all other listeners. Exact DNS/IP host interpretation is shared with TLS
identity lookup; the original host is separate from canonical `dial_host`.
Each source host is limited to 1024 Unicode code points before IDNA processing.
Forwards bind `127.0.0.1` only. Their direct sockets do not use mitmproxy's protocol
sniffing or TLS interception. Ready contains the prepared endpoint facts.

The existing relay owns both pumps, directional aggregate budgets and admission.
It resolves at most 64 candidate addresses under one 10-second dial deadline,
checks the actual numeric candidates against every owned public/internal TCP
endpoint (including IPv4-mapped IPv6), and dials those candidates without another
DNS lookup. Half-close propagates independently in each direction. Stop cancels
both pumps and retains any failed cleanup owner and its shielded close-waiter
task for retry; late connections after
Stop are closed without starting pumps. Raw TLS/client authentication stays opaque.

`tcp_stream {stream}` emits small summary facts at accept/connect/finalization,
with intermediate byte notifications limited to ten per second per retained
connection. `tcp_removed {id}` reports eviction; `tcp_reset` invalidates a whole session,
including cached pages when a replacement file retains the same stream IDs. Captured bytes count only
after a relay write and drain succeeds: they are local forwarding observations,
not proof of application receipt. Recording is chosen once at accept.

- `tcp_status`: prepared forwards and retained stream summaries.
- `tcp_detail {id,offset:0,limit:32}`: summary plus up to 32 retained chunks with
  direction, timestamp, monotonic sequence, observed size and exact retained
  base64. Chunk boundaries are not application framing. Offset is nonnegative;
  page limit is 1–32. Each source chunk is at most the relay's 4096 bytes.
- `clear_tcp`: release captured bytes/rows without killing forwarding. An evicted
  active observation owner cannot recapture itself into the store.
- `save_tcp {path}`: freeze a snapshot, then atomically save `lens-tcp-streams`
  version 1 in a file worker. Private mode-0600 stages are shared with HAR's I/O
  owner. Failed cleanup retains the held descriptor/inode authority for retry;
  foreign replacement paths are never treated as owned stages. Stop/Quit join
  workers and retry pending stage cleanup before reporting success.
- `load_tcp {path}`: parse/validate the whole file before replacement; requires
  stopped capture. Unsupported/duplicate fields, bad base64/counts, excess budgets
  and malformed later chunks leave the old capture intact. Imported open states
  become historical `incomplete`, preserving `source_state` and unknown end time.
- `--inspect-tcp PATH`: open a file with control stdin only; excludes optional listener,
  LAN, TLS and initialization configuration. The ordinary proxy-port value has
  no listener in this mode. Ready says `capture_stopped:true`, has no ports,
  and is followed by historical TCP rows. No public/internal listeners open.
  No DumpMaster is constructed and no CA/TLS configuration is created.
  A normal prepared launch can instead supply `tcp_session_path` to restore a
  retained file before listeners open.

Bounds are 2000 streams, 4 MiB / 1024 chunks per stream, 32 MiB aggregate
`payload + 512 bytes/chunk` accounting and 96 MiB serialized session input/output.
The extra 512-byte allowance is a conservative guard over the pinned CPython's
305-byte shallow chunk-container estimate, not a process-memory ceiling. Endpoint
and error metadata, allocator/OS buffers, JSON parsing and concurrent frozen file
snapshots add memory. Eviction releases bytes even when the live relay still owns
the stream handle; clipping remains explicit while forwarding/counters continue.
The strict version-1 document rejects unknown fields rather than silently losing
source metadata. TCP records are separate from the HTTP capture/HAR owner.

`network_status` includes live owned `public_listeners` and SDK
`internal_listeners`, along with capacity/rates and `pending_cleanup`.
See [TCP forwarding tests](../tests/test_tcp_forwarding.py) for executable examples.

## Raw UDP forwarding and datagram observations

`initialize.udp_forwards` uses the shared exact endpoint parser with at most 32
`{listen_port,target_host,target_port,listen_port_end?}` entries, using the same
closed-interval/base-offset contract and 32-expanded-port bound. UDP ports must be distinct among
themselves; a TCP listener may share the numeric port. Only `127.0.0.1` binds are
supported. Ready returns `udp_forwards`. Optional `udp_session_path` loads a fully
validated historical snapshot before admission starts.

`UDPRelays` owns one listener socket and one connected upstream socket per
listener/client association. It rejects resolved self-targets (including actual
internal SDK UDP endpoints), resolves at most 64 candidates within 10 seconds,
and expires associations after 30 seconds without pending work. Connected remote
sockets filter replies. Empty datagrams survive both directions. UDP payloads
share the existing upload/download budgets without splitting packet boundaries.

Bounds: 256 active associations, 32 queued datagrams per association, aggregate
1024 queued datagrams / 4 MiB queued payload. In-flight buffers are additional.
Owned socket send/receive buffers request 128 KiB. Queue rejection and discarded
pending payload on cleanup count known local drops; they do not measure network
loss. Stop/startup rollback closes both TCP and UDP owners even when one fails;
late DNS and failed cleanup retain their owner/finalizer for retry.

`udp_association {association}` emits summary facts, coalescing active updates
at about 100 ms and flushing final bursts. `udp_removed {id}` reports eviction;
`udp_reset` invalidates all rows and same-ID cached detail pages.

- `udp_status`: prepared forwards, retained summaries and live network ownership.
- `udp_detail {id,offset:0,limit:32}`: association, total and up to 32 whole
  `datagrams`, each with direction, timestamp, sequence, observed_bytes and Base64.
- `clear_udp`: release retained rows/bytes; live handles cannot resurrect them.
- `save_udp {path}`: freeze and atomically save `lens-udp-datagrams` version 1
  using the shared file worker/stage cleanup authority.
- `load_udp {path}`: stopped only; validate the entire file before replacement.
  Historical unfinished states become `incomplete` with source_state/unknown end.
- `--inspect-udp PATH`: control/file-only launch; mutually exclusive with TCP file
  mode, initialization and optional listener/TLS flags. It constructs no
  DumpMaster, opens no listeners and creates no CA. Capture configure is rejected.
- `network_status.udp`: active capacity, queued count/bytes, local drop counts,
  pending cleanup and listener receiving/error facts.

Retention is independent of HTTP/TCP: 2000 rows, 4 MiB / 1024 whole datagrams per
association, 32 MiB aggregate payload plus 512 B per retained datagram, including
empty. Capture only observes successful local forwarding. Clipping never retains
a prefix and forwarding continues. Files are capped at 96 MiB serialized; strict
Base64/count/endpoint/field validation rejects malformed later data atomically.
Recording is selected at association creation. These budgets do not bound total
RSS, socket buffers, JSON parsing or concurrent frozen snapshots.
See [UDP forwarding tests](../tests/test_udp_forwarding.py).

## Observed public client connection

HTTP summaries/details include nullable `client_connection`. A recorded value is
`{version:1,id,listener,peer:[IP,port],listener_address:[IP,port],accepted_at}`.
`id` is a generated connection correlation ID, not a process/device identifier.
Listener kinds are `proxy_port`, `lan_proxy_port`, `socks_port`, `reverse_port`.
The accepted timestamp is the relay callback's wall clock, not a handshake/dial
duration. Existing proxy-receive timing facts retain their separate boundary.

The relay owns the original public peer/local endpoints. After its private dial
connects, a bounded lease associates that outgoing socket pair with those facts.
At SDK `ClientConnected`, Lens freezes the private pair before protocol processing;
request headers resolve that frozen key through the owned lease. Later mutations
to SDK connection fields or forwarded headers never reinterpret peer identity.
Both indexes are bounded by the existing 256-connection admission limit. A
missing/ambiguous association remains null. Disconnect/Stop releases indexes;
retained request facts are independent immutable copies. `network_status` reports
`client_bindings` / `client_observations` counts for cleanup verification.

HAR `_lensClientConnection` is versioned, type/budget checked before atomic import
and copied into the capture owner. Original IP spelling and extra budget-admitted
extension metadata are preserved. Missing versus explicit null remain distinct
in HAR; neither is rebuilt from the SDK's internal loopback connection. Live
metadata participates in retention accounting. Export/snapshot callers do not
share mutable provenance containers with live captures. See
[client-connection tests](../tests/test_client_connection.py).

## Opt-in host client process

Prepared `initialize.client_process` must be a boolean (default false).
`ready.client_process` reports the selected mode. It cannot change during a run;
the native preference is saved without modifying process identity already in
captures. The packaged app includes `Resources/peer-process-identities`, built
from the unchanged shared REA start-identity reader and a restricted PID-only
entry point. An unbundled source engine without that sibling helper reports
lookup unavailable; it does not discover or execute a replacement on PATH.

For the HTTP, LAN, SOCKS and reverse frontends, lookup runs before the internal
dial and forwarding. A 1.5-second deadline includes the two-slot query queue;
the existing 256-connection admission bounds queued owners. Two bounded NUL-field
`lsof` observations must match the accepted socket's held descriptor and inverse
client tuple, a unique visible client PID, and matching REA process start identities
around the second socket observation. Names are kernel short names, not argv or
executable/application identities. Missing permissions/visibility, ambiguity,
changed ownership and deadline expiry produce explicit unknown facts.

The optional nested `client_connection.process` / HAR extension field is
`{version:1,state,scope:"host_tcp_socket",observed_at,...}`. Identified state adds
`pid,start_identity,name,name_bytes_base64,socket_descriptor,method` with method
`lsof+rea-start-identity`. UTF-8 names retain source spelling; invalid UTF-8 uses
Base64 bytes instead. Unknown state has a fixed reason and no claimed identity.
The owning import parser validates it before atomic HAR adoption; absent and
explicit null remain distinct in exported source evidence.

Subprocess creation, pipes, shielded exit waiters and cleanup are retained by one
owner. Lookup expiry/cancellation terminates only owned helper objects; cleanup
may add a one-second launch wait, 0.25-second exit grace, one-second kill/exit wait
and one-second pipe-finalization wait. Failed cleanup retains ownership and
blocks further helpers until Stop retry. Stop cancels/join relays before final
helper cleanup; `network_status.process_lookup_children` exposes outstanding
owners. No ambient environment, process memory, client executable bytes or
transport credentials are captured. Physical device apps, raw TCP streams and
excluded TLS without decrypted requests have no process-level HTTP record.
See [process attribution tests](../tests/test_peer_process.py).

## HTTP URL Block / Allow Lists

`initialize.access_policy` and `configure.access_policy` accept strict selections
`{block_enabled:bool,allow_enabled:bool,block:[str],allow:[str],action:"respond"|"close"}`.
Omitted fields default off/empty/respond; omitted live configure field retains the
current policy. Explicit null and unknown fields fail before committing settings.
`access_policy_status` returns an independent original selection. Lists are capped
at 500 patterns each, 4096 Unicode code points each, nonempty/no NUL/CR/LF.

`access_policy.py` owns immutable/precompiled policy and historical decision parsing.
Each request captures one snapshot. Block takes precedence; Allow enabled with an
empty list denies all. Original and each mapped URL must pass before forwarding.
Denial is terminal across request and response rules. `close` kills the request:
HTTP/1 receives no response; HTTP/2 resets the affected stream. The CA bootstrap
is exempt; opaque CONNECT and raw TCP/UDP remain outside scope.

`summary.access_decision` is null or `{reason,action,matched_url,pattern}`;
HAR `_lensAccessDecision` is absent when no denial was recorded. `block_match`
requires its actual matching pattern; `allow_miss` requires null. Strict historical
validation does not reinterpret it under current policy. Native overview consumes
these facts, and stopped-session persistence retains them. Missing does not imply
allowed. See [Access List tests](../tests/test_access_lists.py).

## Atomic breakpoint message edits

Every paused flow emits a fresh `pause_id` and `pause_stage`. Use
`resume {id,pause_id,stage,action}` with `action:continue` plus exactly one optional
patch: `request_edit {method?,url?,headers?,body_base64?}` or
`response_edit {status_code?,reason?,headers?,body_base64?}`. New patch commands
require the current identity and matching stage. Headers are a full replacement
array of `[name,value]` pairs, preserving duplicates/order, limited to 1024 rows
and 64 KiB including separators. Host, Content-Length and Transfer-Encoding are
managed; do not supply them. URL input is an absolute HTTP(S) URI, at most 64 KiB,
without userinfo/fragment; percent-encode non-ASCII path/query text. An explicit
URL's exact input survives as `_lensBreakpointUrl` separately from normalized
routing. Edited destinations still pass the request's original access policy.

`body_base64` contains decoded replacement bytes (empty string explicitly empties
it), bounded to 32 MiB before Base64 allocation; encoded output is also bounded.
Omitted fields preserve source facts and untouched bodies preserve exact wire
bytes. Changed Content-Encoding strictly decodes/re-encodes using the shared
bounded decoder; malformed/unknown/incomplete encodings fail without applying
any part of the patch. Gzip strict editing also rejects trailing zero padding.
Status is an integer 200–599; CONNECT transitions and 1xx switching are outside
this patch contract. 204/304 and ordinary HEAD body restrictions are enforced.
Framing changes on messages with trailers fail explicitly; reason/method/URL-only
edits or unchanged continuation preserve them.

`action:discard` ignores drafts and resumes unchanged. `action:abort` cancels the
owned pause. Invalid edits and stale identities leave the active pause intact.
Legacy `request_body`/`response_body` UTF-8 commands remain supported through the
same preparation owner, mutually exclusive with new patches. Preparation validates
on a copy; the bridge applies exactly one prepared replacement before resuming.

Method edits retain `_lensFrontendMethod`. An empty effective HEAD response to an
original non-HEAD client gets length zero, preserving prior source framing in
`_lensMethodFraming` (frontend/effective methods and source Content-Length /
Transfer-Encoding arrays). These are observed pre-normalization facts, not proof
of upstream execution. Nonempty synthetic responses and unknown bodies are not
misclassified as empty. An original HEAD client receives no DATA/trailers even
when the edited method obtained a body; capture/HAR keep those bytes. The adapter
operates only at frontend serialization, per HTTP/2 stream. Framing failures abort
at the flow owner because the SDK swallows ordinary addon exceptions.

Breakpoint regressions are available in
[the executable test suite](../tests/test_breakpoint_editing.py).

## Source-bound Compose and outgoing identity

`compose {source_id?,source_fingerprint?,request_edit:{method?,url?,headers?,body_base64?}}`
queues a separate request. With a source, omitted fields and body keep the complete
retained source message; its inspector preview is never a body input. Without a
source, supply an absolute HTTP(S) URL; defaults are GET/empty body. New patches
share `message_edit.prepare_request_edit` with breakpoints. Unknown/unavailable
sources fail before queueing unless a known source's unavailable body is explicitly
replaced. Missing headers are not treated as an empty source selection.

`detail.request_fingerprint` identifies exact method/URL/version/header/trailer
and raw-body/availability facts, excluding connection state and response changes.
It is computed incrementally from complete bytes, without Base64/body copies.
Native source-based drafts send it as `source_fingerprint`; a mismatch rejects
before any work is admitted. Direct source-ID-only callers intentionally select
the current request at queue time. A fingerprint without a source is invalid.
Snapshots contain immutable strings/bytes/header tuples and survive source Clear
or eviction after queue acceptance. The legacy `{method,url,headers,body}` text
form is retained through the same owner, mutually exclusive with the new form.

`{queued:true}` acknowledges admission, not successful delivery. A later
`request_finished` or `request_failed` shares command_id and a nullable `flow_id`
(only when that record is still retained). Each observed generated request has
`request_operation {kind,id,source_id,url_input,attempt}`; HAR uses
`_lensRequestOperation`. Kinds are compose/replay/repeat. Repeat uses job id and
1-based attempt; other attempts are null. New Compose may have null source;
explicit Compose URL input is retained separately from canonical routing. Missing
facts stay absent. The historical `replayed` boolean continues marking internally
generated traffic for compatibility; native labels use the explicit kind.

Generated requests use one HTTP/1.1 transport through this engine's local proxy,
with h11 framing and existing relay cleanup ownership. HTTP absolute targets and
HTTPS CONNECT keep IPv6 brackets; actual method token case and non-ASCII header
bytes are preserved. Strict TLS, current rules/access lists and recording remain
in effect. The pinned SDK's uppercase method getter is not an observation source;
`http_method.request_method` owns its raw RequestData token. Host/Content-Length and
hop-by-hop fields (including Connection nominees and proxy authentication) are
rebuilt; origin Authorization remains a source field. CONNECT as a new ordinary
request, outgoing request trailers and 101 switching are rejected/unsupported.
Generated clients do not negotiate HTTP/2 or follow redirects; an H2 source can
be copied as an HTTP/1.1 request. The existing SDK has further case-insensitive
HEAD/CONNECT semantics; preserving custom method bytes is not proof that every
nonstandard case variant has equivalent semantics.

Outgoing response parsing retains at most 64 KiB of unfinished headers and admits
complete headers/trailers to the same budget; actual body consumption is bounded
to 32 MiB. It streams/discards response bytes while capture remains owned by the
proxy. The complete send has a 120-second deadline. An owned pending token is
created inside the coroutine before its first await, binds at most one flow, and
is released in finally; cancellation before entry creates no provisional owner.
`network.close_streams` retains failed stream/waiter cleanup for Stop retry.
The per-instance authenticated token proves ownership independently of that
pending lifetime. Late or reused owned tokens are stripped and terminated before
rule selection; foreign same-named fields remain ordinary caller data. No expired
token history is retained. See [outgoing identity tests](../tests/test_outgoing_identity.py).

Stop/Quit close admissions and active relays, cancel/join owned outgoing work,
then recheck network cleanup after its finalizers. Late failed writer closes
therefore prevent a successful Stop, retain their original owner, and are retried
by the next Stop. A cancelled final close keeps its shielded waiter. While
network admission is closed, Compose/Replay/Repeat/Resume remain unavailable even
if a failed Stop has not reached the completed capture-stopped state.
