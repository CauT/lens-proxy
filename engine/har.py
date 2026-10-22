"""HAR 1.2 decoded content, with Lens extensions for exact wire-byte restoration."""
import base64
import copy
import ipaddress
import websocket_capture
from rewrite import parse_error as parse_rewrite_error
from urllib.parse import parse_qsl, urlsplit
from mitmproxy import connection, http
from bounds import ImportBudget, message_content, STORE_BYTES, metadata_size, METADATA_BYTES
from har_metadata import export_timing, export_cookies, read_metadata
from har_metadata import capture_timing
from client_connection import import_client_connection
from access_policy import import_decision
from http_urls import request_url, prepare_url
from http_method import parse_method, import_framing, request_method
from outgoing import import_operation
from har_request import (export_request_facts, restore_request_facts,
                         restore_legacy_request, request_facts_metadata_size)


def displayed_request_url(flow):
    # Legacy HAR supplies a URL, not independently observed routing fields.
    # Preserve that selected source text when SDK rendering would change it.
    return flow.metadata.get("lens_har_request_url", request_url(flow.request, pretty=True))


def request_target_source(flow):
    if not flow.metadata.get("imported", False):
        return "capture"
    return "har_facts" if flow.metadata.get("lens_har_request_facts", False) else "har_url"


def snapshot_flow(flow):
    """Freeze completion before HTTPFlow.copy() deliberately clears live state."""
    snapshot = flow.copy()
    websocket_capture.preserve_copy(flow, snapshot)
    if "lens_har_fields" not in flow.metadata:
        snapshot.metadata["lens_har_timing"] = capture_timing(flow)
    return snapshot


def headers(items):
    return [{"name": k, "value": v} for k, v in items]


def body_fields(decoded):
    """HAR text is decoded from Content-Encoding; binary uses base64 transport."""
    try:
        return {"text": decoded.decode("utf-8", "strict")}
    except UnicodeDecodeError:
        return {"text": base64.b64encode(decoded).decode(), "encoding": "base64"}


def export_flow(flow):
    req, res = flow.request, flow.response
    display_url = displayed_request_url(flow)
    request = {"method": request_method(req), "url": display_url, "httpVersion": req.http_version,
               "headers": headers(req.headers.items(multi=True)),
               "queryString": headers(parse_qsl(urlsplit(display_url).query, keep_blank_values=True)),
               "headersSize": -1, "bodySize": len(req.raw_content) if req.raw_content is not None else -1}
    if req.raw_content:
        request["postData"] = {"mimeType": req.headers.get("content-type", ""),
                               **body_fields(message_content(req))}
    raw = (res.raw_content or b"") if res else b""
    decoded = message_content(res) if res else b""
    response = {"status": res.status_code if res else 0, "statusText": res.reason if res else "",
                "httpVersion": res.http_version if res else "",
                "headers": headers(res.headers.items(multi=True)) if res else [],
                "content": {"size": len(decoded), "mimeType": res.headers.get("content-type", "") if res else "",
                            "compression": len(decoded) - len(raw), **body_fields(decoded)},
                "redirectURL": res.headers.get("location", "") if res else "", "headersSize": -1,
                "bodySize": len(raw)}
    if res is not None and res.raw_content is None:
        response["bodySize"] = -1
        response["content"] = {"size": -1, "mimeType": res.headers.get("content-type", "")}
    source_bodies = flow.metadata.get("lens_har_body_fields")
    if source_bodies is not None:
        for side, target, message, field in (("request", request, req, "postData"),
                                              ("response", response, res, "content")):
            source = source_bodies[side]
            for key in ("headersSize", "bodySize"):
                if key in source["sizes"]:
                    target[key] = source["sizes"][key]
                else:
                    target.pop(key, None)
            if source["present"]:
                value = copy.deepcopy(source["description"])
                if source["text_present"]:
                    data = message_content(message) if message else b""
                    if value.get("encoding") == "base64":
                        value["text"] = base64.b64encode(data).decode()
                    else:
                        value.update(body_fields(data))
                target[field] = value
            else:
                target.pop(field, None)
    for side, message in (("request", request), ("response", response)):
        cookies = export_cookies(flow, side)
        if cookies is not None:
            message["cookies"] = cookies
    result = {**export_timing(flow), "request": request, "response": response,
              "_lensError": flow.error.msg if flow.error else None}
    if request_target_source(flow) != "har_url":
        result["_lensRequestFacts"] = export_request_facts(req)
    if req.raw_content is not None:
        result["_lensRawRequestBody"] = base64.b64encode(req.raw_content).decode()
    if res is None or res.raw_content is not None:
        result["_lensRawResponseBody"] = base64.b64encode(raw).decode()
    for key, extension in (("lens_original_url", "_lensOriginalUrl"),
                           ("lens_breakpoint_url", "_lensBreakpointUrl"),
                           ("lens_dns_address", "_lensDnsAddress"),
                           ("lens_dns_dial_address", "_lensDialAddress"),
                           ("lens_breakpoint_error", "_lensBreakpointError"),
                           ("lens_rewrite_error", "_lensRewriteError")):
        if key in flow.metadata and flow.metadata[key] is not None:
            result[extension] = copy.deepcopy(flow.metadata[key])
    if "lens_request_operation" in flow.metadata:
        result["_lensRequestOperation"] = import_operation(flow.metadata["lens_request_operation"])
    if "lens_frontend_method" in flow.metadata:
        result["_lensFrontendMethod"] = parse_method(flow.metadata["lens_frontend_method"])
    if "lens_method_framing" in flow.metadata:
        result["_lensMethodFraming"] = import_framing(flow.metadata["lens_method_framing"])
    if "lens_access_decision" in flow.metadata:
        result["_lensAccessDecision"] = import_decision(flow.metadata["lens_access_decision"])
    if "lens_client_connection" in flow.metadata:
        result["_lensClientConnection"] = copy.deepcopy(flow.metadata["lens_client_connection"])
    result.update(websocket_capture.export(flow))
    return result


def import_headers(source):
    return http.Headers([(h["name"].encode("utf-8", "surrogateescape"),
                          h["value"].encode("utf-8", "surrogateescape")) for h in source])


def restore_body(message, prepared):
    if not prepared.available:
        message.raw_content = None
    elif prepared.raw is not None:
        message.raw_content = prepared.raw
    elif not prepared.fields["text_present"]:
        message.raw_content = b""  # An explicit wire bodySize=0 establishes empty bytes.
    else:
        message.content = prepared.decoded


def import_entry(entry, prepared=None):
    local_budget = None
    if prepared is None:
        local_budget = ImportBudget(1, STORE_BYTES)
        prepared = local_budget.prepare(entry)
    req, res = entry["request"], entry["response"]
    start, source_fields, source_cookies, timing = read_metadata(entry)
    request_headers = import_headers(req.get("headers", []))
    has_facts = "_lensRequestFacts" in entry
    request = (restore_request_facts(entry["_lensRequestFacts"], req, request_headers, start) if has_facts else
               restore_legacy_request(req, request_headers, start))
    flow = http.HTTPFlow(connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0)),
                         connection.Server(address=(request.host, request.port)))
    flow.request = request
    flow.metadata["lens_har_request_facts"] = has_facts
    if not has_facts and req["url"] != request_url(request, pretty=True):
        flow.metadata["lens_har_request_url"] = req["url"]
    restore_body(flow.request, prepared["request"])
    flow.request.timestamp_start = start
    flow.request.timestamp_end = None
    if res.get("status", 0) > 0:
        flow.response = http.Response.make(res["status"], b"")
        flow.response.headers = import_headers(res.get("headers", []))
        restore_body(flow.response, prepared["response"])
        flow.response.http_version = res.get("httpVersion") or "HTTP/1.1"
        flow.response.reason = res.get("statusText", "")
        flow.response.timestamp_start = start
        flow.response.timestamp_end = start + entry["time"] / 1000 if entry["time"] >= 0 else None
    if "_lensError" in entry and entry["_lensError"] is not None and not isinstance(entry["_lensError"], str):
        raise ValueError("Lens error must be a string or null")
    if entry.get("_lensError") is not None:
        from mitmproxy.flow import Error
        flow.error = Error(entry["_lensError"])
    flow.metadata["lens_har_fields"] = source_fields
    flow.metadata["lens_har_cookies"] = source_cookies
    flow.metadata["lens_har_body_fields"] = {side: prepared[side].fields for side in ("request", "response")}
    if timing is not None:
        if (timing["response"] is not None) != (flow.response is not None):
            raise ValueError("_lensTiming response presence conflicts with HAR status")
        if (timing["error"] is not None) != (flow.error is not None):
            raise ValueError("_lensTiming error presence conflicts with _lensError")
        if timing["state"] == "error" and flow.error is None:
            raise ValueError("Error _lensTiming needs a captured error")
        if timing["state"] == "complete" and (flow.response is None or timing["response"]["end"] is None):
            raise ValueError("Completed _lensTiming needs a response end")
        flow.metadata["lens_har_timing"] = timing
        flow.request.timestamp_start = timing["request"]["start"]
        flow.request.timestamp_end = timing["request"]["end"]
        if flow.response:
            flow.response.timestamp_start = timing["response"]["start"]
            flow.response.timestamp_end = timing["response"]["end"]
        if flow.error:
            flow.error.timestamp = timing["error"]["timestamp"]
        for key, conn in (("clientConnection", flow.client_conn), ("serverConnection", flow.server_conn)):
            for field, value in timing[key].items():
                if field != "timestamp_tcp_setup" or key == "serverConnection":
                    setattr(conn, field, value)
    if "_lensBreakpointError" in entry:
        if not isinstance(entry["_lensBreakpointError"], str):
            raise ValueError("Lens breakpoint error must be a string")
        if flow.error is None:
            raise ValueError("Lens breakpoint error needs a captured error")
        flow.metadata["lens_breakpoint_error"] = entry["_lensBreakpointError"]
    if "_lensRewriteError" in entry:
        reason = parse_rewrite_error(entry["_lensRewriteError"])
        if flow.error is None:
            raise ValueError("Lens rewrite error needs a captured error")
        flow.metadata["lens_rewrite_error"] = reason
    if "_lensOriginalUrl" in entry:
        if not isinstance(entry["_lensOriginalUrl"], str):
            raise ValueError("Lens original URL must be a string")
        flow.metadata["lens_original_url"] = entry["_lensOriginalUrl"]
    if "_lensBreakpointUrl" in entry:
        prepare_url(entry["_lensBreakpointUrl"])
        flow.metadata["lens_breakpoint_url"] = entry["_lensBreakpointUrl"]
    if "_lensRequestOperation" in entry:
        flow.metadata["lens_request_operation"] = import_operation(entry["_lensRequestOperation"])
        flow.metadata["lens_replayed"] = True
    if "_lensFrontendMethod" in entry:
        flow.metadata["lens_frontend_method"] = parse_method(entry["_lensFrontendMethod"])
    if "_lensMethodFraming" in entry:
        facts = import_framing(entry["_lensMethodFraming"])
        if (facts["frontend_method"] != flow.metadata.get("lens_frontend_method") or flow.request.method != "HEAD"
                or flow.response is None or flow.response.raw_content != b""
                or flow.response.headers.get_all("content-length") != ["0"] or "transfer-encoding" in flow.response.headers):
            raise ValueError("Edited-method framing contradicts the captured request/response")
        flow.metadata["lens_method_framing"] = facts
    if "_lensDnsAddress" in entry:
        if not isinstance(entry["_lensDnsAddress"], str):
            raise ValueError("Lens DNS address must be an IP literal string")
        ipaddress.ip_address(entry["_lensDnsAddress"])
        flow.metadata["lens_dns_address"] = entry["_lensDnsAddress"]
    if "_lensDialAddress" in entry:
        address = entry["_lensDialAddress"]
        if (not isinstance(address, list) or len(address) != 2 or not isinstance(address[0], str)
                or type(address[1]) is not int or not 1 <= address[1] <= 65535):
            raise ValueError("Lens dial address must be [IP literal, port]")
        ipaddress.ip_address(address[0])
        flow.metadata["lens_dns_dial_address"] = address
    if "_lensAccessDecision" in entry:
        decision = import_decision(entry["_lensAccessDecision"])
        if decision["matched_url"] not in (flow.metadata.get("lens_original_url", request_url(flow.request, pretty=True)), request_url(flow.request, pretty=True)):
            raise ValueError("Lens access decision URL must name this request's original or effective URL")
        if decision["action"] == "respond" and (flow.response is None or flow.response.status_code != 403):
            raise ValueError("Lens access response decision requires its captured HTTP 403")
        if decision["action"] == "close" and flow.error is None:
            raise ValueError("Lens access abort decision requires its captured error")
        flow.metadata["lens_access_decision"] = decision
    if "_lensClientConnection" in entry:
        flow.metadata["lens_client_connection"] = import_client_connection(entry["_lensClientConnection"])
    flow.metadata["imported"] = True
    flow.live = False
    websocket_capture.restore(flow, prepared["websocket"])
    if local_budget:
        local_budget.account_encoded(flow, prepared)
    # Count all retained normalized provenance once, including URL/error
    # extensions. Repeated imports then share the same retention ceiling.
    flow.metadata["lens_har_metadata_bytes"] = 0
    facts_cost = request_facts_metadata_size(flow.request)
    flow.metadata["lens_har_metadata_bytes"] = metadata_size(flow.metadata, METADATA_BYTES - facts_cost) + facts_cost
    return flow
