"""Own HAR timing/cookie facts without inventing missing capture observations.

Lens uses an explicitly documented HAR compatibility profile: -1 means unknown
even for required timing slots (and entry time for unfinished captures). Raw
timestamps describe the proxy's receive boundary, not browser/outbound timings.
"""
import copy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math


TIMING_KEYS = ("blocked", "dns", "connect", "ssl", "send", "wait", "receive")
STANDARD_FIELDS = ("startedDateTime", "time", "timings", "cache", "_lensSourcePageRef",
                   "serverIPAddress", "connection", "comment")
CONNECTION_TIMES = ("timestamp_start", "timestamp_tcp_setup", "timestamp_tls_setup", "timestamp_end")
TIMING_COMMENT = ("Lens proxy observations: send is request headers-received to last-byte-received; "
                  "wait is request last-byte to upstream response headers; receive is upstream response "
                  "headers to last byte. These are not browser/outbound timings. -1 is unknown. "
                  "Connection setup can overlap these intervals and is retained only in _lensTiming.")


def document_metadata():
    return {"version": "1.2", "creator": {"name": "Lens", "version": "0.1.0"},
            "_lensProfile": {"version": 1, "unknownTime": -1, "timingBoundary": "proxy-receive",
                             "entryScope": "merged-request-records"}}


def number(value, label, minimum=None, nullable=False):
    if nullable and value is None:
        return None
    try:
        finite = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{label} must be a finite number" + (" or null" if nullable else ""))
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return value


def date_timestamp(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
        if parsed.utcoffset() is None:
            raise ValueError("missing timezone")
        return number(parsed.timestamp(), label)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError(f"{label} must contain a valid timezone-aware ISO 8601 date") from exc


def interval(start, end):
    return (end - start) * 1000 if start is not None and end is not None and end >= start else -1


def duration_number(value, label):
    number(value, label, minimum=-1)
    if value < 0 and value != -1:
        raise ValueError(f"{label} must be nonnegative or -1 (unknown)")


def flow_state(flow):
    if flow.intercepted:
        return "paused"
    if flow.error:
        return "error"
    saved = flow.metadata.get("lens_har_timing")
    if saved:
        return "complete" if saved["state"] == "complete" else "pending"
    source = flow.metadata.get("lens_har_fields")
    if source is not None and source["time"] == -1:
        return "pending"
    if flow.response is not None and (not flow.live or flow.metadata.get("lens_response_complete", False)):
        return "complete"
    return "pending"


def uses_live_connection_timing(flow):
    """Imported timing fields are frozen source facts, not live SDK sockets."""
    return flow.metadata.get("lens_har_fields") is None and flow.metadata.get("lens_har_timing") is None


def capture_timing(flow):
    saved = flow.metadata.get("lens_har_timing")
    if saved is not None:
        return copy.deepcopy(saved)
    def message_times(message):
        return {"start": message.timestamp_start, "end": message.timestamp_end} if message else None
    def connection_times(conn):
        return {key: getattr(conn, key, None) for key in CONNECTION_TIMES}
    timing = {"version": 1, "state": flow_state(flow), "request": message_times(flow.request),
            "response": message_times(flow.response),
            "error": {"timestamp": flow.error.timestamp} if flow.error else None,
            "clientConnection": connection_times(flow.client_conn),
            "serverConnection": connection_times(flow.server_conn)}
    if flow.response and flow.request.timestamp_end is not None and flow.response.timestamp_start < flow.request.timestamp_end:
        timing["issues"] = ["Response headers precede the last request byte; request/response intervals overlap."]
    return validate_capture_timing(timing)


def flow_duration(flow):
    source = flow.metadata.get("lens_har_fields")
    if source is not None:
        return source["time"] if source["time"] >= 0 else None
    state = flow_state(flow)
    end = flow.error.timestamp if flow.error else flow.response.timestamp_end if flow.response else None
    value = interval(flow.request.timestamp_start, end) if state in ("complete", "error") else -1
    return value if value >= 0 else None


def export_timing(flow):
    source = flow.metadata.get("lens_har_fields")
    if source is not None:
        # Source timing slots/cookies are observations in their own right. Do not
        # reconstitute them from synthetic HTTPFlow timestamps on the next save.
        result = copy.deepcopy(source)
        if "lens_har_timing" in flow.metadata:
            result["_lensTiming"] = capture_timing(flow)
        return result
    timing = capture_timing(flow)
    request, response = timing["request"], timing["response"]
    duration = flow_duration(flow)
    return {"startedDateTime": datetime.fromtimestamp(request["start"], timezone.utc).isoformat(),
            "time": duration if duration is not None else -1,
            "timings": {"blocked": -1, "dns": -1, "connect": -1, "ssl": -1,
                        "send": interval(request["start"], request["end"]),
                        "wait": interval(request["end"], response["start"]) if response else -1,
                        "receive": interval(response["start"], response["end"]) if response else -1,
                        "comment": TIMING_COMMENT}, "cache": {}, "_lensTiming": timing}


def validate_capture_timing(value):
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("Unsupported _lensTiming version")
    if value.get("state") not in ("pending", "paused", "complete", "error"):
        raise ValueError("Invalid _lensTiming state")
    for key in ("request", "response"):
        times = value.get(key)
        if times is None and key == "response":
            continue
        if not isinstance(times, dict) or set(times) != {"start", "end"}:
            raise ValueError(f"_lensTiming.{key} must contain start/end")
        number(times["start"], f"_lensTiming.{key}.start")
        number(times["end"], f"_lensTiming.{key}.end", nullable=True)
    error = value.get("error")
    if error is not None:
        if not isinstance(error, dict) or set(error) != {"timestamp"}:
            raise ValueError("_lensTiming.error must contain timestamp")
        number(error["timestamp"], "_lensTiming.error.timestamp")
    for key in ("clientConnection", "serverConnection"):
        times = value.get(key)
        if not isinstance(times, dict) or set(times) != set(CONNECTION_TIMES):
            raise ValueError(f"_lensTiming.{key} must contain connection timestamps")
        for field in CONNECTION_TIMES:
            number(times[field], f"_lensTiming.{key}.{field}", nullable=True)
    return copy.deepcopy(value)


def read_metadata(entry):
    """Validate once at import; keep source omissions and original field values."""
    start = date_timestamp(entry["startedDateTime"], "startedDateTime")
    duration_number(entry["time"], "HAR time")
    if not isinstance(entry.get("timings"), dict):
        raise ValueError("HAR timings must be an object")
    for key in TIMING_KEYS:
        if key in entry["timings"]:
            duration_number(entry["timings"][key], f"HAR timings.{key}")
    if "comment" in entry["timings"] and not isinstance(entry["timings"]["comment"], str):
        raise ValueError("HAR timings.comment must be a string")
    for key in ("pageref", "_lensSourcePageRef", "serverIPAddress", "connection", "comment"):
        if key in entry and not isinstance(entry[key], str):
            raise ValueError(f"HAR {key} must be a string")
    if "cache" in entry and not isinstance(entry["cache"], dict):
        raise ValueError("HAR cache must be an object")
    result = {key: copy.deepcopy(entry[key]) for key in STANDARD_FIELDS if key in entry}
    if "pageref" in entry:
        if "_lensSourcePageRef" in entry and entry["pageref"] != entry["_lensSourcePageRef"]:
            raise ValueError("Conflicting source HAR page references")
        # Lens merges request records, not browser-page groups. Keep the original
        # reference as source evidence, without publishing a dangling graph edge.
        result["_lensSourcePageRef"] = entry["pageref"]
    cookies = {}
    for side in ("request", "response"):
        if "cookies" not in entry[side]:
            continue
        values = entry[side]["cookies"]
        if not isinstance(values, list):
            raise ValueError(f"HAR {side}.cookies must be an array")
        for cookie in values:
            if not isinstance(cookie, dict) or not all(isinstance(cookie.get(key), str) for key in ("name", "value")):
                raise ValueError(f"HAR {side} cookies must contain string name/value")
            for key in ("path", "domain", "expires", "comment"):
                if key in cookie and not isinstance(cookie[key], str):
                    raise ValueError(f"HAR cookie {key} must be a string")
            for key in ("httpOnly", "secure"):
                if key in cookie and type(cookie[key]) is not bool:
                    raise ValueError(f"HAR cookie {key} must be a boolean")
        cookies[side] = copy.deepcopy(values)
    timing = validate_capture_timing(entry["_lensTiming"]) if "_lensTiming" in entry else None
    return start, result, cookies, timing


def export_cookies(flow, side):
    source = flow.metadata.get("lens_har_cookies", {})
    if side in source:
        return copy.deepcopy(source[side])
    if "lens_har_fields" in flow.metadata:
        return None  # Omitted in the source is distinct from an observed empty array.
    message = getattr(flow, side)
    if message is None:
        return []
    if side == "request":
        return [{"name": name, "value": value} for name, value in message.cookies.items(multi=True)]
    result = []
    for name, (value, attrs) in message.cookies.items(multi=True):
        cookie = {"name": name, "value": value, "httpOnly": "httponly" in attrs, "secure": "secure" in attrs,
                  "_lensAttributes": [{"name": k, "value": v} for k, v in attrs.items(multi=True)]}
        for key in ("path", "domain"):
            if attrs.get(key) is not None:
                cookie[key] = attrs[key]
        if attrs.get("samesite") is not None:
            cookie["_sameSite"] = attrs["samesite"]
        if attrs.get("expires") is not None:
            try:
                expires = parsedate_to_datetime(attrs["expires"])
                if expires.utcoffset() is not None:
                    cookie["expires"] = expires.astimezone(timezone.utc).isoformat()
                else:
                    cookie["_lensCookieIssues"] = ["Expires has no timezone; original attribute retained."]
            except (ValueError, TypeError, OverflowError):
                cookie["_lensCookieIssues"] = ["Unparsed Expires; original attribute retained."]
        result.append(cookie)
    return result
