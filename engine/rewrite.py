"""Immutable text rewrite actions; byte admission precedes growing allocations.

HTTP field validity and message codec/framing belong to the shared owners. Query
matching decodes selected parameter keys/values; untouched target bytes are never normalized.
"""
from dataclasses import dataclass
from urllib.parse import quote_from_bytes, unquote_to_bytes

from mitmproxy import http
from rewrite_text import TextRewrite, Deadline, boolean
from bounds import BODY_BYTES, METADATA_BYTES, decoded_bytes, text_size
from http_headers import HEADER_BYTES, MAX_HEADERS, prepare_headers, validate_header_field, wire_text
from http_urls import URL_BYTES, request_url
from message_edit import (PreparedEdit, content_encoding, prepare_body_replacement,
                          prepare_header_fields, prepare_request_edit, prepare_response_edit)


REWRITE_KINDS = frozenset({f"rewrite_{side}_{target}" for side in ("request", "response")
                           for target in ("header", "body")} | {
                               "rewrite_request_url", "rewrite_request_query", "rewrite_response_status"})
_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = frozenset(b"0123456789abcdefABCDEF")


def literal(value, limit, label, *, nonempty=False):
    text_size(value, limit, label)
    if nonempty and not value:
        raise ValueError(f"{label} must not be empty")
    return value.encode("utf-8")


def count_mode(rule):
    value = rule.get("rewrite_count", "all")
    if value not in ("all", "first"):
        raise ValueError("rewrite_count must be all or first")
    return value


def message_facts(flow):
    return {"request_method": flow.request.method,
            "frontend_method": flow.metadata.get("lens_frontend_method", flow.request.method)}


@dataclass(frozen=True)
class HeaderRewrite:
    name: bytes
    value: bytes
    mode: str
    find: bytes
    count: str
    operation: TextRewrite | None = None
    name_operation: TextRewrite | None = None

    @property
    def threaded(self):
        return bool(self.name_operation or (self.operation and self.operation.threaded))

    @classmethod
    def prepare(cls, rule):
        mode = rule.get("rewrite_mode", "set")
        if mode not in ("set", "add", "remove", "replace"):
            raise ValueError("Header rewrite_mode must be set, add, remove or replace")
        name, value = rule.get("name", ""), rule.get("value", "")
        name_regex = boolean(rule, 'rewrite_name_regex')
        new_name = rule.get('rewrite_new_name', '')
        if not isinstance(new_name, str):
            raise ValueError('rewrite_new_name must be a string')
        if (name_regex or new_name) and mode not in ('replace', 'remove'):
            raise ValueError('Header name matching/renaming requires Replace or Remove')
        if new_name and mode == 'remove':
            raise ValueError('Header Remove cannot rename a field')
        # Pattern names are not HTTP field names. Their generated results pass
        # the same HTTP owner after capture expansion and size admission.
        pair = prepare_headers([["X-Lens-Pattern" if name_regex else name, value]]).fields[0]
        name_operation = TextRewrite.prepare(rule, name, new_name or ('$0' if name_regex else name), HEADER_BYTES, name=True, count='first') if name_regex or new_name else None
        count = count_mode(rule)
        find, operation = b"", None
        if mode == "replace":
            operation = TextRewrite.prepare(rule, rule.get('rewrite_find', ''), rule.get('value', ''), HEADER_BYTES)
            find = operation.find
        elif rule.get("rewrite_find", "") or count != "all" or any(boolean(rule, key) for key in ('rewrite_regex', 'rewrite_whole')) or not boolean(rule, 'rewrite_case_sensitive', True):
            raise ValueError("Header find/count/value matching options only apply to replace mode")
        return cls(*pair, mode, find, count, operation, name_operation)

    def fields(self, headers):
        fields = headers.fields
        deadline = Deadline(self.name_operation.timeout_ms if self.name_operation else self.operation.timeout_ms if self.operation else 250)
        names = {index: self.name_operation.plan(name, HEADER_BYTES, deadline) for index, (name, _) in enumerate(fields)} if self.name_operation else {}
        selected = self.name.lower()
        matching = [i for i, (name, _) in enumerate(fields) if (names[i].count if names else name.lower() == selected)]
        if not matching and self.mode in ("remove", "replace"):
            return headers
        # Predict final serialized field bytes and count before replacements/join.
        total = sum(len(name) + len(value) + 4 for name, value in fields)
        final_count = len(fields)
        replacements = {}
        if self.mode == "add" or (self.mode == "set" and not matching):
            total += len(self.name) + len(self.value) + 4
            final_count += 1
        elif self.mode in ("set", "remove"):
            total -= sum(len(fields[i][0]) + len(fields[i][1]) + 4 for i in matching)
            final_count -= len(matching)
            if self.mode == "set":
                total += len(fields[matching[0]][0]) + len(self.value) + 4
                final_count += 1
        else:
            remaining = self.count == 'first'
            for index in matching:
                operation = self.operation
                if remaining and any(plan.count for plan in replacements.values()):
                    operation = None
                if operation is not None:
                    plan = operation.plan(fields[index][1], HEADER_BYTES, deadline)
                    replacements[index] = plan
                    total += plan.size - len(fields[index][1])
                if names and index in replacements and replacements[index].count:
                    total += names[index].size - len(fields[index][0])
            if not any(plan.count for plan in replacements.values()) and not names:
                return headers
        if total > HEADER_BYTES or final_count > MAX_HEADERS:
            raise ValueError("Rewritten headers exceed 64 KiB or 1024 fields before allocation")
        result = []
        matching_set = frozenset(matching)
        first = matching[0] if matching else None
        for index, (name, value) in enumerate(fields):
            if index not in matching_set:
                result.append((name, value))
            elif self.mode == "set":
                if index == first:
                    result.append((name, self.value))
            elif self.mode != "remove":
                if self.mode == "replace":
                    if index in replacements:
                        value = replacements[index].render()
                    if names and index in replacements and replacements[index].count:
                        name = names[index].render()
                    if (name, value) != fields[index]:
                        validate_header_field(name, value)
                result.append((name, value))
        if self.mode == "add" or (self.mode == "set" and not matching):
            result.append((self.name, self.value))
        return headers if tuple(result) == fields else http.Headers(result)

    def edit(self, flow, side):
        message = getattr(flow, side)
        headers = self.fields(message.headers)
        if headers is message.headers:
            return PreparedEdit(side, message)
        return prepare_header_fields(message, side, headers, **message_facts(flow))


@dataclass(frozen=True)
class BodyRewrite:
    operation: TextRewrite

    @property
    def threaded(self):
        return self.operation.threaded

    @classmethod
    def prepare(cls, rule):
        return cls(TextRewrite.prepare(rule, rule.get('name', ''), rule.get('value', ''), BODY_BYTES))

    def edit(self, flow, side):
        message = getattr(flow, side)
        if message.raw_content is None:
            raise ValueError("Original body is unavailable for rewrite")
        codec = content_encoding(message.headers)
        body = decoded_bytes(message.raw_content, codec, BODY_BYTES, strict=True)
        replacement = self.operation.plan(body, BODY_BYTES).render()
        if replacement is body or replacement == body:
            return PreparedEdit(side, message)
        return prepare_body_replacement(message, side, replacement, **message_facts(flow))


@dataclass(frozen=True)
class URLRewrite:
    operation: TextRewrite

    @property
    def threaded(self):
        return self.operation.threaded

    @classmethod
    def prepare(cls, rule):
        return cls(TextRewrite.prepare(rule, rule.get('name', ''), rule.get('value', ''), URL_BYTES))

    def edit(self, flow, side):
        current = request_url(flow.request, pretty=False)
        # Literal no-match preserves even opaque source target bytes.
        if not self.operation.threaded and self.operation.find.decode('utf-8') not in current:
            return PreparedEdit(side, flow.request)
        source = wire_text(current, "Current URL", URL_BYTES)
        replacement = self.operation.plan(source, URL_BYTES).render()
        if replacement == source:
            return PreparedEdit(side, flow.request)
        return prepare_request_edit(flow.request, {"url": replacement.decode("utf-8")})


def encoded_component(value, label):
    source = literal(value, URL_BYTES, label)
    if sum(1 if byte in _UNRESERVED else 3 for byte in source) > URL_BYTES:
        raise ValueError(f"Encoded {label} exceeds 64 KiB before allocation")
    return quote_from_bytes(source, safe="").encode("ascii")


def decoded_query_component(source):
    # Invalid percent escapes are unknown, never a permissive decoded match.
    for index, byte in enumerate(source):
        if byte == 37 and (index + 2 >= len(source) or source[index + 1] not in _HEX or source[index + 2] not in _HEX):
            return None
    return unquote_to_bytes(source.replace(b"+", b" "))


def decoded_key(segment):
    source = decoded_query_component(segment.partition(b'=')[0])
    if source is None:
        return None
    try:
        return source.decode('utf-8', 'strict')
    except UnicodeError:
        return None


def encoded_query_bytes(source):
    if sum(1 if byte in _UNRESERVED else 3 for byte in source) > URL_BYTES:
        raise ValueError('Encoded query component exceeds 64 KiB before allocation')
    return quote_from_bytes(source, safe='').encode('ascii')


@dataclass(frozen=True)
class QueryRewrite:
    key: str
    pair: bytes
    mode: str
    operation: TextRewrite | None = None
    name_operation: TextRewrite | None = None

    @property
    def threaded(self):
        return bool(self.name_operation or (self.operation and self.operation.threaded))

    @classmethod
    def prepare(cls, rule):
        key = rule.get("name", "")
        name_regex = boolean(rule, "rewrite_name_regex")
        literal(key, URL_BYTES, "Query parameter name", nonempty=not name_regex)
        mode = rule.get("rewrite_mode", "set")
        if mode not in ("set", "add", "remove", "replace"):
            raise ValueError("Query rewrite_mode must be set, add, remove or replace")
        new_name = rule.get('rewrite_new_name', '')
        if not isinstance(new_name, str):
            raise ValueError('rewrite_new_name must be a string')
        if (name_regex or new_name) and mode not in ('replace', 'remove'):
            raise ValueError('Query name matching/renaming requires Replace or Remove')
        if new_name and mode == 'remove':
            raise ValueError('Query Remove cannot rename a parameter')
        name_operation = TextRewrite.prepare(rule, key, new_name or ('$0' if name_regex else key), URL_BYTES, name=True, count='first') if name_regex or new_name else None
        operation = TextRewrite.prepare(rule, rule.get('rewrite_find', ''), rule.get('value', ''), URL_BYTES) if mode == 'replace' else None
        if mode != 'replace' and (rule.get('rewrite_find', '') or rule.get('rewrite_count', 'all') != 'all' or boolean(rule, 'rewrite_regex') or boolean(rule, 'rewrite_whole') or not boolean(rule, 'rewrite_case_sensitive', True)):
            raise ValueError('Query value matching/count options require Replace')
        name = encoded_component(key, "query parameter name")
        value = encoded_component(rule.get("value", ""), "query parameter value")
        if len(name) + len(value) + 1 > URL_BYTES:
            raise ValueError("Encoded query pair exceeds 64 KiB before allocation")
        return cls(key, name + b"=" + value, mode, operation, name_operation)

    def edit(self, flow, side):
        original = flow.request.data.path
        if len(original) > URL_BYTES:
            raise ValueError("Source query target exceeds 64 KiB")
        path, marker, query = original.partition(b"?")
        segments = query.split(b"&") if marker else []
        deadline = Deadline(self.name_operation.timeout_ms if self.name_operation else self.operation.timeout_ms if self.operation else 250)
        keys = [decoded_key(value) for value in segments]
        names = {index: self.name_operation.plan(key.encode('utf-8'), URL_BYTES, deadline) for index, key in enumerate(keys) if key is not None} if self.name_operation else {}
        matching = [index for index in names if names[index].count] if self.name_operation else [index for index, key in enumerate(keys) if key == self.key]
        if self.mode == 'replace':
            return self.replace_values(flow, path, segments, keys, names, matching, deadline)
        if self.mode == "remove" and not matching:
            return PreparedEdit(side, flow.request)
        result = []
        first = matching[0] if matching else None
        matching_set = frozenset(matching)
        for index, value in enumerate(segments):
            if index not in matching_set or self.mode == "add":
                result.append(value)
            elif self.mode == "set" and index == first:
                result.append(self.pair)
        if self.mode == "add" or (self.mode == "set" and not matching):
            result.append(self.pair)
        size = len(path) + (1 + sum(map(len, result)) + max(0, len(result) - 1) if result else 0)
        if size > URL_BYTES:
            raise ValueError("Rewritten query target exceeds 64 KiB before join")
        if path == b"*":
            raise ValueError("An asterisk request target cannot contain a query")
        target = path + (b"?" + b"&".join(result) if result else b"")
        if target == original:
            return PreparedEdit(side, flow.request)
        replacement = flow.request.copy()
        replacement.data.path = target
        return PreparedEdit(side, replacement)


    def replace_values(self, flow, path, segments, keys, names, matching, deadline):
        plans, prefix_size, replaced = {}, len(path) + 1, False
        selected = frozenset(matching)
        def encoded_size(value):
            return sum(1 if byte in _UNRESERVED else 3 for byte in value)
        # Measure the complete final URL in source order. Prefixes cannot shrink
        # through later replacements, so reject before retaining expanded values.
        for index, segment in enumerate(segments):
            if index:
                prefix_size += 1
            value = decoded_query_component(segment.partition(b'=')[2]) if index in selected else None
            plan = self.operation.plan(value, URL_BYTES, deadline) if value is not None and not (self.operation.count == 'first' and replaced) else None
            if plan is None or not plan.count:
                prefix_size += len(segment)
            else:
                name_plan = names.get(index)
                # Unchanged parameter names retain their source percent spelling.
                raw_name = segment.partition(b'=')[0]
                if name_plan is not None and not name_plan.identity():
                    name_size = name_plan.measure(encoded_size)
                else:
                    name_plan = None
                    name_size = len(raw_name)
                value_size = plan.measure(encoded_size)
                prefix_size += name_size + 1 + value_size
                plans[index] = name_plan, plan
                replaced = True
            if prefix_size > URL_BYTES:
                raise ValueError('Rewritten query target exceeds 64 KiB before allocation')
        if not replaced:
            return PreparedEdit('request', flow.request)
        result = []
        for index, segment in enumerate(segments):
            if index not in plans:
                result.append(segment); continue
            name_plan, plan = plans[index]
            raw_name = segment.partition(b'=')[0]
            raw_value = segment.partition(b'=')[2]
            updated = plan.render()
            original_value = decoded_query_component(raw_value)
            if name_plan is None and updated == original_value:
                result.append(segment); continue
            name = encoded_query_bytes(name_plan.render()) if name_plan else raw_name
            result.append(name + b'=' + encoded_query_bytes(updated))
        target = path + b'?' + b'&'.join(result)
        if target == flow.request.data.path:
            return PreparedEdit('request', flow.request)
        replacement = flow.request.copy(); replacement.data.path = target
        return PreparedEdit('request', replacement)


@dataclass(frozen=True)
class StatusRewrite:
    status: int
    reason: str

    @classmethod
    def prepare(cls, rule):
        name = rule.get("name", "")
        if len(name) != 3 or not name.isascii() or not name.isdecimal() or not 200 <= int(name) <= 599:
            raise ValueError("Response status rewrite name must be a decimal status from 200 through 599")
        reason = rule.get("value", "")
        # Validate with the same reason/status owner used against actual messages.
        prepare_response_edit(http.Response.make(200, b""), {"status_code": int(name), "reason": reason},
                              request_method="GET", frontend_method="GET")
        return cls(int(name), reason)

    def edit(self, flow, side):
        if flow.response.status_code < 200 or flow.websocket is not None:
            raise ValueError("Response status rewrite cannot change a protocol-switch response")
        return prepare_response_edit(flow.response, {"status_code": self.status, "reason": self.reason},
                                     **message_facts(flow))


def prepare(rule):
    kind = rule["kind"]
    if kind not in REWRITE_KINDS:
        return None
    target = kind.rsplit("_", 1)[-1]
    for key in ('rewrite_regex', 'rewrite_name_regex', 'rewrite_whole', 'rewrite_case_sensitive'):
        boolean(rule, key, key == 'rewrite_case_sensitive')
    if target not in ('header', 'query') and (rule.get('rewrite_name_regex', False) or rule.get('rewrite_new_name', '')):
        raise ValueError('Name matching/renaming applies only to headers and query parameters')
    if target == 'status' and (rule.get('rewrite_regex', False) or rule.get('rewrite_whole', False) or not rule.get('rewrite_case_sensitive', True)):
        raise ValueError('Status rewrite uses an explicit numeric replacement, not text matching')
    return {"header": HeaderRewrite, "body": BodyRewrite, "url": URLRewrite,
            "query": QueryRewrite, "status": StatusRewrite}[target].prepare(rule)


RewriteAction = HeaderRewrite | BodyRewrite | URLRewrite | QueryRewrite | StatusRewrite


def parse_error(value):
    """Own explicitly retained rewrite failures without reinterpreting their text."""
    if not isinstance(value, str) or not value:
        raise ValueError("Lens rewrite error must be a nonempty string")
    # Diagnostics may include a whole admitted header plus explanation. Their
    # persistence budget belongs to HAR metadata, not HTTP header syntax.
    text_size(value, METADATA_BYTES, "Lens rewrite error", metadata=True)
    return value
