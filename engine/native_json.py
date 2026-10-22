"""Lossless native-only JSONL projection for Foundation's Unicode boundary.

Only the control representation changes. HTTP/HAR source objects remain untouched.
A sizing pass admits the complete ASCII JSON envelope before any Base64 payload,
visible surrogate escape, or complete serialized message is allocated.
"""
import base64
from dataclasses import dataclass
import json
import math
import re

from bounds import HAR_FILE_BYTES


_GENERATED_KEY_PREFIX = "__lens_native_key_"
_SURROGATES = re.compile(r"[\ud800-\udfff]")
_ASCII_ESCAPES = tuple((chr(code), 1 if code in (8, 9, 10, 12, 13) else 5) for code in (*range(32), 127))


class _Budget:
    def __init__(self, limit):
        if type(limit) is not int or limit < 0:
            raise ValueError("Native JSON byte budget must be a nonnegative integer")
        self.limit, self.used = limit, 0

    def add(self, count):
        if count > self.limit - self.used:
            raise ValueError("Native JSON message exceeds its encoded byte budget")
        self.used += count


@dataclass(slots=True)
class _StringPlan:
    source: str


@dataclass(slots=True)
class _ContainerPlan:
    source: object
    children: dict
    keys: dict | None = None


@dataclass(slots=True)
class _SourceText:
    path: tuple
    kind: str
    source: str


def _string_cost(value, budget, *, visible_surrogates=False):
    """Count ensure_ascii JSON and UTF-8-surrogatepass bytes without encoding."""
    if len(value) + 2 > budget.limit - budget.used:
        raise ValueError("Native JSON message exceeds its encoded byte budget")
    budget.add(2)
    if value.isascii():
        extra = value.count('"') + value.count('\\')
        if not value.isprintable():
            extra += sum(value.count(char) * cost for char, cost in _ASCII_ESCAPES)
        budget.add(len(value) + extra)
        return len(value), False
    source_bytes, has_surrogate = 0, False
    for char in value:
        code = ord(char)
        source_bytes += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
        if 0xD800 <= code <= 0xDFFF:
            has_surrogate = True
            # The six visible characters \\udcff require seven JSON bytes: the
            # literal backslash is itself escaped by JSON serialization.
            budget.add(7 if visible_surrogates else 6)
        elif char in ('"', '\\', '\b', '\f', '\n', '\r', '\t'):
            budget.add(2)
        elif 0x20 <= code < 0x7F:
            budget.add(1)
        else:
            budget.add(6 if code <= 0xFFFF else 12)
    return source_bytes, has_surrogate


def _source_byte_cost(value, budget):
    # Source keys are not rendered: only their Base64 bytes and ASCII generated
    # key appear. A scalar precheck avoids scanning an obviously oversized key.
    if len(value) > budget.limit - budget.used:
        raise ValueError("Native JSON message exceeds its encoded byte budget")
    count = 0
    for char in value:
        code = ord(char)
        count += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
    return count


def _number_cost(value, budget):
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Native JSON numbers must be finite")
    else:
        # Admission before decimal conversion. This rational is a lower bound
        # on log10(2), so enormous integers cannot allocate their decimal text
        # merely to discover they exceed the available output budget.
        bits = value.bit_length()
        lower = max(1, (max(0, bits - 1) * 301029995663981) // 1000000000000000 + 1)
        if lower + (value < 0) > budget.limit - budget.used:
            raise ValueError("Native JSON number exceeds its encoded byte budget")
    try:
        # For finite built-in floats/integers, JSON uses the exact built-in
        # numeric repr. No JSON document is allocated during admission.
        budget.add(len(repr(value)))
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"Native JSON number cannot be encoded: {exc}") from exc


def _annotation(path, kind, source, source_bytes, records, budget):
    if records:
        budget.add(1)
    # Exactly {"path":PATH,"kind":KIND,"utf8_surrogatepass_base64":"BASE64"}.
    budget.add(len('{"path":') + len(',"kind":') + len(',"utf8_surrogatepass_base64":') + 1)
    budget.add(2 + max(0, len(path) - 1))
    for component in path:
        if type(component) is str:
            _string_cost(component, budget)
        else:
            _number_cost(component, budget)
    _string_cost(kind, budget)
    budget.add(2 + ((source_bytes + 2) // 3) * 4)
    # Store references only after their full serialized expansion was admitted.
    records.append(_SourceText(tuple(path), kind, source))


def _measure(value, path, ancestors, records, budget):
    value_type = type(value)
    if value_type is str:
        source_bytes, changed = _string_cost(value, budget, visible_surrogates=True)
        if changed:
            _annotation(path, 'value', value, source_bytes, records, budget)
            return _StringPlan(value)
        return None
    if value is None:
        budget.add(4)
        return None
    if value_type is bool:
        budget.add(4 if value else 5)
        return None
    if value_type in (int, float):
        _number_cost(value, budget)
        return None
    if value_type not in (dict, list, tuple):
        raise ValueError(f"Unsupported native JSON value type: {value_type.__name__}")
    identity = id(value)
    if identity in ancestors:
        raise ValueError("Native JSON message contains a cycle")
    ancestors.add(identity)
    try:
        budget.add(2 + max(0, len(value) - 1))
        changes = {}
        if value_type in (list, tuple):
            for index, item in enumerate(value):
                path.append(index)
                child = _measure(item, path, ancestors, records, budget)
                path.pop()
                if child is not None:
                    changes[index] = child
            return _ContainerPlan(value, changes) if changes else None
        for key in value:
            if type(key) is not str:
                raise ValueError("Native JSON object keys must be strings")
        # Test generated names against the source dictionary directly. Its
        # ASCII keys keep their identity, including keys later in source order;
        # monotonic IDs also cannot collide with earlier generated names. No
        # additional set proportional to every ordinary source key is needed.
        renames = {}
        next_key = 0
        for key in value:
            if key.isascii():
                continue
            while True:
                candidate = _GENERATED_KEY_PREFIX + str(next_key)
                next_key += 1
                if candidate not in value:
                    break
            renames[key] = candidate
        for key, item in value.items():
            projected_key = renames.get(key, key)
            _string_cost(projected_key, budget)
            budget.add(1)
            path.append(projected_key)
            if key in renames:
                _annotation(path, 'key', key, _source_byte_cost(key, budget), records, budget)
            child = _measure(item, path, ancestors, records, budget)
            path.pop()
            if child is not None:
                changes[key] = child
        return _ContainerPlan(value, changes, renames) if changes or renames else None
    finally:
        ancestors.remove(identity)


def _project(plan):
    if isinstance(plan, _StringPlan):
        return _SURROGATES.sub(lambda match: f'\\u{ord(match.group()):04x}', plan.source)
    if isinstance(plan.source, dict):
        return {plan.keys.get(key, key): _project(plan.children[key]) if key in plan.children else value
                for key, value in plan.source.items()}
    result = list(plan.source)
    for index, child in plan.children.items():
        result[index] = _project(child)
    return result


def encode_native_message(message, *, max_bytes=HAR_FILE_BYTES):
    """Return one admitted, Unicode-safe native envelope, without a newline.

    Source text records retain Python code points, including literal surrogate
    pairs distinct from astral scalars. Their paths use the projected object's
    actual ASCII keys/array indices; kind=key restores that object's member name.
    """
    budget = _Budget(max_bytes)
    budget.add(len('{"native_json":1,"message":') + len(',"source_text":[') + len(']}'))
    records = []
    try:
        plan = _measure(message, [], set(), records, budget)
        projected = message if plan is None else _project(plan)
        source_text = []
        # Repeated source strings share one Base64 allocation; serialized copies
        # at distinct paths were each admitted by the sizing pass above.
        encoded_sources = {}
        for record in records:
            identity = id(record.source)
            if identity not in encoded_sources:
                encoded_sources[identity] = base64.b64encode(record.source.encode('utf-8', 'surrogatepass')).decode('ascii')
            source_text.append({'path': list(record.path), 'kind': record.kind,
                                'utf8_surrogatepass_base64': encoded_sources[identity]})
        encoded = json.dumps({'native_json': 1, 'message': projected, 'source_text': source_text},
                             ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    except RecursionError as exc:
        raise ValueError("Native JSON nesting exceeds encoder stack capacity") from exc
    # This is an invariant check, not allocation admission: every exact byte was
    # counted before projection/Base64/full-message allocation.
    if len(encoded) != budget.used:
        raise ValueError("Native JSON encoded-size accounting mismatch")
    return encoded
