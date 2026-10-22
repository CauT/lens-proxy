"""Compiled Rewrite text matching and pre-admitted capture-group expansion.

Literal byte replacement retains its original fast path. Pattern matching uses
UTF-8 with surrogateescape so opaque input bytes survive untouched spans/groups.
Each operation shares one deadline across measurement and rendering; no expanded
output is allocated until the complete output size has been admitted.
"""
from dataclasses import dataclass
import time
import regex

from bounds import text_size
from http_headers import HEADER_BYTES

DEFAULT_TIMEOUT_MS = 250
MAX_TIMEOUT_MS = 5000


def boolean(rule, key, default=False):
    value = rule.get(key, default)
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


class Deadline:
    def __init__(self, milliseconds):
        self.end = time.monotonic() + milliseconds / 1000

    def remaining(self):
        value = self.end - time.monotonic()
        if value <= 0:
            raise ValueError("Rewrite matching exceeded its selected time budget")
        return value


def encoded(value):
    return value.encode('utf-8', 'surrogateescape')


def template(value, pattern):
    """Java-style $N/${name} references and backslash quoting, parsed once."""
    result, literal, index = [], [], 0
    def flush():
        if literal:
            result.append(''.join(literal)); literal.clear()
    while index < len(value):
        char = value[index]; index += 1
        if char == '\\':
            if index == len(value):
                raise ValueError("Rewrite replacement ends with an unpaired backslash")
            literal.append(value[index]); index += 1
        elif char != '$':
            literal.append(char)
        else:
            flush()
            if index < len(value) and value[index] == '{':
                end = value.find('}', index + 1)
                name = value[index + 1:end] if end >= 0 else ''
                if name not in pattern.groupindex:
                    raise ValueError("Rewrite replacement refers to an unknown named group")
                result.append(pattern.groupindex[name]); index = end + 1
            elif index < len(value) and value[index].isascii() and value[index].isdigit():
                group = int(value[index]); index += 1
                if group > pattern.groups:
                    raise ValueError("Rewrite replacement refers to an unknown capture group")
                while index < len(value) and value[index].isascii() and value[index].isdigit():
                    candidate = group * 10 + int(value[index])
                    if candidate > pattern.groups:
                        break
                    group = candidate; index += 1
                result.append(group)
            else:
                raise ValueError("Rewrite replacement $ requires a numbered or named capture group")
    flush()
    return tuple(result)


@dataclass(frozen=True)
class TextRewrite:
    find: bytes
    value: bytes
    count: str
    pattern: object = None
    parts: tuple = ()
    whole: bool = False
    timeout_ms: int = DEFAULT_TIMEOUT_MS

    @property
    def threaded(self):
        return self.pattern is not None

    @classmethod
    def prepare(cls, rule, find, replacement, limit, *, name=False, count=None):
        is_regex = boolean(rule, 'rewrite_name_regex' if name else 'rewrite_regex')
        sensitive = False if name else boolean(rule, 'rewrite_case_sensitive', True)
        whole = not is_regex if name else boolean(rule, 'rewrite_whole')
        milliseconds = rule.get('rewrite_timeout_ms', DEFAULT_TIMEOUT_MS)
        if type(milliseconds) is not int or not 1 <= milliseconds <= MAX_TIMEOUT_MS:
            raise ValueError("rewrite_timeout_ms must be an integer from 1 through 5000")
        count = count or rule.get('rewrite_count', 'all')
        if count not in ('all', 'first'):
            raise ValueError("rewrite_count must be all or first")
        text_size(find, HEADER_BYTES if is_regex else limit, 'Rewrite match pattern')
        text_size(replacement, limit, 'Rewrite replacement')
        if not find and not is_regex:
            raise ValueError("Rewrite find text must not be empty")
        find_bytes, value_bytes = encoded(find), encoded(replacement)
        if not is_regex and sensitive and not whole:
            return cls(find_bytes, value_bytes, count)
        # A blank regex match selects the entire value once, matching the
        # documented blank-Match workflow instead of inserting at every boundary.
        expression = find if is_regex and find else regex.escape(find) if find else r'(?s:.*)\Z'
        try:
            compiled = regex.compile(expression, regex.VERSION0 | (0 if sensitive else regex.IGNORECASE))
        except (regex.error, RecursionError, OverflowError) as exc:
            raise ValueError(f"Invalid Rewrite regular expression: {exc}") from exc
        parts = template(replacement, compiled) if is_regex else (replacement,)
        return cls(find_bytes, value_bytes, count, compiled, parts, whole or not find, milliseconds)

    def plan(self, source, limit, deadline=None):
        if self.pattern is None:
            matches = source.count(self.find) if self.count == 'all' else int(self.find in source)
            size = len(source) + matches * (len(self.value) - len(self.find))
            if size > limit:
                raise ValueError(f"Rewrite replacement exceeds its {limit} byte budget before allocation")
            return TextPlan(self, source, None, None, size, matches)
        deadline = deadline or Deadline(self.timeout_ms)
        text = source.decode('utf-8', 'surrogateescape')
        plan = TextPlan(self, source, text, deadline, 0, 0)
        size, cursor, matches = 0, 0, 0
        for match in plan.matches():
            size += len(encoded(text[cursor:match.start()]))
            spans = {}
            for part in self.parts:
                if isinstance(part, int):
                    span = match.span(part)
                    if span not in spans:
                        spans[span] = len(encoded(text[span[0]:span[1]])) if span[0] >= 0 else 0
                    size += spans[span]
                else:
                    size += len(encoded(part))
                if size > limit:
                    raise ValueError(f"Rewrite replacement exceeds its {limit} byte budget before allocation")
                deadline.remaining()
            cursor = match.end(); matches += 1
        size += len(encoded(text[cursor:]))
        deadline.remaining()
        if size > limit:
            raise ValueError(f"Rewrite replacement exceeds its {limit} byte budget before allocation")
        return TextPlan(self, source, text, deadline, size, matches)


@dataclass(frozen=True)
class TextPlan:
    operation: TextRewrite
    source: bytes
    text: str | None
    deadline: Deadline | None
    size: int
    count: int

    def matches(self):
        try:
            if self.operation.whole:
                match = self.operation.pattern.fullmatch(self.text, timeout=self.deadline.remaining(), concurrent=True)
                if match is not None:
                    yield match
            else:
                for match in self.operation.pattern.finditer(self.text, timeout=self.deadline.remaining(), concurrent=True):
                    self.deadline.remaining()
                    yield match
                    if self.operation.count == 'first':
                        return
        except TimeoutError as exc:
            raise ValueError("Rewrite matching exceeded its selected time budget") from exc

    def chunks(self):
        if self.text is None:
            cursor = 0
            for _ in range(self.count):
                start = self.source.find(self.operation.find, cursor)
                yield self.source[cursor:start]
                yield self.operation.value
                cursor = start + len(self.operation.find)
            yield self.source[cursor:]
            return
        cursor = 0
        for match in self.matches():
            yield encoded(self.text[cursor:match.start()])
            for part in self.operation.parts:
                self.deadline.remaining()
                yield encoded((match.group(part) or '') if isinstance(part, int) else part)
            cursor = match.end()
        yield encoded(self.text[cursor:])

    def measure(self, cost):
        return sum(cost(chunk) for chunk in self.chunks())

    def identity(self):
        position = 0
        for chunk in self.chunks():
            if not self.source.startswith(chunk, position):
                return False
            position += len(chunk)
        return position == len(self.source)

    def render(self):
        if not self.count:
            return self.source
        if self.text is None:
            return self.source.replace(self.operation.find, self.operation.value, -1 if self.operation.count == 'all' else 1)
        result, position = bytearray(self.size), 0
        for value in self.chunks():
            self.deadline.remaining()
            end = position + len(value)
            if end > self.size:
                raise ValueError("Rewrite replacement changed after size admission")
            result[position:end] = value; position = end
        if position != self.size:
            raise ValueError("Rewrite replacement changed after size admission")
        return bytes(result)
