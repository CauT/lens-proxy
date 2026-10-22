"""Prepared HTTP URL-glob access decisions, before and after URL mapping.

Matching is deliberately the same case-sensitive, whole-string glob operation as
request rules. Source selections remain separate from compiled matchers. A saved
historical decision describes its observed URL and reason; it does not claim that
any current policy would produce the same result.
"""
from dataclasses import dataclass, field
import fnmatch
import re
from typing import Pattern


MAX_PATTERNS = 500
MAX_PATTERN_LENGTH = 4096
_FIELDS = frozenset(("block_enabled", "allow_enabled", "block", "allow", "action"))
_DECISION_FIELDS = frozenset(("reason", "action", "matched_url", "pattern"))
_ACTIONS = frozenset(("respond", "close"))
_UNSET = object()


def _text(value, label, maximum=None):
    if not isinstance(value, str) or not value or any(c in value for c in "\0\r\n"):
        raise ValueError(f"{label} must be a nonempty string without NUL, CR, or LF")
    if maximum is not None and len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} Unicode codepoints")
    return value


def _patterns(value, label):
    if not isinstance(value, list) or len(value) > MAX_PATTERNS:
        raise ValueError(f"{label} must be an array of at most {MAX_PATTERNS} URL globs")
    return tuple(_text(item, f"{label} URL glob", MAX_PATTERN_LENGTH) for item in value)


def _compile(patterns):
    return tuple(re.compile(fnmatch.translate(pattern)) for pattern in patterns)


@dataclass(frozen=True)
class AccessPolicy:
    block_enabled: bool
    allow_enabled: bool
    block: tuple[str, ...]
    allow: tuple[str, ...]
    action: str
    _block_matchers: tuple[Pattern[str], ...] = field(repr=False, compare=False)
    _allow_matchers: tuple[Pattern[str], ...] = field(repr=False, compare=False)

    def public(self):
        """Return an independent selection, retaining spelling, order and duplicates."""
        return {"block_enabled": self.block_enabled, "allow_enabled": self.allow_enabled,
                "block": list(self.block), "allow": list(self.allow), "action": self.action}

    def deny(self, original_url, effective_url=None):
        """Return a concrete denial or None; evaluate all Block matches first.

        Both the caller's URL and a distinct mapped URL must pass Allow. Mapping
        cannot turn a blocked original into an allowed request, nor conceal a
        blocked destination behind an allowed original URL.
        """
        original_url = _text(original_url, "Original URL")
        urls = [original_url]
        if effective_url is not None:
            effective_url = _text(effective_url, "Effective URL")
            if effective_url != original_url:
                urls.append(effective_url)
        if self.block_enabled:
            for url in urls:
                for pattern, matcher in zip(self.block, self._block_matchers):
                    if matcher.match(url) is not None:
                        return {"reason": "block_match", "action": self.action,
                                "matched_url": url, "pattern": pattern}
        if self.allow_enabled:
            for url in urls:
                if not any(matcher.match(url) is not None for matcher in self._allow_matchers):
                    return {"reason": "allow_miss", "action": self.action,
                            "matched_url": url, "pattern": None}
        return None


def parse_access_policy(value=_UNSET):
    """Validate once and prepare an immutable policy; omitted fields use defaults."""
    if value is _UNSET:
        value = {}
    if not isinstance(value, dict) or set(value) - _FIELDS:
        raise ValueError("Access policy must be an object with only supported fields")
    block_enabled, allow_enabled = value.get("block_enabled", False), value.get("allow_enabled", False)
    if type(block_enabled) is not bool or type(allow_enabled) is not bool:
        raise ValueError("Access policy enabled selections must be booleans")
    action = value.get("action", "respond")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("Access policy action must be respond or close")
    block = _patterns(value.get("block", []), "Block List")
    allow = _patterns(value.get("allow", []), "Allow List")
    return AccessPolicy(block_enabled, allow_enabled, block, allow, action,
                        _compile(block), _compile(allow))


def import_decision(value):
    """Validate historical facts, without inferring missing reasons or patterns."""
    if not isinstance(value, dict) or set(value) != _DECISION_FIELDS:
        raise ValueError("Access decision must contain exactly reason, action, matched_url, and pattern")
    reason, action = value["reason"], value["action"]
    if not isinstance(reason, str) or reason not in ("block_match", "allow_miss"):
        raise ValueError("Access decision reason must be block_match or allow_miss")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("Access decision action must be respond or close")
    url = _text(value["matched_url"], "Access decision URL")
    pattern = value["pattern"]
    if reason == "block_match":
        pattern = _text(pattern, "Access decision Block pattern", MAX_PATTERN_LENGTH)
        if re.compile(fnmatch.translate(pattern)).match(url) is None:
            raise ValueError("Access decision Block pattern must match its observed URL")
    elif pattern is not None:
        raise ValueError("Access decision Allow miss cannot identify a matched pattern")
    return {"reason": reason, "action": action, "matched_url": url, "pattern": pattern}
