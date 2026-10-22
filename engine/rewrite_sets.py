"""Rewrite-set ownership: one scope shared by its ordered child actions."""
from dataclasses import dataclass
import fnmatch
from bounds import text_size, METADATA_BYTES
from rewrite import REWRITE_KINDS

MAX_RULES = 500


@dataclass(frozen=True)
class RewriteScope:
    identity: str | None
    name: str
    enabled: bool
    locations: tuple

    def matches(self, url):
        return self.enabled and any(fnmatch.fnmatchcase(url, pattern) for pattern in self.locations)


def expand_rules(values):
    if not isinstance(values, list) or len(values) > MAX_RULES:
        raise ValueError('rules must be an array of at most 500 rules')
    count, identities = 0, set()
    for value in values:
        count += 1
        if count > MAX_RULES:
            raise ValueError('At most 500 traffic rule, set and location rows are allowed in total')
        if not isinstance(value, dict):
            raise ValueError('Every rule must be an object')
        if value.get('kind') != 'rewrite_set':
            yield value, None
            continue
        name, enabled = value.get('name', ''), value.get('enabled', True)
        text_size(name, METADATA_BYTES, 'Rewrite set name')
        if not name.strip() or type(enabled) is not bool:
            raise ValueError('Rewrite sets require a name and boolean enabled state')
        identity = value.get('id')
        if identity is not None:
            if not isinstance(identity, str) or not identity or identity in identities:
                raise ValueError('Rewrite set identities must be nonempty unique strings')
            identities.add(identity)
        locations = value.get('locations')
        if not isinstance(locations, list):
            raise ValueError('Rewrite set locations must be an array of URL globs')
        for location in locations:
            text_size(location, METADATA_BYTES, 'Rewrite set location')
            if not location or any(char in location for char in '\x00\r\n'):
                raise ValueError('Rewrite set locations must be nonempty URL globs without NUL or line breaks')
        children = value.get('rewrite_rules')
        if not isinstance(children, list):
            raise ValueError('Rewrite set rewrite_rules must be an array')
        count += len(children) + len(locations)
        if count > MAX_RULES:
            raise ValueError('At most 500 traffic rule, set and location rows are allowed in total')
        scope = RewriteScope(identity, name, enabled, tuple(locations))
        for child in children:
            if not isinstance(child, dict) or child.get('kind') not in REWRITE_KINDS:
                raise ValueError('Rewrite sets may contain Rewrite actions only; nested sets are unsupported')
            yield child, scope
