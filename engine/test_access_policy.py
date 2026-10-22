import copy
from dataclasses import FrozenInstanceError
import fnmatch
import unittest
from unittest.mock import patch

from access_policy import MAX_PATTERNS, MAX_PATTERN_LENGTH, import_decision, parse_access_policy


class AccessPolicySemantics(unittest.TestCase):
    def test_default_and_disabled_selections_do_not_enforce_rules(self):
        expected = {"block_enabled": False, "allow_enabled": False,
                    "block": [], "allow": [], "action": "respond"}
        self.assertEqual(parse_access_policy().public(), expected)
        self.assertEqual(parse_access_policy({}).public(), expected)
        policy = parse_access_policy({"block": ["*"], "allow": []})
        self.assertIsNone(policy.deny("https://example.test/"))
        self.assertIsNone(policy.deny("https://example.test/", "https://mapped.test/"))

    def test_block_precedes_allow_for_both_original_and_effective_urls(self):
        policy = parse_access_policy({"block_enabled": True, "allow_enabled": True,
                                      "block": ["*mapped.test/*", "*blocked*"],
                                      "allow": ["https://allowed.test/*"], "action": "close"})
        result = policy.deny("https://outside.test/", "https://mapped.test/target")
        self.assertEqual(result, {"reason": "block_match", "action": "close",
                                  "matched_url": "https://mapped.test/target", "pattern": "*mapped.test/*"})
        self.assertEqual(policy.deny("https://allowed.test/blocked", "https://allowed.test/")["reason"],
                         "block_match")
        self.assertEqual(policy.deny("https://outside.test/")["reason"], "allow_miss")

    def test_allow_requires_each_distinct_url_and_empty_allow_denies_all(self):
        policy = parse_access_policy({"allow_enabled": True, "allow": ["https://allowed.test/*"]})
        self.assertIsNone(policy.deny("https://allowed.test/one", "https://allowed.test/two"))
        for original, effective, missed in (
                ("https://outside.test/", "https://allowed.test/", "https://outside.test/"),
                ("https://allowed.test/", "https://outside.test/", "https://outside.test/")):
            self.assertEqual(policy.deny(original, effective),
                             {"reason": "allow_miss", "action": "respond", "matched_url": missed, "pattern": None})
        empty = parse_access_policy({"allow_enabled": True})
        self.assertEqual(empty.deny("https://any.test/")["reason"], "allow_miss")
        self.assertIsNone(parse_access_policy({"block_enabled": True}).deny("https://any.test/"))

    def test_matching_retains_fnmatchcase_semantics_and_prepares_once(self):
        patterns = ["https://Case.test/[!a-c]?/*", "https://中文.test/*?q=[[]x]", "*", "["]
        urls = ["https://Case.test/z0/item", "https://case.test/z0/item", "https://Case.test/a0/item",
                "https://中文.test/path?q=[x]", "[", "https://x.test/a?b=c"]
        for pattern in patterns:
            policy = parse_access_policy({"block_enabled": True, "block": [pattern]})
            expected = [fnmatch.fnmatchcase(url, pattern) for url in urls]
            with patch("access_policy.fnmatch.translate", side_effect=AssertionError("must prepare only once")):
                for url, matched in zip(urls, expected):
                    self.assertEqual(policy.deny(url) is not None, matched)
        policy = parse_access_policy({"block_enabled": True, "block": ["*test/*", "*"]})
        self.assertEqual(policy.deny("https://a.test/")["pattern"], "*test/*")

    def test_source_and_output_mutation_cannot_change_prepared_policy(self):
        source = {"block_enabled": True, "block": ["*private*", "*private*"], "action": "close"}
        policy = parse_access_policy(source)
        source["block"].clear()
        source["block_enabled"] = False
        public = policy.public()
        self.assertEqual(public["block"], ["*private*", "*private*"])
        public["block"].append("*")
        public["action"] = "respond"
        self.assertIsNone(policy.deny("https://public.test/"))
        decision = policy.deny("https://private.test/")
        decision["reason"] = "altered"
        self.assertEqual(policy.deny("https://private.test/")["reason"], "block_match")
        with self.assertRaises(FrozenInstanceError):
            policy.action = "respond"
        with self.assertRaises(TypeError):
            policy.block[0] = "*"

    def test_exact_pattern_count_and_unicode_codepoint_boundaries(self):
        source = "界" * MAX_PATTERN_LENGTH
        policy = parse_access_policy({"block": [source] * MAX_PATTERNS, "allow": ["*"] * MAX_PATTERNS})
        self.assertEqual(policy.public()["block"], [source] * MAX_PATTERNS)
        for field in ("block", "allow"):
            for invalid in (["*"] * (MAX_PATTERNS + 1), [source + "界"]):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    parse_access_policy({field: invalid})
        self.assertEqual(parse_access_policy({"block": ["🚀" * MAX_PATTERN_LENGTH]}).block[0],
                         "🚀" * MAX_PATTERN_LENGTH)

    def test_malformed_configuration_and_url_values_fail_before_use(self):
        invalid = [None, [], True, {"unexpected": 1}, {"block_enabled": 1}, {"allow_enabled": None},
                   {"action": "deny"}, {"action": []}, {"block": ()}, {"allow": "*"}]
        invalid.extend({field: [value]} for field in ("block", "allow")
                       for value in (None, 1, "", "a\0b", "a\rb", "a\nb"))
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                parse_access_policy(source)
        policy = parse_access_policy()
        for value in (None, 1, "", "https://test/\0", "https://test/\r", "https://test/\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.deny(value)
            if value is not None:
                with self.assertRaises(ValueError):
                    policy.deny("https://test/", value)

    def test_import_preserves_exact_decisions_without_claiming_current_policy(self):
        values = [parse_access_policy({"block_enabled": True, "block": ["*"], "action": "close"})
                  .deny("https://observed.test/"),
                  parse_access_policy({"allow_enabled": True}).deny("https://observed.test/")]
        for value in values:
            original = copy.deepcopy(value)
            imported = import_decision(value)
            self.assertEqual(imported, value)
            self.assertIsNot(imported, value)
            imported["pattern"] = "altered"
            self.assertEqual(value, original)

    def test_import_rejects_missing_facts_unknown_fields_and_contradictions(self):
        decision = {"reason": "block_match", "action": "respond",
                    "matched_url": "https://observed.test/", "pattern": "*observed.test/*"}
        bad = [None, []]
        bad.extend({k: v for k, v in decision.items() if k != field} for field in decision)
        bad.extend({**decision, **update} for update in (
            {"extra": 1}, {"reason": None}, {"reason": "unknown"}, {"action": "reset"},
            {"action": []}, {"matched_url": None}, {"matched_url": ""}, {"matched_url": "a\nb"},
            {"pattern": None}, {"pattern": ""}, {"pattern": "a\0b"},
            {"pattern": "x" * (MAX_PATTERN_LENGTH + 1)}, {"pattern": "https://different.test/*"},
            {"reason": "allow_miss", "pattern": "*"}))
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                import_decision(value)


if __name__ == "__main__":
    unittest.main()
