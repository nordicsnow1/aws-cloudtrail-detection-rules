"""Run each fixture event against the EventBridge pattern of its rule.

Fixture layout: tests/fixtures/<RULE-ID>/positive*.json must match the rule,
tests/fixtures/<RULE-ID>/negative*.json must not match. Each file is a full
EventBridge event; "detail" holds the CloudTrail record.
"""
import json
from pathlib import Path

import pytest

from eventbridge_matcher import matches

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def load_rules():
    rules = {}
    for path in sorted((ROOT / "rules").glob("*/rules.json")):
        for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]:
            rules[rule["id"]] = rule
    return rules


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


RULES = load_rules()
CASES = sorted(
    (path.parent.name, path, path.name.startswith("positive"))
    for path in FIXTURES.glob("*/*.json")
    if path.name.startswith(("positive", "negative"))
)


def test_fixture_folders_are_rule_ids():
    unknown = {p.name for p in FIXTURES.iterdir() if p.is_dir()} - set(RULES)
    assert not unknown, "fixture folders without a matching rule: " + str(unknown)


@pytest.mark.parametrize(
    "rule_id, path, should_match", CASES,
    ids=[rule_id + "/" + path.name for rule_id, path, _ in CASES])
def test_fixture_against_eventbridge_pattern(rule_id, path, should_match):
    pattern = RULES[rule_id]["eventbridge_pattern"]
    assert matches(pattern, load_json(path)) == should_match


def test_log004_old_pattern_misses_the_event():
    """Regression: the original LOG-004 source (aws.cloudtrail) never matched."""
    event = load_json(FIXTURES / "LOG-004" / "positive.json")
    assert not matches(load_json(FIXTURES / "LOG-004" / "pattern.json"), event)
    assert matches(load_json(FIXTURES / "LOG-004" / "pattern_fixed.json"), event)


# --- Checks of the matcher itself -------------------------------------------

@pytest.mark.parametrize("pattern, event, expected", [
    ({"a": ["x"]}, {"a": "x"}, True),
    ({"a": ["x"]}, {"a": "y"}, False),
    ({"a": ["x"]}, {}, False),
    ({"a": ["x", "y"]}, {"a": "y"}, True),
    ({"a": ["x"]}, {"a": ["y", "x"]}, True),
    ({"a": {"b": ["x"]}}, {"a": {"b": "x"}}, True),
    ({"a": {"b": ["x"]}}, {"a": "x"}, False),
    ({"a": [True]}, {"a": True}, True),
    ({"a": [True]}, {"a": "true"}, False),
    ({"a": [{"prefix": "Access"}]}, {"a": "AccessDenied"}, True),
    ({"a": [{"suffix": "Operation"}]}, {"a": "Client.UnauthorizedOperation"}, True),
    ({"a": [{"suffix": "Operation"}]}, {"a": "UnauthorizedAccess"}, False),
    ({"a": [{"exists": False}]}, {}, True),
    ({"a": [{"exists": True}]}, {}, False),
    ({"a": [{"anything-but": "x"}]}, {"a": "y"}, True),
    ({"a": [{"anything-but": "x"}]}, {"a": "x"}, False),
    ({"a": [{"equals-ignore-case": "ROOT"}]}, {"a": "Root"}, True),
])
def test_matcher(pattern, event, expected):
    assert matches(pattern, event) == expected


def test_matcher_rejects_unknown_operator():
    with pytest.raises(NotImplementedError):
        matches({"a": [{"wildcard": "*x"}]}, {"a": "x"})
