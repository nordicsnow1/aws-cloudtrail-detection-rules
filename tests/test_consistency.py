"""Check that the patterns in rules/*.json match the copies in Terraform."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EB_TEXT = (ROOT / "eventbridge" / "rules.tf").read_text(encoding="utf-8")
CW_TEXT = (ROOT / "cloudwatch" / "metric-filters.tf").read_text(encoding="utf-8")


def load_rules():
    rules = {}
    for path in sorted((ROOT / "rules").glob("*/rules.json")):
        for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]:
            rules[rule["id"]] = rule
    return rules


RULES = load_rules()

# Which JSON rules each EventBridge rule in rules.tf implements.
# A Terraform rule that covers several JSON rules must match their merged pattern.
EB_TO_JSON = {
    "cloudtrail_stopped": ["LOG-001"],
    "cloudtrail_deleted": ["LOG-002"],
    "guardduty_deleted": ["LOG-004"],
    "iam_admin_policy": ["IAM-003"],
    "iam_inline_policy": ["IAM-001"],
    "iam_access_key": ["IAM-002"],
    "root_activity": ["ACCESS-001"],
    "root_login": ["ACCESS-003"],
    "s3_public": ["EXFIL-001", "EXFIL-002"],
    "snapshot_shared": ["EXFIL-003", "EXFIL-004", "EXFIL-005"],
    "kms_key_deletion": ["ENCRYPT-001", "ENCRYPT-002"],
    "security_group_change": ["SG-001", "SG-002"],
}


# --- Minimal parser for the HCL object syntax inside jsonencode({...}) -------

TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_-]*|[{}\[\]=,]')


def parse_hcl_value(tokens, i):
    tok = tokens[i]
    if tok == "{":
        obj, i = {}, i + 1
        while tokens[i] != "}":
            key = json.loads(tokens[i]) if tokens[i].startswith('"') else tokens[i]
            assert tokens[i + 1] == "=", "expected '=' after " + key
            obj[key], i = parse_hcl_value(tokens, i + 2)
            if tokens[i] == ",":
                i += 1
        return obj, i + 1
    if tok == "[":
        items, i = [], i + 1
        while tokens[i] != "]":
            value, i = parse_hcl_value(tokens, i)
            items.append(value)
            if tokens[i] == ",":
                i += 1
        return items, i + 1
    if tok.startswith('"'):
        return json.loads(tok), i + 1
    if tok in ("true", "false"):
        return tok == "true", i + 1
    raise ValueError("unexpected token " + tok)


def eventbridge_patterns():
    patterns = {}
    blocks = re.split(r'resource "aws_cloudwatch_event_rule" "', EB_TEXT)[1:]
    for block in blocks:
        name = block.split('"', 1)[0]
        body = block.split("jsonencode(", 1)[1]
        patterns[name], _ = parse_hcl_value(TOKEN.findall(body), 0)
    return patterns


EB_PATTERNS = eventbridge_patterns()


# --- Helpers ------------------------------------------------------------------

def merge(a, b):
    """Merge two patterns: lists become the union, objects merge key by key."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for key, value in b.items():
            out[key] = merge(out[key], value) if key in out else value
        return out
    if isinstance(a, list) and isinstance(b, list):
        return a + [x for x in b if x not in a]
    assert a == b, "cannot merge " + repr(a) + " and " + repr(b)
    return a


def normalize(pattern):
    """Sort lists so that value order does not matter."""
    if isinstance(pattern, dict):
        return {k: normalize(v) for k, v in pattern.items()}
    if isinstance(pattern, list):
        return sorted((normalize(x) for x in pattern), key=json.dumps)
    return pattern


# --- Tests --------------------------------------------------------------------

def test_every_eventbridge_rule_is_mapped():
    assert set(EB_PATTERNS) == set(EB_TO_JSON), (
        "update EB_TO_JSON when you add or remove a rule in rules.tf")


@pytest.mark.parametrize("name", sorted(EB_TO_JSON))
def test_eventbridge_pattern_matches_json(name):
    expected = {}
    for rule_id in EB_TO_JSON[name]:
        expected = merge(expected, RULES[rule_id]["eventbridge_pattern"])
    assert normalize(EB_PATTERNS[name]) == normalize(expected)


CW_FILTERS = dict(re.findall(
    r'name\s*=\s*"([A-Z]+-\d{3})-[^"]*"\s*\n'
    r'\s*description\s*=\s*"[^"]*"\s*\n'
    r'\s*pattern\s*=\s*"((?:[^"\\]|\\.)*)"', CW_TEXT))


def test_every_json_rule_has_cloudwatch_filter():
    assert set(CW_FILTERS) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_cloudwatch_pattern_matches_json(rule_id):
    if rule_id not in CW_FILTERS:
        pytest.skip("no metric filter for this rule")
    tf_pattern = json.loads('"' + CW_FILTERS[rule_id] + '"')
    assert tf_pattern == RULES[rule_id]["cloudwatch_filter_pattern"]
