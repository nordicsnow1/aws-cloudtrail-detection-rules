import json
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_rules():
    rules = []
    for path in sorted(RULES_DIR.glob("*/rules.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        rules.extend(data["rules"])
    return rules


ALL_RULES = load_rules()


def expected_source(pattern):
    """Return the expected source list, or None if source must be absent."""
    detail = pattern.get("detail", {})
    detail_type = pattern.get("detail-type", [""])[0]
    if detail_type.startswith("AWS Console Sign"):
        return ["aws.signin"]
    if "eventSource" in detail:
        service = detail["eventSource"][0].split(".")[0]
        return ["aws." + service]
    return None


@pytest.mark.parametrize("rule", ALL_RULES, ids=[r["id"] for r in ALL_RULES])
def test_eventbridge_source(rule):
    pattern = rule.get("eventbridge_pattern")
    if pattern is None:
        pytest.skip("rule has no eventbridge_pattern")
    expected = expected_source(pattern)
    if expected is None:
        assert "source" not in pattern, (
            "rule covers all services, so source must be absent, "
            "but it is " + str(pattern.get("source"))
        )
    else:
        assert pattern.get("source") == expected
