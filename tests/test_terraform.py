import re
from pathlib import Path

import pytest

TF_FILE = Path(__file__).resolve().parent.parent / "eventbridge" / "rules.tf"
TF_TEXT = TF_FILE.read_text(encoding="utf-8")

RULE_NAMES = re.findall(
    r'resource "aws_cloudwatch_event_rule" "([^"]+)"', TF_TEXT)
TARGETED = set(re.findall(
    r'rule\s*=\s*aws_cloudwatch_event_rule\.([A-Za-z0-9_]+)\.name', TF_TEXT))


@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_has_target(name):
    assert name in TARGETED, (
        "rule '" + name + "' has no target, so it never sends an alert")
