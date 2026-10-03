"""Check every fixture against the real AWS pattern engines.

These tests call two read-only AWS APIs that create no resources:
  aws events test-event-pattern   (EventBridge pattern vs. full event)
  aws logs test-metric-filter     (CloudWatch filter vs. the CloudTrail record)

They need the AWS CLI and valid credentials, so they are skipped by default
(see pytest.ini). Run them with:  python -m pytest -m aws
"""
import json
import shutil
import subprocess

import pytest

from test_fixtures import CASES, RULES, load_json

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(shutil.which("aws") is None, reason="AWS CLI not installed"),
]

IDS = [rule_id + "/" + path.name for rule_id, path, _ in CASES]


def aws_cli(tmp_path, command, request):
    """Run an AWS CLI command with its input in a temp file; return parsed JSON."""
    request_file = tmp_path / "request.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    result = subprocess.run(
        ["aws", *command, "--cli-input-json", "file://" + request_file.as_posix(),
         "--output", "json"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("rule_id, path, should_match", CASES, ids=IDS)
def test_eventbridge_pattern_with_aws(tmp_path, rule_id, path, should_match):
    response = aws_cli(tmp_path, ["events", "test-event-pattern"], {
        "EventPattern": json.dumps(RULES[rule_id]["eventbridge_pattern"]),
        "Event": json.dumps(load_json(path)),
    })
    assert response["Result"] == should_match


@pytest.mark.parametrize("rule_id, path, should_match", CASES, ids=IDS)
def test_cloudwatch_filter_with_aws(tmp_path, rule_id, path, should_match):
    response = aws_cli(tmp_path, ["logs", "test-metric-filter"], {
        "filterPattern": RULES[rule_id]["cloudwatch_filter_pattern"],
        "logEventMessages": [json.dumps(load_json(path)["detail"])],
    })
    assert bool(response.get("matches")) == should_match
