"""Report-only remediation, the policy gate, and opt-in fix mode."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from silentblue.cli import app
from silentblue.models import RemediationCase
from silentblue.policy import review_patch
from silentblue.remediate import resolve_overlaps, run_remediate
from silentblue.runner import run_scan
from tests.conftest import link_directory

runner = CliRunner()

SOURCE = 'def read_user(conn, name):\n    conn.execute("SELECT " + name)\n'
SAFE = {
    "summary": "Pass the value as a bound parameter.",
    "start_line": 2,
    "end_line": 2,
    "replacement": '    conn.execute("SELECT name FROM users WHERE name = ?", (name,))',
}


class ScriptedClient:
    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        if not self.replies:
            raise RuntimeError("no scripted reply")
        return self.replies.pop(0)


class Boom:
    def complete(self, system: str, user: str) -> str:
        raise AssertionError("model was called")


def _case(case_id: str, start: int, end: int) -> RemediationCase:
    return RemediationCase(
        case_id=case_id,
        rule_id="sql-unparameterized",
        control_family="injection",
        playbook="injection",
        severity="high",
        title="Query text is assembled",
        file="app.py",
        line=start,
        mode="fix",
        status="proposed",
        start_line=start,
        end_line=end,
        replacement="x = 1",
        generated_at="2026-01-01T00:00:00Z",
    )


def _scan(workspace):
    (workspace["repo"] / "app.py").write_text(SOURCE, encoding="utf-8")
    return run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )


def _remediate(workspace, replies: list[str], **kwargs):
    client = ScriptedClient([json.dumps(item) if isinstance(item, dict) else item for item in replies])
    result = run_remediate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=client,
        **kwargs,
    )
    return result, client


def test_policy_accepts_a_same_file_repair():
    review = review_patch(
        finding_file="app.py",
        proposed_file="app.py",
        start_line=1,
        end_line=1,
        replacement='conn.execute("SELECT name FROM users WHERE name = ?", (name,))',
        line_count=1,
        original_span='conn.execute("SELECT " + name)',
    )
    assert review.ok
    assert review.refusal == ""


def test_policy_refuses_another_file_a_disabled_control_and_a_deleted_test():
    outside = review_patch(
        finding_file="app.py",
        proposed_file="../outside.py",
        start_line=1,
        end_line=1,
        replacement="x = 1",
        line_count=1,
        original_span="x = 0",
    )
    assert outside.refusal == "outside_path"
    disabled = review_patch(
        finding_file="client.py",
        proposed_file="client.py",
        start_line=1,
        end_line=1,
        replacement="requests.get(url, verify=False)",
        line_count=1,
        original_span="requests.get(url)",
    )
    assert disabled.refusal == "control_disabled"
    deleted = review_patch(
        finding_file="tests/test_app.py",
        proposed_file="tests/test_app.py",
        start_line=1,
        end_line=2,
        replacement="def helper():\n    return 1",
        line_count=2,
        original_span="def test_login():\n    assert True",
    )
    assert deleted.refusal == "deletes_test"


def test_overlapping_ranges_keep_the_earlier_patch():
    first = "sb1_" + "a" * 32
    second = "sb1_" + "b" * 32
    resolved = resolve_overlaps([_case(first, 2, 4), _case(second, 4, 6)])
    assert resolved[0].status == "proposed"
    assert resolved[1].status == "refused"
    assert resolved[1].refusal == "overlap"


def test_report_only_writes_the_case_and_leaves_source(workspace):
    scanned = _scan(workspace)
    source = workspace["repo"] / "app.py"
    before = source.read_bytes()
    assert scanned.exit_code == 0
    assert source.read_bytes() == before
    assert not (workspace["repo"] / "security-remediation").exists()
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["metrics"]["model_calls"] == 0
    finding = report["findings"][0]
    result, client = _remediate(workspace, [SAFE])
    assert result.exit_code == 0
    assert result.case_count == 1
    assert result.applied_count == 0
    assert result.model_calls == 1
    assert source.read_bytes() == before
    case_path = workspace["repo"] / "security-remediation" / f"{finding['case_id']}.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    assert case["case_id"] == finding["case_id"]
    assert case["playbook"] == "injection"
    assert case["file"] == "app.py"
    assert case["status"] == "proposed"
    assert case["applied"] is False
    assert case["mode"] == "report-only"
    assert "name = ?" in case["replacement"]
    assert "Playbook: injection" in client.prompts[0]
    assert result.manifest_path is not None
    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert manifest["command"] == "remediate"
    assert manifest["model_calls"] == 1


def test_fix_mode_applies_an_accepted_patch(workspace):
    _scan(workspace)
    source = workspace["repo"] / "app.py"
    result, _client = _remediate(workspace, [SAFE], mode="fix")
    assert result.exit_code == 0
    assert result.applied_count == 1
    updated = source.read_text(encoding="utf-8")
    assert "name = ?" in updated
    assert '"SELECT " + name' not in updated
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["status"] == "applied"
    assert case["applied"] is True
    assert case["mode"] == "fix"


def test_fix_mode_records_a_refusal_and_leaves_source(workspace):
    _scan(workspace)
    source = workspace["repo"] / "app.py"
    before = source.read_bytes()
    refused = {
        "summary": "Turn verification off.",
        "file": "app.py",
        "start_line": 2,
        "end_line": 2,
        "replacement": "requests.get(url, verify=False)",
    }
    result, _client = _remediate(workspace, [refused], fix=True)
    assert result.exit_code == 0
    assert result.refused_count == 1
    assert result.applied_count == 0
    assert source.read_bytes() == before
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["status"] == "refused"
    assert case["refusal"] == "control_disabled"
    assert "verify=False" in case["replacement"]
    again = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert again.exit_code == 0
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert all(not item["file"].startswith("security-remediation") for item in report["findings"])


def test_a_patch_for_another_file_is_refused(workspace):
    _scan(workspace)
    before = (workspace["repo"] / "app.py").read_bytes()
    other = {
        "summary": "Edit a different file.",
        "file": "other.py",
        "start_line": 1,
        "end_line": 1,
        "replacement": "x = 1",
    }
    result, _client = _remediate(workspace, [other], mode="fix")
    assert result.exit_code == 0
    assert result.applied_count == 0
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["refusal"] == "outside_path"
    assert (workspace["repo"] / "app.py").read_bytes() == before
    assert not (workspace["repo"] / "other.py").exists()


def test_unparseable_reply_degrades_and_leaves_source(workspace):
    _scan(workspace)
    before = (workspace["repo"] / "app.py").read_bytes()
    result, _client = _remediate(workspace, ["not json", "still not json"])
    assert result.exit_code == 1
    assert "degraded" in result.message
    assert result.model_calls == 2
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["status"] == "refused"
    assert case["refusal"] == "unparseable"
    assert (workspace["repo"] / "app.py").read_bytes() == before


def test_inconclusive_gap_is_not_a_case(workspace, monkeypatch):
    monkeypatch.delenv("SILENTBLUE_API_KEY", raising=False)
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    scanned = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=ScriptedClient(
            [
                json.dumps(
                    {
                        "objectives": [
                            {
                                "control_family": "injection",
                                "title": "Query construction",
                                "rationale": "Database calls",
                                "paths": ["app.py"],
                            }
                        ]
                    }
                ),
                json.dumps(
                    {
                        "gaps": [
                            {
                                "control_family": "injection",
                                "playbook": "injection",
                                "title": "Unclear query",
                                "file": "app.py",
                                "line": 1,
                                "description": "The line does not show a query.",
                                "remediation": "Keep the query text constant.",
                                "severity": "low",
                                "confidence": 0.2,
                            }
                        ]
                    }
                ),
                json.dumps({"verdict": "inconclusive", "reason": "The line is an assignment."}),
            ]
        ),
    )
    assert scanned.exit_code == 0
    result = run_remediate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=Boom(),
    )
    assert result.exit_code == 0
    assert result.case_count == 0
    assert result.message == "no confirmed gaps"
    assert not (workspace["repo"] / "security-remediation").exists()


def test_missing_key_writes_nothing(workspace, monkeypatch):
    monkeypatch.delenv("SILENTBLUE_API_KEY", raising=False)
    _scan(workspace)
    result = run_remediate(repo=workspace["repo"], manifest_dir=workspace["manifests"])
    assert result.exit_code == 2
    assert "SILENTBLUE_API_KEY" in result.message
    assert not (workspace["repo"] / "security-remediation").exists()


def test_remediation_junction_is_refused(workspace):
    outside = workspace["root"] / "escaped"
    outside.mkdir()
    link_directory(workspace["repo"] / "security-remediation", outside)
    result, _client = _remediate(workspace, [SAFE])
    assert result.exit_code == 2
    assert "remediation directory" in result.message
    assert list(outside.glob("sb1_*.json")) == []


def test_cli_remediate_requires_a_key(workspace, monkeypatch):
    monkeypatch.delenv("SILENTBLUE_API_KEY", raising=False)
    _scan(workspace)
    invoked = runner.invoke(
        app,
        ["remediate", "--repo", str(workspace["repo"]), "--manifest-dir", str(workspace["manifests"])],
    )
    assert invoked.exit_code == 2
    assert "SILENTBLUE_API_KEY" in invoked.stderr
    assert not (workspace["repo"] / "security-remediation").exists()
