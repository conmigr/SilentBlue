"""Host verdicts from a read-only panel. Source stays unchanged."""

from __future__ import annotations

import json

import pytest

from silentblue.models import RemediationCase
from silentblue.remediate import run_remediate
from silentblue.runner import run_scan
from silentblue.validate import host_verdict, run_validate
from tests.test_remediate import SAFE, SOURCE, ScriptedClient


class RecordingClient:
    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.systems: list[str] = []
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.systems.append(system)
        self.prompts.append(user)
        if not self.replies:
            raise RuntimeError("no scripted reply")
        return self.replies.pop(0)


class Boom:
    def complete(self, system: str, user: str) -> str:
        raise AssertionError("model was called")


@pytest.mark.parametrize(
    ("votes", "expected"),
    [
        (["fixed", "fixed", "fixed"], "fixed"),
        (["fixed", "fixed", "partial"], "fixed"),
        (["partial", "partial", "fixed"], "partial"),
        (["not_fixed", "not_fixed", "fixed"], "not_fixed"),
        (["fixed", "not_fixed", "partial"], "not_fixed"),
        (["inconclusive", "inconclusive", "fixed"], "inconclusive"),
        ([], "inconclusive"),
        (["bogus"], "inconclusive"),
    ],
)
def test_host_verdict_uses_majority_and_breaks_ties_conservatively(votes, expected):
    assert host_verdict(votes) == expected


def _prepare(workspace, replacement: dict):
    (workspace["repo"] / "app.py").write_text(SOURCE, encoding="utf-8")
    scanned = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert scanned.exit_code == 0
    drafted = run_remediate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=ScriptedClient([json.dumps(replacement)]),
    )
    assert drafted.exit_code == 0
    return workspace["repo"] / "app.py"


def _votes(vote: str) -> list[str]:
    return [json.dumps({"vote": vote, "reason": "Reviewed the patched file."}) for _ in range(3)]


def test_panel_records_fixed_without_changing_source(workspace):
    source = _prepare(workspace, SAFE)
    before = source.read_bytes()
    client = RecordingClient(_votes("fixed"))
    result = run_validate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=client,
    )
    assert result.exit_code == 0
    assert result.model_calls == 3
    assert list(result.verdicts.values()) == ["fixed"]
    assert source.read_bytes() == before
    names = {path.name for path in workspace["repo"].iterdir()}
    assert "silentblue-validate-" not in "".join(names)
    assert [system.split(" for Silent Blue")[0] for system in client.systems] == [
        "You are the security architect",
        "You are the control owner",
        "You are the regression reviewer",
    ]
    patched = '2|    conn.execute("SELECT name FROM users WHERE name = ?", (name,))'
    assert any(patched in prompt for prompt in client.prompts)
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["validation"]["verdict"] == "fixed"
    assert case["validation"]["detector_cleared"] is True
    assert case["applied"] is False
    assert [vote["role"] for vote in case["validation"]["votes"]] == [
        "security architect",
        "control owner",
        "regression reviewer",
    ]


def test_host_downgrades_fixed_when_the_detector_still_matches(workspace):
    source = _prepare(
        workspace,
        {
            "summary": "Leave the query as it is.",
            "start_line": 2,
            "end_line": 2,
            "replacement": '    conn.execute("SELECT " + name)',
        },
    )
    before = source.read_bytes()
    result = run_validate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=RecordingClient(_votes("fixed")),
    )
    assert result.exit_code == 0
    assert list(result.verdicts.values()) == ["partial"]
    assert source.read_bytes() == before
    case = json.loads(next((workspace["repo"] / "security-remediation").glob("sb1_*.json")).read_text(encoding="utf-8"))
    assert case["validation"]["verdict"] == "partial"
    assert case["validation"]["detector_cleared"] is False
    assert "detector still reports" in case["validation"]["reason"]


def test_refused_case_is_skipped_without_a_model_call(workspace):
    case = RemediationCase(
        case_id="sb1_" + "c" * 32,
        rule_id="sql-unparameterized",
        control_family="injection",
        playbook="injection",
        severity="high",
        title="Query text is assembled",
        file="app.py",
        line=2,
        mode="report-only",
        status="refused",
        refusal="control_disabled",
        generated_at="2026-01-01T00:00:00Z",
    )
    directory = workspace["repo"] / "security-remediation"
    directory.mkdir()
    (directory / f"{case.case_id}.json").write_text(case.model_dump_json(indent=2), encoding="utf-8")
    (workspace["repo"] / "app.py").write_text(SOURCE, encoding="utf-8")
    before = (workspace["repo"] / "app.py").read_bytes()
    result = run_validate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=Boom(),
    )
    assert result.exit_code == 0
    assert result.model_calls == 0
    assert result.verdicts[case.case_id] == "skipped"
    assert (workspace["repo"] / "app.py").read_bytes() == before
