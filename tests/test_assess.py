"""Assess profile with a scripted model route. No network calls."""

from __future__ import annotations

import json

import pytest

from silentblue.errors import UsageError
from silentblue.graph import build_graph
from silentblue.model import HttpModelClient
from silentblue.models import ModelConfig, ScopedFile, ScopeResult
from silentblue.runner import run_scan


class ScriptedClient:
    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        if not self.replies:
            raise RuntimeError("no scripted reply")
        return self.replies.pop(0)


def _scan(workspace, source: str, replies: list[str], name: str = "app.py"):
    (workspace["repo"] / name).write_text(source, encoding="utf-8")
    client = ScriptedClient(replies)
    result = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=client,
    )
    return result, client


def test_confirmed_gap_carries_playbook_line_and_verdict(workspace):
    source = 'def read_user(conn, name):\n    conn.execute("SELECT " + name)\n'
    result, client = _scan(
        workspace,
        source,
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
                            "title": "SQL built by concatenation",
                            "file": "app.py",
                            "line": 2,
                            "description": "The query text is assembled from a value.",
                            "remediation": "Use a bound parameter.",
                            "severity": "high",
                            "confidence": 0.8,
                        }
                    ]
                }
            ),
            json.dumps(
                {"verdict": "confirmed", "reason": "The query text is assembled on this line."}
            ),
        ],
    )
    assert result.exit_code == 0
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assessed = [item for item in report["findings"] if item["origin"] == "assessment"]
    assert len(assessed) == 1
    gap = assessed[0]
    assert gap["file"] == "app.py"
    assert gap["line"] == 2
    assert gap["playbook"] == "injection"
    assert gap["verdict"] == "confirmed"
    assert gap["case_id"].startswith("sb1_")
    assert report["profile"] == "assess"
    assert report["metrics"]["model_calls"] == 3
    assert report["hollow"] is False
    markdown = next((workspace["repo"] / "security-scan").glob("*_report.md")).read_text(encoding="utf-8")
    assert "Playbook: injection" in markdown
    assert "Verdict: confirmed" in markdown
    assert any("read_user calls execute" in prompt for prompt in client.prompts)


def test_bad_line_is_dropped(workspace):
    source = 'def read_user(conn, name):\n    conn.execute("SELECT " + name)\n'
    result, _client = _scan(
        workspace,
        source,
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
                            "title": "Missing line",
                            "file": "app.py",
                            "line": 99,
                            "description": "This line is not in the file.",
                            "remediation": "Use a bound parameter.",
                            "severity": "high",
                            "confidence": 0.4,
                        }
                    ]
                }
            ),
        ],
    )
    assert result.exit_code == 0
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert all(item["line"] != 99 for item in report["findings"])
    assert any(item["reason"] == "line_out_of_range" for item in report["dropped"])


def test_invalid_json_is_dropped_and_degrades(workspace):
    result, _client = _scan(
        workspace,
        "value = 1\n",
        [
            json.dumps(
                {
                    "objectives": [
                        {
                            "control_family": "configuration",
                            "title": "Shared configuration",
                            "rationale": "Settings",
                            "paths": ["app.py"],
                        }
                    ]
                }
            ),
            "not json",
            "still not json",
        ],
        name="app.py",
    )
    assert result.exit_code == 1
    assert "degraded" in result.message
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["hollow"] is False
    assert any(item["reason"] == "unparseable" for item in report["dropped"])


def test_empty_objectives_still_reads_source(workspace):
    result, client = _scan(
        workspace,
        "value = 1\n",
        [json.dumps({"objectives": []}), json.dumps({"gaps": []})],
    )
    assert result.exit_code == 0
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["hollow"] is False
    assert report["metrics"]["model_calls"] == 2
    assert "untrusted" not in report["summary"]
    assert any("1|value = 1" in prompt for prompt in client.prompts)


def test_assess_without_a_key_writes_no_report(workspace, monkeypatch):
    monkeypatch.delenv("SILENTBLUE_API_KEY", raising=False)
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
    )
    assert result.exit_code == 2
    assert "SILENTBLUE_API_KEY" in result.message
    assert not (workspace["repo"] / "security-scan").exists()


def test_endpoint_must_be_http(tmp_path):
    with pytest.raises(UsageError):
        HttpModelClient(ModelConfig(base_url="file:///tmp/model", api_key="local"))


def test_python_graph_records_direct_calls(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def caller():\n    callee()\n\ndef callee():\n    return 1\n", encoding="utf-8")
    scope = ScopeResult(
        files=[ScopedFile(path="app.py", size=40, language="python")]
    )
    summary = build_graph(repo, scope).summary(["app.py"])
    assert "app.py: caller calls callee" in summary
