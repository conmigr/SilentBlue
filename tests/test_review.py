"""The model file list, and findings that stay open until a cited line clears them."""

from __future__ import annotations

import json

from silentblue.models import ScopedFile, ScopeResult
from silentblue.reviewlist import build_review_list
from silentblue.runner import run_scan


def test_the_list_keeps_an_in_repo_import_and_drops_backups(tmp_path):
    repo = tmp_path / "repo"
    (repo / "backups").mkdir(parents=True)
    (repo / ".claude" / "worktrees" / "w").mkdir(parents=True)
    (repo / "app.py").write_text("import os\nimport helper\n", encoding="utf-8")
    (repo / "helper.py").write_text("value = 1\n", encoding="utf-8")
    (repo / "backups" / "old.py").write_text("value = 1\n", encoding="utf-8")
    (repo / ".claude" / "worktrees" / "w" / "skip.py").write_text("value = 1\n", encoding="utf-8")
    files = [
        ScopedFile(path="app.py", size=20, language="python"),
        ScopedFile(path="helper.py", size=10, language="python"),
        ScopedFile(path="backups/old.py", size=10, language="python"),
        ScopedFile(path=".claude/worktrees/w/skip.py", size=10, language="python"),
    ]
    paths, note = build_review_list(repo, ScopeResult(files=files), tmp_path / "state")
    assert paths == ["app.py", "helper.py"]
    assert "Git could not be read" in note


def test_a_model_finding_stays_until_a_real_line_clears_it(workspace):
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    observation = {
        "observations": [
            {
                "file": "app.py",
                "line": 1,
                "category": "logging",
                "impact": "The value is written without a control.",
                "recommendation": "Drop the write.",
            }
        ]
    }

    class Once:
        def __init__(self, reply: str) -> None:
            self.reply = reply

        def complete(self, system: str, user: str) -> str:
            return self.reply

    first = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=Once(json.dumps(observation)),
    )
    assert first.exit_code == 1
    assert "release gate:" in first.message
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    kept = [item for item in report["findings"] if item["origin"] == "assessment"]
    assert len(kept) == 1
    case_id = kept[0]["case_id"]

    class Hold:
        def complete(self, system: str, user: str) -> str:
            assert case_id in user
            return json.dumps(
                {
                    "observations": [],
                    "cleared": [{"case_id": case_id, "file": "missing.py", "line": 1}],
                }
            )

    second = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=Hold(),
    )
    assert second.exit_code == 1
    assert "release gate:" in second.message
    again = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    still = [item for item in again["findings"] if item["origin"] == "assessment"]
    assert [item["case_id"] for item in still] == [case_id]

    class Clear:
        def complete(self, system: str, user: str) -> str:
            return json.dumps(
                {
                    "observations": [],
                    "cleared": [{"case_id": case_id, "file": "app.py", "line": 1}],
                }
            )

    third = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=Clear(),
    )
    assert third.exit_code == 0
    final = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert [item for item in final["findings"] if item["origin"] == "assessment"] == []
