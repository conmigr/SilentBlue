"""Detect-only batch scans."""

from __future__ import annotations

import json
from pathlib import Path

from silentblue.batch import run_batch
from tests.conftest import link_directory
from tests.test_remediate import SOURCE


def test_batch_scans_each_repo_and_records_failures(workspace):
    good = workspace["root"] / "good"
    empty = workspace["root"] / "empty"
    good.mkdir()
    empty.mkdir()
    (good / "app.py").write_text(SOURCE, encoding="utf-8")
    (empty / "node_modules").mkdir()
    (empty / "node_modules" / "skip.js").write_text("x = 1\n", encoding="utf-8")
    listing = workspace["root"] / "repos.txt"
    listing.write_text(f"# comment\n\n{good}\n{empty}\n", encoding="utf-8")
    result = run_batch(
        repo_list=listing,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 1
    assert result.model_calls == 0
    assert len(result.repos) == 2
    assert result.repos[0].exit_code == 1
    assert "release gate:" in result.repos[0].message
    assert result.repos[0].finding_count == 1
    assert result.repos[0].model_calls == 0
    assert result.repos[1].exit_code == 2
    assert result.summary_path is not None
    summary = json.loads(Path(result.summary_path).read_text(encoding="utf-8"))
    assert summary["command"] == "batch"
    assert summary["model_calls"] == 0
    report = json.loads((good / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["profile"] == "detect"
    assert report["metrics"]["model_calls"] == 0
    assert not (empty / "security-scan").exists()


def test_empty_list_exits_2(workspace):
    listing = workspace["root"] / "repos.txt"
    listing.write_text("# nothing\n\n", encoding="utf-8")
    result = run_batch(
        repo_list=listing,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 2
    assert result.message == "empty repo list"
    assert result.repos == []


def test_list_junction_is_refused(workspace):
    outside = workspace["root"] / "list-outside"
    outside.mkdir()
    (outside / "secret.txt").write_text('password = "list-secret-value"\n', encoding="utf-8")
    link = workspace["root"] / "repos-link"
    link_directory(link, outside)
    result = run_batch(
        repo_list=link,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 2
    assert "repo list" in result.message
    assert "list-secret-value" not in result.message
