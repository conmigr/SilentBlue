"""Scope boundaries."""

from __future__ import annotations

import os

import pytest

from silentblue.models import ScopeConfig
from silentblue.paths import is_within
from silentblue.runner import run_scan
from silentblue.scope import collect_scope
from tests.conftest import link_directory


def test_is_within_rejects_siblings(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "a.txt"
    inside.write_text("a", encoding="utf-8")
    outside = tmp_path / "b.txt"
    outside.write_text("b", encoding="utf-8")
    assert is_within(root, inside)
    assert is_within(root, root)
    assert not is_within(root, outside)
    assert not is_within(root, tmp_path / "root2" / "a.txt")


def test_symlink_escape_is_not_opened(workspace):
    repo = workspace["repo"]
    outside_dir = workspace["root"] / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "evil.py").write_text(
        'password = "directory-secret-value"\n'
        "def lookup(conn, name):\n"
        '    conn.execute("SELECT " + name)\n',
        encoding="utf-8",
    )
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    link_directory(repo / "linked", outside_dir)

    scope = collect_scope(repo, ScopeConfig())
    assert [item.path for item in scope.files] == ["ok.py"]
    assert "linked" in scope.symlink_escapes

    result = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 0
    report = (repo / "security-scan" / "findings.json").read_text(encoding="utf-8")
    assert "linked/evil.py" not in report
    assert "evil.py" not in report
    assert "directory-secret-value" not in report
    assert '"symlink_escapes": 1' in report


def test_inside_file_symlink_is_excluded_by_default(workspace):
    repo = workspace["repo"]
    (repo / "real.py").write_text("x = 1\n", encoding="utf-8")
    try:
        (repo / "alias.py").symlink_to(repo / "real.py")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink not permitted: {exc}")
    scope = collect_scope(repo, ScopeConfig())
    assert [item.path for item in scope.files] == ["real.py"]


def test_output_symlink_is_refused(workspace):
    repo = workspace["repo"]
    external = workspace["root"] / "external"
    external.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    link_directory(repo / "security-scan", external)
    result = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 2
    assert not (external / "findings.json").exists()
    assert result.findings_path is None


def test_state_directory_inside_repo_is_refused(workspace):
    repo = workspace["repo"]
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = run_scan(
        repo=repo,
        state_dir=repo / "state",
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 2
    assert "state directory" in result.message
    assert not (repo / "security-scan" / "findings.json").exists()
