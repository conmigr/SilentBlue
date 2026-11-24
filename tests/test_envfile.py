"""Operator env files stay out of the repository being scanned."""

from __future__ import annotations

import os
from pathlib import Path

from silentblue.envfile import load_operator_env


def _home(monkeypatch, home: Path) -> None:
    monkeypatch.delenv("SILENTBLUE_DOTENV", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))


def test_operator_file_fills_an_empty_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SILENTBLUE_API_KEY", "")
    monkeypatch.setenv("SILENTBLUE_MODEL", "")
    monkeypatch.setenv("SILENTBLUE_BASE_URL", "")
    home = tmp_path / "home"
    _home(monkeypatch, home)
    env_file = home / ".silentblue" / ".env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text(
        "\n".join(
            [
                "# operator settings",
                "SILENTBLUE_API_KEY=operator-key",
                'SILENTBLUE_MODEL="gpt-4o-mini"',
                "DATABASE_URL=ignore-me",
                "export SILENTBLUE_BASE_URL=https://example.invalid/v1",
            ]
        ),
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    loaded = load_operator_env(repo, tmp_path)
    assert loaded == [env_file]
    assert os.environ["SILENTBLUE_API_KEY"] == "operator-key"
    assert os.environ["SILENTBLUE_MODEL"] == "gpt-4o-mini"
    assert os.environ["SILENTBLUE_BASE_URL"] == "https://example.invalid/v1"
    assert os.environ.get("DATABASE_URL") != "ignore-me"


def test_existing_environment_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("SILENTBLUE_MODEL", "already")
    home = tmp_path / "home"
    _home(monkeypatch, home)
    env_file = home / ".silentblue" / ".env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("SILENTBLUE_MODEL=from-file\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    load_operator_env(repo, tmp_path)
    assert os.environ["SILENTBLUE_MODEL"] == "already"


def test_env_file_inside_the_repository_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("SILENTBLUE_API_KEY", "")
    home = tmp_path / "home"
    _home(monkeypatch, home)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("SILENTBLUE_API_KEY=from-the-target\n", encoding="utf-8")
    loaded = load_operator_env(repo, repo)
    assert loaded == []
    assert os.environ.get("SILENTBLUE_API_KEY", "") == ""
