"""Shared paths for scan tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def link_directory(link: Path, target: Path) -> None:
    """Create a directory symlink, or a Windows junction when symlinks are blocked."""

    destination = target.resolve()
    try:
        link.symlink_to(destination, target_is_directory=True)
    except (OSError, NotImplementedError):
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0 or not link.exists():
            detail = (completed.stderr or completed.stdout).strip()
            pytest.skip(f"directory link not permitted: {detail}")
    if not link.exists():
        pytest.skip("directory link was not created")


@pytest.fixture(autouse=True)
def _isolate_operator_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer env file from supplying a credential during tests."""

    monkeypatch.setenv("SILENTBLUE_DOTENV", "0")


@pytest.fixture
def workspace(tmp_path: Path) -> dict[str, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state"
    manifests = tmp_path / "manifests"
    return {"root": tmp_path, "repo": repo, "state": state, "manifests": manifests}
