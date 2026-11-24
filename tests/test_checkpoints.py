"""Checkpoint load, discard, and retention."""

from __future__ import annotations

import os
import time

from silentblue import __version__
from silentblue.checkpoints import CheckpointStore, prune_runs
from silentblue.models import RunState


def _state(repo: str) -> RunState:
    return RunState(
        tool_version=__version__,
        run_id="abc",
        repo=repo,
        repo_name="repo",
        started_at="2026-01-01T00:00:00Z",
        stop_after="d0",
    )


def test_corrupt_checkpoint_is_discarded(tmp_path):
    store = CheckpointStore(tmp_path / "run")
    store.reset()
    state = _state(str(tmp_path / "repo"))
    store.save("d0", state)
    loaded = store.load("d0", repo=state.repo, tool_version=state.tool_version)
    assert loaded is not None
    assert loaded.repo == state.repo

    (store.checkpoint_dir / "d0.json").write_text("{", encoding="utf-8")
    assert store.load("d0", repo=state.repo, tool_version=state.tool_version) is None


def test_checkpoint_identity_mismatch_is_discarded(tmp_path):
    store = CheckpointStore(tmp_path / "run")
    store.reset()
    state = _state(str(tmp_path / "repo"))
    store.save("d0", state)
    assert store.load("d0", repo="elsewhere", tool_version=state.tool_version) is None
    assert store.load("d0", repo=state.repo, tool_version="0.0.0") is None


def test_gc_prunes_old_runs_and_dry_run_keeps_them(tmp_path):
    state = tmp_path / "state"
    old = state / "runs" / "old"
    new = state / "runs" / "new"
    old.mkdir(parents=True)
    new.mkdir()
    aged = time.time() - 10 * 86400
    os.utime(old, (aged, aged))

    preview = prune_runs(state, keep_runs=10, max_age_days=5, dry_run=True)
    assert old in preview
    assert old.exists() and new.exists()

    removed = prune_runs(state, keep_runs=10, max_age_days=5, dry_run=False)
    assert old in removed
    assert not old.exists()
    assert new.exists()
