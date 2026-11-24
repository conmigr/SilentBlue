"""Checkpoint store. Invalid files are discarded."""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path

from pydantic import ValidationError

from silentblue.models import CheckpointEnvelope, RunState, StageName

logger = logging.getLogger(__name__)


class CheckpointStore:
    """JSON checkpoints for one run, kept outside the target repository."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.checkpoint_dir = run_dir / "checkpoints"

    def reset(self) -> None:
        if self.run_dir.exists():
            shutil.rmtree(self.run_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save(self, stage: StageName, state: RunState, complete: bool = True) -> None:
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        envelope = CheckpointEnvelope(stage=stage, state=state, complete=complete)
        path = self.checkpoint_dir / f"{stage}.json"
        path.write_text(
            json.dumps(envelope.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )

    def load(self, stage: StageName, *, repo: str, tool_version: str) -> RunState | None:
        envelope = self._read(stage, repo=repo, tool_version=tool_version)
        if envelope is None or not envelope.complete:
            return None
        return envelope.state

    def load_partial(self, stage: StageName, *, repo: str, tool_version: str) -> RunState | None:
        """Return an in-progress checkpoint. A finished stage is not partial."""

        envelope = self._read(stage, repo=repo, tool_version=tool_version)
        if envelope is None or envelope.complete:
            return None
        return envelope.state

    def _read(self, stage: StageName, *, repo: str, tool_version: str) -> CheckpointEnvelope | None:
        path = self.checkpoint_dir / f"{stage}.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            envelope = CheckpointEnvelope.model_validate(data)
        except (OSError, json.JSONDecodeError, ValidationError):
            logger.warning("discarding checkpoint %s", stage)
            return None
        state = envelope.state
        if envelope.stage != stage or state.repo != repo or state.tool_version != tool_version:
            logger.warning("discarding checkpoint %s", stage)
            return None
        return envelope


def prune_runs(
    state_dir: Path,
    *,
    keep_runs: int,
    max_age_days: float,
    dry_run: bool,
) -> list[Path]:
    """Remove run directories that are too old or beyond the keep window."""

    runs_root = state_dir / "runs"
    if not runs_root.is_dir():
        return []
    runs = [path for path in runs_root.iterdir() if path.is_dir()]
    runs.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    now = time.time()
    max_age = max_age_days * 86400
    removed: list[Path] = []
    for index, path in enumerate(runs):
        age = now - path.stat().st_mtime
        if index >= keep_runs or age > max_age:
            removed.append(path)
            if not dry_run:
                shutil.rmtree(path)
    return removed
