"""Assess reviews units together and a stopped scan can continue."""

from __future__ import annotations

import json
import threading
import time

from silentblue.runner import run_scan
from silentblue.session import Session


class _ReviewClient:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.inside = 0
        self.peak = 0
        self.reviews: list[str] = []

    def complete(self, system: str, user: str) -> str:
        if "Source excerpts" not in user:
            return json.dumps({"objectives": []})
        with self.lock:
            self.inside += 1
            self.peak = max(self.peak, self.inside)
            self.reviews.append(user)
        time.sleep(0.4)
        with self.lock:
            self.inside -= 1
        return json.dumps({"gaps": []})


def _files(repo, count: int) -> None:
    for index in range(count):
        (repo / f"file{index}.py").write_text("value = 1\n", encoding="utf-8")


def test_review_units_overlap(workspace, monkeypatch):
    monkeypatch.setenv("SILENTBLUE_WORKERS", "4")
    _files(workspace["repo"], 8)
    client = _ReviewClient()
    result = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=client,
    )
    assert result.exit_code == 0
    assert client.peak >= 2
    assert len(client.reviews) == 2
    findings = json.loads(
        next((workspace["repo"] / "security-scan").glob("*findings.json")).read_text(encoding="utf-8")
    )
    assert "Model read 8 of 8 list paths" in findings["summary"]
    assert findings["metrics"]["files_reviewed"] == 8
    assert findings["metrics"]["source_files"] == 8


def test_stop_leaves_the_next_unit_and_resume_skips_the_finished_one(workspace, monkeypatch):
    monkeypatch.setenv("SILENTBLUE_WORKERS", "1")
    _files(workspace["repo"], 8)
    stop = threading.Event()

    class Stopping(_ReviewClient):
        def complete(self, system: str, user: str) -> str:
            if "Source excerpts" in user:
                stop.set()
            return super().complete(system, user)

    first = Stopping()
    stopped = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=first,
        stop_event=stop,
    )
    assert "scan stopped" in stopped.message
    assert len(first.reviews) == 1
    checkpoint = json.loads(next(workspace["state"].rglob("d4.json")).read_text(encoding="utf-8"))
    assert checkpoint["complete"] is False
    assert len(checkpoint["state"]["reviewed_units"]) == 1

    second = _ReviewClient()
    resumed = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        profile="assess",
        client=second,
        resume=True,
    )
    assert resumed.exit_code == 0
    assert len(second.reviews) == 1
    assert first.reviews[0] != second.reviews[0]


def test_status_shows_a_running_scan(workspace):
    lines: list[str] = []
    session = Session(
        workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        reader=lambda: "",
        writer=lines.append,
    )
    session.resolved_state = workspace["state"]
    session._progress.update(
        running=True,
        profile="assess",
        stage="d4",
        units_done=2,
        units_total=9,
        files_queued=8,
        source_files=40,
        model_calls=5,
    )
    session._status()
    text = "\n".join(lines)
    assert "scan  running" in text
    assert "units  2 of 9" in text
    assert "source files  8 queued of 40" in text
    assert "model calls  5" in text
    session._thread = threading.current_thread()
    session._dispatch("/scan")
    assert lines[-1] == "A scan is already running. Type /status."
