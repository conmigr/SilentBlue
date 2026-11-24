"""Run manifests for commands that sit beside scan."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from silentblue import __version__
from silentblue.redact import redact


def write_manifest(directory: Path, payload: dict) -> Path:
    """Write a redacted manifest. The caller supplies command-specific fields."""

    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"run_manifest_{stamp}.json"
    suffix = 1
    while path.exists():
        path = directory / f"run_manifest_{stamp}_{suffix:02d}.json"
        suffix += 1
    body = {
        "tool": "silentblue",
        "version": __version__,
        **payload,
    }
    if isinstance(body.get("message"), str):
        body["message"] = redact(body["message"])
    if isinstance(body.get("argv"), list):
        body["argv"] = [redact(item) if isinstance(item, str) else item for item in body["argv"]]
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path
