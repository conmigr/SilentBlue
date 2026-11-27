"""Owner confirm for a test secret, stored outside the repository.

The record holds a hash of the line. A changed line opens the row again.
The line itself is not stored.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from silentblue.errors import UsageError
from silentblue.paths import is_reparse_point, is_within

_CASE = re.compile(r"^sb1_[0-9a-f]{32}$")


class ConfirmEntry(BaseModel):
    """One owner confirm, bound to the line that was shown."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    path: str
    rule_id: str
    line_hash: str
    reason: str
    recorded_at: str = ""


def confirm_path(state_dir: Path, repo: Path) -> Path:
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir / "confirm" / f"{digest}.json"


def line_hash(repo: Path, relative: str, line: int) -> str | None:
    """Hash one source line. The line is not returned."""

    path = repo / relative
    if not is_within(repo, path) or is_reparse_point(path):
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, content in enumerate(handle, start=1):
                if number != line:
                    continue
                if "\0" in content:
                    return None
                text = content.rstrip("\n\r")
                return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except OSError:
        return None
    return None


def load_confirms(state_dir: Path, repo: Path) -> list[ConfirmEntry]:
    path = confirm_path(state_dir, repo)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return []
    entries: list[ConfirmEntry] = []
    for item in data["entries"]:
        try:
            entries.append(ConfirmEntry.model_validate(item))
        except ValueError:
            continue
    return entries


def record_confirm(state_dir: Path, repo: Path, entry: ConfirmEntry) -> None:
    """Write one confirm. The repository cannot hold this file."""

    if is_within(repo.resolve(), state_dir.resolve()):
        raise UsageError("state directory must be outside the repository")
    if _CASE.fullmatch(entry.case_id) is None:
        raise UsageError("confirm needs a case id")
    if not entry.line_hash or len(entry.line_hash) != 64:
        raise UsageError("confirm needs the current line")
    if not entry.reason.strip() or len(entry.reason) > 400:
        raise UsageError("confirm needs a reason")
    path = confirm_path(state_dir, repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = [item for item in load_confirms(state_dir, repo) if item.case_id != entry.case_id]
    entries.append(entry)
    entries.sort(key=lambda item: item.case_id)
    payload = {"entries": [item.model_dump(mode="json") for item in entries]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def confirm_status(state_dir: Path, repo: Path, case_id: str, digest: str | None) -> str:
    """recorded when the hash matches, stale when the line changed, else empty."""

    for entry in load_confirms(state_dir, repo):
        if entry.case_id != case_id:
            continue
        if digest and entry.line_hash == digest:
            return "recorded"
        return "stale"
    return ""
