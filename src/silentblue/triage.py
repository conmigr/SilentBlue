"""Disposition recorded beside a case id, outside the repository."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from silentblue.errors import UsageError
from silentblue.paths import is_within

_CASE = re.compile(r"^sb1_[0-9a-f]{32}$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TriageEntry(BaseModel):
    """One operator decision for a case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    disposition: str = Field(pattern="^(open|assigned|accepted)$")
    owner: str = ""
    reason: str = ""
    expires: str = ""
    recorded_at: str = ""


def triage_path(state_dir: Path, repo: Path) -> Path:
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir / "triage" / f"{digest}.json"


def load_entries(state_dir: Path, repo: Path) -> list[TriageEntry]:
    path = triage_path(state_dir, repo)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return []
    entries: list[TriageEntry] = []
    for item in data["entries"]:
        try:
            entries.append(TriageEntry.model_validate(item))
        except ValueError:
            continue
    return entries


def record_entry(state_dir: Path, repo: Path, entry: TriageEntry) -> None:
    """Write one decision. The repository cannot hold this file."""

    if is_within(repo.resolve(), state_dir.resolve()):
        raise UsageError("state directory must be outside the repository")
    if _CASE.fullmatch(entry.case_id) is None:
        raise UsageError("triage needs a case id")
    if entry.disposition == "accepted" and not _valid_day(entry.expires):
        raise UsageError("accepted risk needs an expiry date")
    if len(entry.owner) > 80 or len(entry.reason) > 400:
        raise UsageError("triage text is too long")
    path = triage_path(state_dir, repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = [item for item in load_entries(state_dir, repo) if item.case_id != entry.case_id]
    entries.append(entry)
    entries.sort(key=lambda item: item.case_id)
    payload = {"entries": [item.model_dump(mode="json") for item in entries]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def active_disposition(entry: TriageEntry, today: date | None = None) -> str:
    """Accepted rows return to open on the expiry date."""

    if entry.disposition != "accepted":
        return entry.disposition
    current = today or datetime.now(timezone.utc).date()
    if not _valid_day(entry.expires):
        return "open"
    year, month, day = (int(part) for part in entry.expires.split("-"))
    if date(year, month, day) <= current:
        return "open"
    return "accepted"


def accepted_case_ids(state_dir: Path, repo: Path, today: date | None = None) -> set[str]:
    """Case ids whose acceptance is still in force."""

    return {
        entry.case_id
        for entry in load_entries(state_dir, repo)
        if active_disposition(entry, today) == "accepted"
    }


def _valid_day(value: str) -> bool:
    if _DAY.fullmatch(value) is None:
        return False
    year, month, day = (int(part) for part in value.split("-"))
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True
