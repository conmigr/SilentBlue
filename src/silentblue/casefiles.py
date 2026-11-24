"""Case files under security-remediation. Paths stay inside the repository."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import ValidationError

from silentblue.errors import UsageError
from silentblue.models import CASE_ID, FinalReport, RemediationCase
from silentblue.paths import is_reparse_point, is_within

DIRNAME = "security-remediation"
_MAX_BYTES = 512 * 1024


def assert_real_dir(repo: Path, dirname: str) -> Path:
    """Refuse a linked or escaped output directory."""

    directory = repo / dirname
    if is_reparse_point(directory) or (directory.exists() and not directory.is_dir()):
        raise UsageError("remediation directory must be a real directory inside the repository")
    if directory.exists() and not is_within(repo, directory):
        raise UsageError("remediation directory must be a real directory inside the repository")
    return directory


def findings_file(repo: Path, explicit: Path | None) -> Path:
    """Locate findings.json inside the repository."""

    path = explicit if explicit is not None else repo / "security-scan" / "findings.json"
    if not is_within(repo, path) or is_reparse_point(path) or not path.is_file():
        if explicit is None and not path.exists():
            raise UsageError("findings.json is missing; run a scan first")
        raise UsageError("findings file must be a real file inside the repository")
    return path


def load_report(path: Path) -> FinalReport:
    try:
        return FinalReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise UsageError("findings.json is not a Silent Blue report") from exc


def read_source(repo: Path, relative: str) -> str | None:
    """Read one in-scope text file. Links that leave the repository are refused."""

    path = repo / relative
    if not is_within(repo, path) or is_reparse_point(path) or not path.is_file():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192] or len(raw) > _MAX_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def case_path(repo: Path, case_id: str) -> Path:
    if CASE_ID.fullmatch(case_id) is None:
        raise UsageError("case id is not a Silent Blue case")
    return repo / DIRNAME / f"{case_id}.json"


def save_case(repo: Path, case: RemediationCase) -> Path:
    directory = assert_real_dir(repo, DIRNAME)
    directory.mkdir(parents=True, exist_ok=True)
    path = case_path(repo, case.case_id)
    if not is_within(repo, path):
        raise UsageError("case path must stay inside the repository")
    _atomic_write(path, case.model_dump_json(indent=2, exclude_none=True) + "\n")
    return path


def load_case(path: Path) -> RemediationCase:
    return RemediationCase.model_validate_json(path.read_text(encoding="utf-8"))


def list_cases(repo: Path) -> list[Path]:
    directory = repo / DIRNAME
    if is_reparse_point(directory) or not directory.is_dir() or not is_within(repo, directory):
        return []
    found: list[Path] = []
    for path in sorted(directory.glob("sb1_*.json")):
        if path.is_file() and not is_reparse_point(path) and is_within(repo, path):
            found.append(path)
    return found


def split_lines(text: str) -> tuple[list[str], bool]:
    return text.splitlines(), text.endswith("\n")


def join_lines(lines: list[str], trailing: bool) -> str:
    body = "\n".join(lines)
    if trailing:
        return body + "\n"
    return body


def span(lines: list[str], start: int, end: int) -> str:
    if start < 1 or end < start or end > len(lines):
        return ""
    return "\n".join(lines[start - 1 : end])


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)
