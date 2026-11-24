"""Detect-only scans across a list of repositories."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from silentblue.envfile import load_operator_env
from silentblue.errors import SilentBlueError, UsageError
from silentblue.manifest import write_manifest
from silentblue.models import BatchRepoResult, BatchResult
from silentblue.paths import is_reparse_point, is_within
from silentblue.redact import configure_logging, redact
from silentblue.runner import resolve_state_dir, run_scan

logger = logging.getLogger(__name__)

_MAX_LIST_BYTES = 64 * 1024
_MAX_REPOS = 100


def run_batch(
    *,
    repo_list: Path,
    state_dir: Path | None = None,
    manifest_dir: Path | None = None,
    cwd: Path | None = None,
    argv: list[str] | None = None,
) -> BatchResult:
    """Scan every listed repository with the detect profile. Model calls stay at zero."""

    configure_logging()
    exit_code = 0
    message = "ok"
    rows: list[BatchRepoResult] = []
    summary_path: str | None = None
    try:
        paths = _read_list(repo_list)
        roots = [Path(raw).expanduser() for raw in paths]
        load_operator_env(None, cwd or Path.cwd(), extra_roots=roots)
        state = resolve_state_dir(state_dir, cwd or Path.cwd())
        for raw in paths:
            root = Path(raw).expanduser()
            if is_within(root, state):
                rows.append(
                    BatchRepoResult(
                        repo=root.name,
                        exit_code=2,
                        message="state directory must be outside the repository",
                    )
                )
                continue
            result = run_scan(
                repo=root,
                state_dir=state,
                manifest_dir=manifest_dir or cwd or Path.cwd(),
                cwd=cwd or Path.cwd(),
                argv=argv or [],
                profile="detect",
            )
            rows.append(
                BatchRepoResult(
                    repo=root.name,
                    exit_code=result.exit_code,
                    finding_count=result.finding_count,
                    message=result.message,
                    model_calls=_calls(result.findings_path),
                )
            )
        failed = sum(row.exit_code != 0 for row in rows)
        message = f"scanned {len(rows)} repositories, {failed} failed"
        if failed:
            exit_code = 1
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
        logger.warning("%s", message)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
        logger.exception("batch failed")
    model_calls = sum(row.model_calls for row in rows)
    try:
        summary_path = str(
            write_manifest(
                manifest_dir or cwd or Path.cwd(),
                {
                    "command": "batch",
                    "argv": argv or [],
                    "exit_code": exit_code,
                    "message": message,
                    "repos": [row.model_dump() for row in rows],
                    "model_calls": model_calls,
                },
            )
        )
    except OSError as exc:
        logger.warning("manifest was not written: %s", exc.strerror or "unwritable")
    return BatchResult(
        exit_code=exit_code,
        message=message,
        repos=rows,
        model_calls=model_calls,
        summary_path=summary_path,
    )


def _read_list(path: Path) -> list[str]:
    if is_reparse_point(path) or not path.is_file():
        raise UsageError("repo list must be a real file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UsageError("repo list must be a real file") from exc
    if len(raw) > _MAX_LIST_BYTES or b"\0" in raw[:1024]:
        raise UsageError("repo list is not a text file")
    rows: list[str] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rows.append(stripped)
    if not rows:
        raise UsageError("empty repo list")
    if len(rows) > _MAX_REPOS:
        raise UsageError("repo list is limited to 100 repositories")
    return rows


def _calls(findings_path: str | None) -> int:
    if not findings_path:
        return 0
    try:
        payload = json.loads(Path(findings_path).read_text(encoding="utf-8"))
        return int(payload.get("metrics", {}).get("model_calls", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0
