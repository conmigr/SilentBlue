"""Load operator settings from a local env file.

Values already present in the process environment stay as they are.
A file inside the repository being scanned is ignored.
"""

from __future__ import annotations

import os
from pathlib import Path

from silentblue.paths import is_reparse_point, is_within

_MAX_BYTES = 64 * 1024


def load_operator_env(
    repo: Path | None,
    cwd: Path,
    *,
    extra_roots: list[Path] | None = None,
) -> list[Path]:
    """Apply Silent Blue keys from the operator's env files. Returns files read."""

    if os.environ.get("SILENTBLUE_DOTENV") == "0":
        return []
    roots = [repo] if repo is not None else []
    roots.extend(extra_roots or [])
    loaded: list[Path] = []
    for path in (Path.home() / ".silentblue" / ".env", cwd / ".env"):
        if any(is_within(root, path) for root in roots):
            continue
        if _apply(path):
            loaded.append(path)
    return loaded


def _apply(path: Path) -> bool:
    if is_reparse_point(path) or not path.is_file():
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    if len(raw) > _MAX_BYTES or b"\0" in raw[:1024]:
        return False
    for line in raw.decode("utf-8", errors="replace").splitlines():
        parsed = _assignment(line)
        if parsed is None:
            continue
        key, value = parsed
        if os.environ.get(key, "").strip():
            continue
        os.environ[key] = value
    return True


def _assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].strip()
    if "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    key = key.strip()
    if not _allowed(key):
        return None
    return key, _unquote(value.strip())


def _allowed(key: str) -> bool:
    return key.startswith("SILENTBLUE_") and key.isidentifier() and key != "SILENTBLUE_DOTENV"


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
