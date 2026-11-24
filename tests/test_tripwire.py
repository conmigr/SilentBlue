"""The tree stays free of upstream harness names."""

from __future__ import annotations

from pathlib import Path

_SKIP = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
}


def _needles() -> list[str]:
    parts = (
        ("vva", "harness"),
        ("visa-", "vulnerability"),
        ("glass", "wing"),
        ("myth", "os"),
        ("red", " team"),
    )
    return [left + right for left, right in parts]


def test_repository_has_no_upstream_names():
    root = Path(__file__).resolve().parents[1]
    banned = [needle.lower() for needle in _needles()]
    hits: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP or part.endswith(".egg-info") for part in path.parts):
            continue
        data = path.read_bytes()
        if b"\0" in data[:1024]:
            continue
        text = data.decode("utf-8", errors="ignore").lower()
        for needle in banned:
            if needle in text:
                hits.append(f"{path.name}: {needle}")
    assert hits == []
