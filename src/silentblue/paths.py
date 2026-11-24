"""Repository boundary checks."""

from __future__ import annotations

import os
from pathlib import Path


_REPARSE_POINT = 0x400


def is_reparse_point(path: Path) -> bool:
    """Return True for symlinks and other links, including Windows junctions."""

    try:
        if path.is_symlink():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & _REPARSE_POINT)


def is_within(root: Path, candidate: Path) -> bool:
    """Return True when ``candidate`` resolves to ``root`` or a path inside it."""

    try:
        root_resolved = root.resolve()
        candidate_resolved = candidate.resolve()
    except OSError:
        return False
    root_key = os.path.normcase(os.path.normpath(str(root_resolved)))
    candidate_key = os.path.normcase(os.path.normpath(str(candidate_resolved)))
    if candidate_key == root_key:
        return True
    prefix = root_key.rstrip("\\/") + os.sep
    return candidate_key.startswith(prefix)
