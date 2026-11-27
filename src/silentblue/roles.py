"""Path roles. A role changes the owner action. It does not drop the row."""

from __future__ import annotations

import re

from silentblue.evidence import is_document

_TEST_PARTS = frozenset({"tests", "test", "__tests__", "spec", "testing"})
_SPECIMEN_PARTS = frozenset({"examples", "example", "samples", "demo", "demos"})
_TEST_NAME = re.compile(r"(?i)(^test_|_test\.|_spec\.|\.test\.|\.spec\.)")


def path_role(path: str) -> str:
    """product, test, specimen, or docs, from the path alone."""

    if is_document(path):
        return "docs"
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    if any(part.lower() in _SPECIMEN_PARTS for part in parts):
        return "specimen"
    name = parts[-1] if parts else ""
    if any(part.lower() in _TEST_PARTS for part in parts[:-1]) or _TEST_NAME.search(name):
        return "test"
    return "product"
