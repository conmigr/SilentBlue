"""Coverage ledger for one scan. A row is checked, or it carries a skip reason."""

from __future__ import annotations

from silentblue.models import CoverageLedger, CoverageRow, RunState, ScopeResult
from silentblue.playbooks import PLAYBOOKS
from silentblue.scope import SOURCE_LANGUAGES

_CODE_FAMILIES = tuple(name for name in PLAYBOOKS if name != "supply-chain")
_SUPPLY_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "uv.lock",
        "go.mod",
        "go.sum",
        "cargo.lock",
        "gemfile.lock",
        "composer.lock",
        "gradle.lockfile",
        "packages.lock.json",
        "conan.lock",
        "pyproject.toml",
        "pom.xml",
        "constraints.txt",
    }
)


def ledger_for(scope: ScopeResult | None, *, unread: list[str] | None = None) -> CoverageLedger:
    """Build the ledger from the inventory and any review paths still unread."""

    rows: list[CoverageRow] = []
    if scope is not None:
        for item in scope.files:
            rows.append(_checked(item.path, item.language))
        for skip in scope.file_skips:
            rows.append(CoverageRow(path=skip.path, reason=skip.reason))
    rows.sort(key=lambda row: row.path)
    pending = list(unread or [])
    saturated = bool(rows) and all(row.families or row.reason for row in rows) and not pending
    return CoverageLedger(saturated=saturated, rows=rows, unread=pending)


def ledger_from_state(state: RunState) -> CoverageLedger:
    """Ledger for a finished or partial run."""

    return ledger_for(state.scope, unread=_unread(state))


def _checked(path: str, language: str) -> CoverageRow:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if language in SOURCE_LANGUAGES:
        families = list(_CODE_FAMILIES)
        if _supply(path, name):
            families.append("supply-chain")
        return CoverageRow(path=path, language=language, families=families)
    if _supply(path, name):
        return CoverageRow(path=path, language=language, families=["supply-chain"])
    return CoverageRow(path=path, language=language, reason="outside a language pack")


def _supply(path: str, name: str) -> bool:
    portable = path.replace("\\", "/")
    if name.startswith("requirements") or name in _SUPPLY_NAMES:
        return True
    return "/.github/workflows/" in f"/{portable}"


def _unread(state: RunState) -> list[str]:
    if not state.review_paths:
        return []
    reviewed = set(state.reviewed_units)
    listed = set(state.review_paths)
    read = {
        path
        for unit in state.units
        if unit.unit_id in reviewed
        for path in unit.paths
        if path in listed
    }
    return [path for path in state.review_paths if path not in read]
