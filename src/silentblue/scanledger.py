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


def ledger_for(
    scope: ScopeResult | None,
    *,
    unread: list[str] | None = None,
    read: list[str] | None = None,
    skips: dict[str, str] | None = None,
    review_paths: list[str] | None = None,
    stop: str = "",
    refute: str = "",
    miss: str = "",
) -> CoverageLedger:
    """Build the detector ledger and, when a review list exists, the model ledger."""

    read_set = set(read or [])
    skip_map = dict(skips or {})
    listed = list(review_paths or [])
    listed_set = set(listed)
    pending = [path for path in listed if path not in read_set and path not in skip_map]
    if unread is not None and review_paths is None:
        pending = list(unread)
    rows: list[CoverageRow] = []
    if scope is not None:
        for item in scope.files:
            rows.append(_checked(item.path, item.language, listed_set, read_set, skip_map))
        for skip in scope.file_skips:
            rows.append(CoverageRow(path=skip.path, reason=skip.reason))
    rows.sort(key=lambda row: row.path)
    saturated = bool(rows) and all(row.families or row.reason for row in rows)
    model_saturated = bool(listed) and not pending and not skip_map
    return CoverageLedger(
        saturated=saturated,
        model_saturated=model_saturated,
        rows=rows,
        unread=pending,
        stop=stop,
        refute=refute,
        miss=miss,
    )


def ledger_from_state(state: RunState) -> CoverageLedger:
    """Ledger for a finished or partial run."""

    return ledger_for(
        state.scope,
        read=_read(state),
        skips=state.review_skips,
        review_paths=state.review_paths,
        stop=state.review_stop,
        refute=state.refute_status,
        miss=state.miss_status,
    )


def _checked(
    path: str,
    language: str,
    listed: set[str],
    read: set[str],
    skips: dict[str, str],
) -> CoverageRow:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    model_state = _model_state(path, listed, read, skips)
    if language in SOURCE_LANGUAGES:
        families = list(_CODE_FAMILIES)
        if _supply(path, name):
            families.append("supply-chain")
        return CoverageRow(path=path, language=language, families=families, model_state=model_state)
    if _supply(path, name):
        return CoverageRow(path=path, language=language, families=["supply-chain"], model_state=model_state)
    return CoverageRow(
        path=path,
        language=language,
        reason="outside a language pack",
        model_state=model_state,
    )


def _model_state(path: str, listed: set[str], read: set[str], skips: dict[str, str]) -> str:
    if not listed:
        return ""
    if path in read:
        return "read"
    if path in skips:
        return f"skipped: {skips[path]}"
    if path in listed:
        return "unread"
    return "not on the review list"


def _supply(path: str, name: str) -> bool:
    portable = path.replace("\\", "/")
    if name.startswith("requirements") or name in _SUPPLY_NAMES:
        return True
    return "/.github/workflows/" in f"/{portable}"


def _read(state: RunState) -> list[str]:
    if not state.review_paths:
        return []
    reviewed = set(state.reviewed_units)
    listed = set(state.review_paths)
    skipped = set(state.review_skips)
    seen: list[str] = []
    for unit in state.units:
        if unit.unit_id not in reviewed:
            continue
        for path in unit.paths:
            if path in listed and path not in skipped and path not in seen:
                seen.append(path)
    return seen
