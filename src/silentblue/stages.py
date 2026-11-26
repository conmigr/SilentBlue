"""Analysis stages for detect and assess scans."""

from __future__ import annotations

from pathlib import Path

from silentblue.assess import bind_assessment, run_d2, run_d3, run_d4, run_d6
from silentblue.context import build_context
from silentblue.detectors import deduplicate, detect
from silentblue.errors import UsageError
from silentblue.models import RunState
from silentblue.rank import prioritize
from silentblue.runtime import StageContext
from silentblue.scope import collect_scope


def run_d0(state: RunState, ctx: StageContext) -> RunState:
    """Inventory the repository."""

    scope = collect_scope(
        Path(state.repo),
        ctx.config.scope,
        extra_exclude_dirs={ctx.config.output.dirname},
    )
    if not scope.files:
        raise UsageError("empty scope: no files left after exclusions")
    return state.model_copy(update={"scope": scope})


def run_d1(state: RunState, ctx: StageContext) -> RunState:
    """Build the shared context package. No model call."""

    if state.scope is None:
        raise UsageError("scope is missing")
    return state.model_copy(update={"context": build_context(state.scope)})


def run_d5(state: RunState, ctx: StageContext) -> RunState:
    """Bind cited lines to disk, then add deterministic detector rows."""

    if state.scope is None:
        raise UsageError("scope is missing")
    bound, dropped = bind_assessment(state)
    detected, detect_dropped = detect(Path(state.repo), state.scope)
    cleared = set(state.cleared_keys)
    existing = {f"{item.file}|{item.line}|{item.rule_id}" for item in bound}
    fresh = [
        item
        for item in detected
        if f"{item.file}|{item.line}|{item.rule_id}" not in existing
        and f"{item.file}|{item.line}|{item.rule_id}" not in cleared
    ]
    return ctx.stamp(
        state.model_copy(
            update={
                "findings": [*bound, *fresh],
                "dropped": [*state.dropped, *dropped, *detect_dropped],
            }
        )
    )


def run_d7(state: RunState, ctx: StageContext) -> RunState:
    """Collapse duplicate detector hits."""

    findings, dropped = deduplicate(state.findings)
    return ctx.stamp(
        state.model_copy(update={"findings": findings, "dropped": [*state.dropped, *dropped]})
    )


def run_d8(state: RunState, ctx: StageContext) -> RunState:
    """Rank gaps and mint case ids."""

    return ctx.stamp(state.model_copy(update={"findings": prioritize(state.findings)}))


STAGE_RUNNERS = {
    "d0": run_d0,
    "d1": run_d1,
    "d2": run_d2,
    "d3": run_d3,
    "d4": run_d4,
    "d5": run_d5,
    "d6": run_d6,
    "d7": run_d7,
    "d8": run_d8,
}
