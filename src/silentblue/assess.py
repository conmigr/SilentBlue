"""Assessment stages. Prompts ask for control evidence and a typed JSON object."""

from __future__ import annotations

import json
import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from silentblue.errors import UsageError
from silentblue.graph import build_graph
from silentblue.models import (
    ControlObjective,
    DroppedFinding,
    Finding,
    RunState,
    Severity,
    WorkUnit,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.scope import is_source_path
from silentblue.threat import priority_bands
from silentblue.playbooks import PLAYBOOKS, Playbook, playbook_for
from silentblue.redact import redact
from silentblue.runtime import StageContext

_SYSTEM = (
    "You are a defensive security reviewer for Silent Blue. "
    "Report missing or weak security controls. "
    "Cite only files and lines you were shown. "
    "Describe the control to add. "
    "Return one JSON object and nothing else."
)
_FAMILIES = ", ".join(sorted(PLAYBOOKS))
_PRIORITY_WORDS = (
    "auth",
    "login",
    "token",
    "session",
    "secret",
    "password",
    "middleware",
    "crypto",
    "config",
    "api",
    "csrf",
    "jwt",
    "rate",
    "pickle",
    "redirect",
)
_REVIEW = "review"


class _ObjectiveDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_family: str
    title: str
    rationale: str = ""
    paths: list[str] = []


class _ObjectiveList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    objectives: list[_ObjectiveDraft] = []


class _GapDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    control_family: str
    playbook: str
    title: str
    file: str
    line: int
    description: str
    remediation: str = ""
    severity: str = "medium"
    confidence: float = 0.5


class _GapList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    gaps: list[_GapDraft] = []


class _ReviewDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    verdict: str
    reason: str = ""


def prepare_graph(ctx: StageContext, state: RunState) -> None:
    """Build the symbol graph once the scope exists. It stays in memory."""

    if ctx.graph_ready or state.scope is None or ctx.config.profile != "assess":
        return
    ctx.graph = build_graph(Path(state.repo), state.scope)
    ctx.graph_ready = True


def run_d2(state: RunState, ctx: StageContext) -> RunState:
    """Ask which controls this repository needs."""

    if state.scope is None or state.context is None:
        raise UsageError("context is missing")
    paths = [item.path for item in state.scope.files[:200]]
    sample = _excerpts(Path(state.repo), _ranked_source(paths)[:3], 1500)
    user = (
        f"Primary language: {state.context.primary_language}\n"
        f"Manifests: {', '.join(state.context.manifests) or 'none'}\n"
        f"Control-related paths: {', '.join(state.context.control_hints) or 'none'}\n"
        f"Allowed control families: {_FAMILIES}\n"
        "Files:\n"
        + "\n".join(paths)
        + "\n\nSource sample:\n"
        + (sample or "(no source excerpt)")
        + "\n\nReturn JSON "
        '{"objectives": [{"control_family", "title", "rationale", "paths"}]}. '
        "paths must be chosen from the file list. "
        "Name a control for every family this source needs. "
        "Return an empty objectives array only when the list has no source files."
    )
    parsed = _ask(ctx, user, _ObjectiveList)
    objectives: list[ControlObjective] = []
    if parsed is not None:
        known = {item.path for item in state.scope.files}
        for item in parsed.objectives:
            if item.control_family not in PLAYBOOKS or not item.title.strip():
                continue
            selected = [path.replace("\\", "/") for path in item.paths if path.replace("\\", "/") in known]
            objectives.append(
                ControlObjective(
                    control_family=item.control_family,
                    title=item.title.strip()[:200],
                    rationale=redact(item.rationale.strip())[:400],
                    paths=selected[: ctx.config.budgets.max_files_per_unit],
                )
            )
    return ctx.stamp(state.model_copy(update={"objectives": objectives}))


def run_d3(state: RunState, ctx: StageContext) -> RunState:
    """Turn objectives into work units. No model call."""

    if state.scope is None:
        raise UsageError("scope is missing")
    files = [item.path for item in state.scope.files]
    known = set(files)
    units: list[WorkUnit] = []
    state_dir = getattr(ctx, "state_dir", None) or (Path.home() / ".silentblue" / "state")
    bands = priority_bands(Path(state.repo), state_dir, state.scope)
    cap = ctx.config.budgets.max_files_per_unit
    if bands:
        ordered = sorted(bands, key=lambda path: (bands[path], path))
        units.extend(_preferred_units(ordered, known, ctx.config.budgets.max_units, cap))
    for index, objective in enumerate(state.objectives, start=1):
        if len(units) >= ctx.config.budgets.max_units:
            break
        chosen = _resolve_paths(objective.paths, known, files, cap)
        if not chosen:
            continue
        units.append(
            WorkUnit(
                unit_id=f"u{index}",
                control_family=objective.control_family,
                title=objective.title,
                rationale=objective.rationale,
                paths=chosen,
            )
        )
    covered = {path for unit in units for path in unit.paths}
    room = ctx.config.budgets.max_units - len(units)
    per_unit = ctx.config.budgets.max_files_per_unit
    for walk_index, chunk in enumerate(_source_chunks(files, covered, room, per_unit), start=1):
        units.append(
            WorkUnit(
                unit_id=f"w{walk_index}",
                control_family=_REVIEW,
                title="Source review",
                rationale="Read this source against every control playbook.",
                paths=chunk,
            )
        )
    return ctx.stamp(state.model_copy(update={"units": units}))


def run_d4(state: RunState, ctx: StageContext) -> RunState:
    """Check each unit against its playbook. Units already reviewed are skipped."""

    findings = list(state.findings)
    dropped = list(state.dropped)
    reviewed = list(state.reviewed_units)
    done = set(reviewed)
    pending = [unit for unit in state.units if unit.unit_id not in done]
    repo = Path(state.repo)
    queued = len({path for unit in state.units for path in unit.paths})
    source_files = 0
    if state.scope is not None:
        source_files = sum(1 for item in state.scope.files if is_source_path(item.path))
    ctx.note_progress(
        units_total=len(state.units),
        units_done=len(reviewed),
        files_queued=queued,
        source_files=source_files,
        model_calls=ctx.model_calls,
    )

    def worker(unit: WorkUnit) -> tuple[str, list[Finding], list[DroppedFinding], bool]:
        return _review_unit(repo, unit, ctx)

    for unit_id, found, lost, keep in _map_work(ctx, pending, worker):
        findings.extend(found)
        dropped.extend(lost)
        if keep:
            reviewed.append(unit_id)
        state = ctx.stamp(
            state.model_copy(
                update={"findings": findings, "dropped": dropped, "reviewed_units": reviewed}
            )
        )
        if ctx.store is not None:
            ctx.store.save("d4", state, complete=False)
        ctx.note_progress(units_done=len(reviewed), model_calls=ctx.model_calls)
    return ctx.stamp(
        state.model_copy(update={"findings": findings, "dropped": dropped, "reviewed_units": reviewed})
    )


def bind_assessment(
    state: RunState,
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Keep assessment gaps whose file and line still exist on disk."""

    if state.scope is None:
        raise UsageError("scope is missing")
    allowed = {path for unit in state.units for path in unit.paths}
    scope_files = {item.path for item in state.scope.files}
    repo = Path(state.repo)
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for finding in state.findings:
        if finding.origin != "assessment":
            kept.append(finding)
            continue
        if finding.file not in scope_files or finding.file not in allowed:
            dropped.append(_drop(finding, "unbound"))
            continue
        if finding.playbook not in PLAYBOOKS or finding.playbook != finding.control_family:
            dropped.append(_drop(finding, "playbook"))
            continue
        snippet = source_line(repo, finding.file, finding.line)
        if snippet is None:
            dropped.append(_drop(finding, "line_out_of_range"))
            continue
        kept.append(finding.model_copy(update={"snippet": snippet}))
    return kept, dropped


def run_d6(state: RunState, ctx: StageContext) -> RunState:
    """Confirm, reject, or leave inconclusive each pending gap."""

    dropped = list(state.dropped)
    slots: list[Finding | None] = list(state.findings)
    pending = [index for index, finding in enumerate(slots) if finding is not None and finding.verdict == "pending"]

    def worker(index: int) -> tuple[int, Finding | None, DroppedFinding | None]:
        finding = slots[index]
        assert finding is not None
        return (index, *_review_pending(finding, ctx))

    for index, replacement, lost in _map_work(ctx, pending, worker):
        if lost is not None:
            dropped.append(lost)
        slots[index] = replacement
        ctx.note_progress(model_calls=ctx.model_calls)
    kept = [finding for finding in slots if finding is not None]
    return ctx.stamp(state.model_copy(update={"findings": kept, "dropped": dropped}))


def _map_work(ctx: StageContext, items: list, worker):
    """Run items on the worker pool. A stop or a full budget starts no further item."""

    if not items:
        return []
    workers = max(1, min(ctx.config.budgets.workers, len(items)))
    results = []
    remaining = iter(items)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        in_flight = {}

        def submit_next() -> bool:
            if ctx.should_stop():
                return False
            try:
                item = next(remaining)
            except StopIteration:
                return False
            in_flight[pool.submit(worker, item)] = item
            return True

        for _ in range(workers):
            if not submit_next():
                break
        while in_flight:
            finished, _pending = wait(set(in_flight), return_when=FIRST_COMPLETED)
            for future in finished:
                in_flight.pop(future, None)
                results.append(future.result())
                submit_next()
    return results


def _review_unit(
    repo: Path, unit: WorkUnit, ctx: StageContext
) -> tuple[str, list[Finding], list[DroppedFinding], bool]:
    found: list[Finding] = []
    lost: list[DroppedFinding] = []
    playbooks = _unit_playbooks(unit)
    if not playbooks:
        return unit.unit_id, found, lost, True
    excerpts = _excerpts(repo, unit.paths, ctx.config.budgets.max_excerpt_bytes)
    if not excerpts:
        lost.append(
            DroppedFinding(
                rule_id=f"assessment-{unit.control_family}",
                file=unit.paths[0],
                line=1,
                reason="no_excerpt",
            )
        )
        return unit.unit_id, found, lost, True
    graph_text = ctx.graph.summary(unit.paths)
    rendered = "\n\n".join(playbook.render() for playbook in playbooks)
    allowed = ", ".join(playbook.playbook_id for playbook in playbooks)
    user = (
        f"Objective: {unit.title}\n"
        f"{rendered}\n\n"
        f"Symbol graph:\n{graph_text}\n\n"
        f"Source excerpts:\n{excerpts}\n\n"
        'Return JSON {"gaps": [{"control_family", "playbook", "title", "file", '
        '"line", "description", "remediation", "severity", "confidence"}]}. '
        f"playbook must be one of: {allowed}. "
        "file must be one of the excerpt paths. "
        "line must be a line number shown in that excerpt. "
        "Describe the control to add. "
        "Use an empty gaps array when every control holds."
    )
    parsed = _ask(ctx, user, _GapList)
    if parsed is None:
        lost.append(
            DroppedFinding(
                rule_id=f"assessment-{unit.control_family}",
                file=unit.paths[0],
                line=1,
                reason="budget" if getattr(ctx._local, "refused", False) else "unparseable",
            )
        )
        return unit.unit_id, found, lost, not getattr(ctx._local, "refused", False)
    limit = 8 if unit.control_family == _REVIEW else 5
    for gap in parsed.gaps[:limit]:
        playbook = playbook_for(gap.playbook) or playbook_for(gap.control_family)
        if playbook is None or playbook not in playbooks:
            lost.append(
                DroppedFinding(
                    rule_id=f"assessment-{unit.control_family}",
                    file=unit.paths[0],
                    line=1,
                    reason="playbook",
                )
            )
            continue
        finding = _gap_to_finding(gap, unit, playbook)
        if finding is None:
            lost.append(
                DroppedFinding(
                    rule_id=f"assessment-{unit.control_family}",
                    file=unit.paths[0],
                    line=1,
                    reason="playbook",
                )
            )
            continue
        found.append(finding)
    return unit.unit_id, found, lost, True


def _review_pending(
    finding: Finding, ctx: StageContext
) -> tuple[Finding | None, DroppedFinding | None]:
    playbook = playbook_for(finding.playbook)
    if playbook is None:
        return None, _drop(finding, "playbook")
    graph_text = ctx.graph.summary([finding.file])
    user = (
        f"{playbook.render()}\n\n"
        f"Candidate: {finding.title} at {finding.file}:{finding.line}\n"
        f"Description: {finding.description}\n"
        f"Source line: {finding.snippet}\n"
        f"Symbol graph:\n{graph_text}\n\n"
        'Return JSON {"verdict": "confirmed" | "rejected" | "inconclusive", "reason": "..."}. '
        "confirmed means the source line shows the gap named in the playbook. "
        "rejected means the control holds or the line does not show that gap. "
        "inconclusive means the line is not enough to decide."
    )
    parsed = _ask(ctx, user, _ReviewDraft)
    if parsed is None:
        return None, _drop(finding, "budget" if ctx.budget_exhausted else "unparseable")
    verdict = parsed.verdict.strip().lower()
    if verdict not in {"confirmed", "rejected", "inconclusive"}:
        ctx.degraded = True
        return None, _drop(finding, "unparseable")
    if verdict == "rejected":
        return None, _drop(finding, "rejected")
    reason = redact(parsed.reason.strip())[:400]
    description = finding.description
    if reason:
        description = f"{description}\nReview: {reason}"
    return finding.model_copy(update={"verdict": verdict, "description": description}), None


def source_line(repo: Path, relative: str, line: int, max_chars: int = 240) -> str | None:
    """Read one in-scope line. Links that leave the repository are refused."""

    path = repo / relative
    if not is_within(repo, path) or is_reparse_point(path):
        return None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, content in enumerate(handle, start=1):
                if "\0" in content:
                    return None
                if number == line:
                    return redact(content.rstrip("\n"))[:max_chars]
    except OSError:
        return None
    return None


def _ask(ctx: StageContext, user: str, model: type[BaseModel]) -> BaseModel | None:
    raw = ctx.complete(_SYSTEM, user)
    parsed = _validate(raw, model)
    if parsed is not None or raw is None:
        return parsed
    retry = ctx.complete(
        _SYSTEM,
        user + "\n\nThe previous reply was not valid JSON for the requested object. Return one JSON object.",
    )
    parsed = _validate(retry, model)
    if parsed is None and retry is not None:
        ctx.degraded = True
    return parsed


def _validate(raw: str | None, model: type[BaseModel]) -> BaseModel | None:
    if raw is None:
        return None
    try:
        return model.model_validate(_parse_json_object(raw))
    except (ValueError, ValidationError, json.JSONDecodeError):
        return None


def _parse_json_object(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no json object")
    data = json.loads(cleaned[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data


def _unit_playbooks(unit: WorkUnit) -> list[Playbook]:
    if unit.control_family == _REVIEW:
        return [PLAYBOOKS[name] for name in sorted(PLAYBOOKS)]
    playbook = playbook_for(unit.control_family)
    return [playbook] if playbook is not None else []


def _preferred_units(
    ordered: list[str],
    known: set[str],
    max_units: int,
    per_unit: int,
) -> list[WorkUnit]:
    pending = [path for path in ordered if path in known]
    units: list[WorkUnit] = []
    for start in range(0, len(pending), per_unit):
        if len(units) >= max_units:
            break
        units.append(
            WorkUnit(
                unit_id=f"p{len(units) + 1}",
                control_family=_REVIEW,
                title="Boundary review",
                rationale="Read files named by the accepted threat model, then files that already have a gap.",
                paths=pending[start : start + per_unit],
            )
        )
    return units


def _ranked_source(files: list[str]) -> list[str]:
    chosen = [path for path in files if is_source_path(path)]

    def key(path: str) -> tuple[int, str]:
        low = path.lower()
        return (0 if any(word in low for word in _PRIORITY_WORDS) else 1, low)

    return sorted(chosen, key=key)


def _source_chunks(files: list[str], covered: set[str], room: int, per_unit: int) -> list[list[str]]:
    if room <= 0 or per_unit <= 0:
        return []
    pending = [path for path in _ranked_source(files) if path not in covered]
    chunks: list[list[str]] = []
    for start in range(0, len(pending), per_unit):
        if len(chunks) >= room:
            break
        chunks.append(pending[start : start + per_unit])
    return chunks


def _resolve_paths(hinted: list[str], known: set[str], files: list[str], cap: int) -> list[str]:
    chosen: list[str] = []
    for hint in hinted:
        normalized = hint.replace("\\", "/").lstrip("/")
        if normalized in known and normalized not in chosen:
            chosen.append(normalized)
            continue
        prefix = normalized.rstrip("/") + "/"
        for path in files:
            if path.startswith(prefix) and path not in chosen:
                chosen.append(path)
    if not chosen:
        chosen = list(files)
    return chosen[:cap]


def _excerpts(repo: Path, paths: list[str], max_bytes: int) -> str:
    blocks: list[str] = []
    for relative in paths:
        block = _numbered(repo, relative, max_bytes)
        if block:
            blocks.append(block)
    return "\n\n".join(blocks)


def _numbered(repo: Path, relative: str, max_bytes: int) -> str | None:
    path = repo / relative
    if not is_within(repo, path) or is_reparse_point(path):
        return None
    try:
        raw = path.read_bytes()[:max_bytes]
    except OSError:
        return None
    if b"\0" in raw[:1024]:
        return None
    text = redact(raw.decode("utf-8", errors="replace"))
    numbered = "\n".join(f"{index}|{line}" for index, line in enumerate(text.splitlines(), start=1))
    return f"## {relative}\n{numbered}"


def _gap_to_finding(gap: _GapDraft, unit: WorkUnit, playbook: Playbook) -> Finding | None:
    relative = gap.file.replace("\\", "/")
    if relative not in unit.paths or gap.line < 1:
        return None
    if gap.playbook != playbook.playbook_id or gap.control_family != playbook.control_family:
        return None
    severity: Severity = gap.severity if gap.severity in {"critical", "high", "medium", "low", "info"} else "medium"
    confidence = gap.confidence if 0 <= gap.confidence <= 1 else 0.5
    remediation = gap.remediation.strip() or playbook.remediation
    return Finding(
        rule_id=f"assessment-{playbook.playbook_id}",
        control_family=playbook.control_family,
        severity=severity,
        title=gap.title.strip()[:200] or playbook.control_family,
        file=relative,
        line=gap.line,
        description=redact(gap.description.strip())[:800],
        remediation=redact(remediation)[:800],
        confidence=confidence,
        origin="assessment",
        playbook=playbook.playbook_id,
        verdict="pending",
    )


def _drop(finding: Finding, reason: str) -> DroppedFinding:
    return DroppedFinding(
        rule_id=finding.rule_id,
        file=finding.file,
        line=finding.line,
        reason=reason,
    )
