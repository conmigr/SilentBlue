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
    CASE_ID,
    DroppedFinding,
    Finding,
    RunState,
    Severity,
    WorkUnit,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.playbooks import PLAYBOOKS, Playbook, playbook_for
from silentblue.rank import case_id_for
from silentblue.reviewlist import build_review_list, save_reply, save_review_list
from silentblue.scope import is_source_path
from silentblue.redact import redact
from silentblue.runtime import StageContext

_SYSTEM = (
    "You are a defensive security reviewer for Silent Blue. "
    "Report missing or weak security controls. "
    "Cite only files and lines you were shown. "
    "The recommendation is the source change for those lines, in the language of that file. "
    "Do not include a proof-of-concept, a payload, or steps that trigger the flaw. "
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
    """Write the model file list before any model call, and carry open model findings."""

    if state.scope is None:
        raise UsageError("scope is missing")
    repo = Path(state.repo)
    state_dir = _state_dir(ctx)
    paths, note = build_review_list(repo, state.scope, state_dir)
    from silentblue.detectors import detect

    detected, _detect_dropped = detect(repo, state.scope)
    unsettled: list[Finding] = []
    added = False
    for finding in detected:
        if finding.verdict != "inconclusive":
            continue
        if finding.file not in paths:
            paths.append(finding.file)
            added = True
        unsettled.append(
            finding.model_copy(
                update={"case_id": finding.case_id or case_id_for(finding.file, finding.line, finding.rule_id)}
            )
        )
    if added:
        note = f"{note} Files with unsettled detector findings were added."
    save_review_list(state_dir, repo, state.run_id, paths, note)
    carried = _carried_findings(repo, ctx.config.output.dirname)
    return ctx.stamp(
        state.model_copy(
            update={
                "objectives": [],
                "review_paths": paths,
                "review_note": note,
                "findings": [*carried, *unsettled],
            }
        )
    )


def run_d3(state: RunState, ctx: StageContext) -> RunState:
    """Cut the saved file list into units. No model call and no unit cap."""

    cap = max(1, ctx.config.budgets.max_files_per_unit)
    units: list[WorkUnit] = []
    paths = list(state.review_paths)
    for index, start in enumerate(range(0, len(paths), cap), start=1):
        units.append(
            WorkUnit(
                unit_id=f"m{index}",
                control_family=_REVIEW,
                title="Source review",
                rationale=state.review_note or "Read these files.",
                paths=paths[start : start + cap],
            )
        )
    return ctx.stamp(state.model_copy(update={"units": units}))


def run_d4(state: RunState, ctx: StageContext) -> RunState:
    """Read each unit once. A cited line is kept. A bad reply does not delete a finding."""

    findings = list(state.findings)
    dropped = list(state.dropped)
    reviewed = list(state.reviewed_units)
    done = set(reviewed)
    pending = [unit for unit in state.units if unit.unit_id not in done]
    repo = Path(state.repo)
    carried = [
        item
        for item in findings
        if item.origin == "assessment" or item.verdict == "inconclusive"
    ]
    cleared_keys = list(state.cleared_keys)
    known_rows = _known_rows(state, ctx)
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

    def worker(unit: WorkUnit) -> tuple[str, list[Finding], list[DroppedFinding], list[str], list[str], bool]:
        return _review_unit(repo, unit, ctx, carried, known_rows, state.run_id)

    for unit_id, found, lost, cleared, confirmed, keep in _map_work(ctx, pending, worker):
        if cleared:
            gone = set(cleared)
            for item in findings:
                if item.case_id in gone:
                    cleared_keys.append(f"{item.file}|{item.line}|{item.rule_id}")
            findings = [item for item in findings if item.case_id not in gone]
        if confirmed:
            accepted = set(confirmed)
            findings = [
                item.model_copy(update={"verdict": "confirmed"})
                if item.case_id in accepted and item.verdict == "inconclusive"
                else item
                for item in findings
            ]
        present = {(item.file, item.line, item.rule_id) for item in findings}
        for item in found:
            key = (item.file, item.line, item.rule_id)
            if key not in present:
                findings.append(item)
                present.add(key)
        dropped.extend(lost)
        if keep:
            reviewed.append(unit_id)
        state = ctx.stamp(
            state.model_copy(
                update={
                    "findings": findings,
                    "dropped": dropped,
                    "reviewed_units": reviewed,
                    "cleared_keys": cleared_keys,
                }
            )
        )
        if ctx.store is not None:
            ctx.store.save("d4", state, complete=False)
        ctx.note_progress(units_done=len(reviewed), model_calls=ctx.model_calls)
    return ctx.stamp(
        state.model_copy(
            update={
                "findings": findings,
                "dropped": dropped,
                "reviewed_units": reviewed,
                "cleared_keys": cleared_keys,
            }
        )
    )


def bind_assessment(
    state: RunState,
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Keep a model finding when its file is still in scope and its line still exists."""

    if state.scope is None:
        raise UsageError("scope is missing")
    scope_files = {item.path for item in state.scope.files}
    repo = Path(state.repo)
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for finding in state.findings:
        if finding.origin != "assessment":
            kept.append(finding)
            continue
        if finding.file not in scope_files:
            dropped.append(_drop(finding, "unbound"))
            continue
        snippet = source_line(repo, finding.file, finding.line)
        if snippet is None:
            dropped.append(_drop(finding, "line_out_of_range"))
            continue
        kept.append(finding.model_copy(update={"snippet": snippet}))
    return kept, dropped


def run_d6(state: RunState, ctx: StageContext) -> RunState:
    """Leave model findings in place. Clearing happens in the same review call."""

    return ctx.stamp(state)


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
    repo: Path,
    unit: WorkUnit,
    ctx: StageContext,
    carried: list[Finding],
    known_rows: list[Finding],
    run_id: str,
) -> tuple[str, list[Finding], list[DroppedFinding], list[str], list[str], bool]:
    found: list[Finding] = []
    lost: list[DroppedFinding] = []
    excerpts = _excerpts(repo, unit.paths, ctx.config.budgets.max_excerpt_bytes)
    if not excerpts:
        return unit.unit_id, found, lost, [], [], False
    user = _review_prompt(repo, unit, ctx, carried, known_rows, excerpts)
    raw = ctx.complete(_SYSTEM, user)
    _store_reply(ctx, repo, run_id, raw if raw is not None else "(no reply)")
    parsed = _read_review(raw)
    if parsed is None:
        return unit.unit_id, found, lost, [], [], False
    observations, clears, confirms = parsed
    for item in observations:
        finding = _observation_to_finding(repo, unit, item)
        if finding is None:
            lost.append(
                DroppedFinding(
                    rule_id="assessment-review",
                    file=unit.paths[0],
                    line=1,
                    reason="line_out_of_range",
                )
            )
            continue
        found.append(finding)
    cleared = _cleared_ids(repo, unit, carried, clears)
    confirmed = _cleared_ids(repo, unit, carried, confirms)
    return unit.unit_id, found, lost, cleared, confirmed, True


def _state_dir(ctx: StageContext) -> Path:
    directory = getattr(ctx, "state_dir", None)
    if isinstance(directory, Path):
        return directory
    return Path.home() / ".silentblue" / "state"


def _carried_findings(repo: Path, dirname: str) -> list[Finding]:
    path = repo / dirname / "findings.json"
    if is_reparse_point(path) or not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("findings", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        return []
    carried: list[Finding] = []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict) or row.get("origin") != "assessment":
            continue
        try:
            finding = Finding.model_validate(row)
        except (ValidationError, ValueError):
            continue
        if CASE_ID.fullmatch(finding.case_id or ""):
            carried.append(finding)
    return carried


def _known_rows(state: RunState, ctx: StageContext) -> list[Finding]:
    from silentblue.detectors import detect

    rows: list[Finding] = []
    if state.scope is not None:
        detected, _dropped = detect(Path(state.repo), state.scope)
        rows.extend(detected)
    for finding in _carried_report_rows(Path(state.repo), ctx.config.output.dirname):
        if finding.rule_id == "dependency-vulnerable":
            rows.append(finding)
    return rows


def _carried_report_rows(repo: Path, dirname: str) -> list[Finding]:
    path = repo / dirname / "findings.json"
    if is_reparse_point(path) or not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("findings", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        return []
    found: list[Finding] = []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            found.append(Finding.model_validate(row))
        except (ValidationError, ValueError):
            continue
    return found


def _review_prompt(
    repo: Path,
    unit: WorkUnit,
    ctx: StageContext,
    carried: list[Finding],
    known_rows: list[Finding],
    excerpts: str,
) -> str:
    open_cases = [
        item
        for item in carried
        if item.file in unit.paths and CASE_ID.fullmatch(item.case_id or "")
    ]
    case_lines = [
        (
            f"- {item.case_id} {item.file}:{item.line} verdict {item.verdict} "
            f"category {item.category or item.control_family}: {item.description}"
        )
        for item in open_cases
    ]
    recorded = [
        f"- {item.rule_id} {item.file}:{item.line} {item.title}"
        for item in known_rows
        if item.file in unit.paths and item.verdict != "inconclusive"
    ][:12]
    graph_text = ctx.graph.summary(unit.paths) if ctx.graph_ready else "(none)"
    return (
        f"{_threat_card(repo, _state_dir(ctx))}\n\n"
        "Open cases on these files. An unsettled detector case stays open unless "
        "you cite a line. A model finding stays open unless you cite the line "
        "that now enforces the control.\n"
        + ("\n".join(case_lines) or "(none)")
        + "\n\nDetector rows already confirmed in code:\n"
        + ("\n".join(recorded) or "(none)")
        + f"\n\nSymbol graph:\n{graph_text}\n\n"
        f"Source excerpts:\n{excerpts}\n\n"
        'Return one JSON object {"observations": [{"file", "line", "category", '
        '"impact", "recommendation"}], "cleared": [{"case_id", "file", "line"}], '
        '"confirmed": [{"case_id", "file", "line"}]}. '
        "file and line must appear in the excerpts. "
        "category is a short word you choose. "
        "An observation is a missing or weak control. "
        "recommendation is the replacement to write at that line so a developer can apply it. "
        "Name the API or setting. Do not include a proof-of-concept or a payload. "
        "A cleared item cites the line that shows the control in place. "
        "A confirmed item cites the line where a caller value enters the sink. "
        "Use an empty observations array when you see no new gap."
    )


def _threat_card(repo: Path, state_dir: Path) -> str:
    from silentblue.threat import threat_status

    model, status = threat_status(repo, state_dir, None)
    if model is None or status != "accepted":
        return "No accepted threat model."
    lines = ["Accepted threat model."]
    for asset in model.assets[:12]:
        files = ", ".join(asset.files) or "none"
        lines.append(
            f"Asset: {asset.name}. Expected control: {asset.expected_control}. Files: {files}"
        )
    for boundary in model.boundaries[:8]:
        lines.append(
            f"Boundary: {boundary.name}. Expected control: {boundary.expected_control}."
        )
    for assumption in model.assumptions[:8]:
        lines.append(f"Assumption: {assumption}")
    return "\n".join(lines)


def _store_reply(ctx: StageContext, repo: Path, run_id: str, text: str) -> None:
    with ctx._lock:
        index = getattr(ctx, "reply_index", 0) + 1
        ctx.reply_index = index
    save_reply(_state_dir(ctx), repo, run_id, index, text)


def _read_review(raw: str | None) -> tuple[list[dict], list[dict], list[dict]] | None:
    if raw is None or not str(raw).strip():
        return None
    try:
        data = _parse_json_object(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    clears = [item for item in data.get("cleared") or [] if isinstance(item, dict)]
    confirms = [item for item in data.get("confirmed") or [] if isinstance(item, dict)]
    items = None
    for key in ("observations", "gaps", "findings", "candidates", "issues", "results"):
        if isinstance(data.get(key), list):
            items = data[key]
            break
    if items is None and _has_citation(data):
        items = [data]
    observations = []
    for item in items or []:
        if isinstance(item, dict):
            normalized = _normalize_observation(item)
            if normalized is not None:
                observations.append(normalized)
    return observations, clears, confirms


def _has_citation(item: dict) -> bool:
    file_name = ""
    for key in ("file", "path", "filepath", "file_path", "filename"):
        if item.get(key):
            file_name = str(item[key])
            break
    return bool(file_name) and _as_line(item.get("line") or item.get("line_number")) is not None


def _normalize_observation(item: dict) -> dict | None:
    normalized = _normalize_gap(item)
    relative = str(normalized.get("file") or "").replace("\\", "/").strip()
    line = normalized.get("line")
    if not relative or not isinstance(line, int) or line < 1:
        return None
    impact = str(
        normalized.get("impact")
        or normalized.get("description")
        or ""
    ).strip()
    recommendation = str(
        normalized.get("recommendation") or normalized.get("remediation") or ""
    ).strip()
    category = str(
        normalized.get("category")
        or normalized.get("control_family")
        or normalized.get("playbook")
        or "observation"
    ).strip()
    if not impact:
        impact = "Cited control gap"
    return {
        "file": relative,
        "line": line,
        "category": category[:80],
        "impact": impact[:800],
        "recommendation": recommendation[:4000],
        "severity": normalized.get("severity") or "medium",
        "confidence": normalized.get("confidence", 0.5),
        "title": str(normalized.get("title") or category or "Cited control gap")[:200],
    }


def _observation_to_finding(repo: Path, unit: WorkUnit, item: dict) -> Finding | None:
    relative = item["file"]
    if relative not in unit.paths:
        return None
    snippet = source_line(repo, relative, item["line"])
    if snippet is None:
        return None
    category = item["category"] or "observation"
    playbook = _match_playbook(category)
    family = playbook or category
    slug = re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-") or "observation"
    rule_id = f"assessment-{slug[:40]}"
    severity: Severity = item["severity"] if item["severity"] in {"critical", "high", "medium", "low", "info"} else "medium"
    confidence = item["confidence"] if isinstance(item["confidence"], (int, float)) and 0 <= item["confidence"] <= 1 else 0.5
    recommendation = item["recommendation"]
    matched = playbook_for(playbook) if playbook else None
    if not recommendation and matched is not None:
        recommendation = matched.remediation
    if not recommendation:
        recommendation = "Review this line and add the missing control."
    return Finding(
        case_id=case_id_for(relative, item["line"], rule_id),
        rule_id=rule_id,
        control_family=family[:80],
        severity=severity,
        title=item["title"],
        file=relative,
        line=item["line"],
        description=redact(item["impact"])[:800],
        remediation=redact(recommendation)[:4000],
        snippet=snippet,
        confidence=float(confidence),
        origin="assessment",
        playbook=playbook,
        category=category,
        verdict="confirmed",
    )


def _cleared_ids(repo: Path, unit: WorkUnit, carried: list[Finding], clears: list[dict]) -> list[str]:
    by_id = {item.case_id: item for item in carried if item.case_id}
    chosen: list[str] = []
    for item in clears:
        case_id = str(item.get("case_id") or "")
        finding = by_id.get(case_id)
        if finding is None:
            continue
        relative = str(item.get("file") or item.get("path") or "").replace("\\", "/")
        line = _as_line(item.get("line"))
        if relative not in unit.paths or not isinstance(line, int):
            continue
        if source_line(repo, relative, line) is None:
            continue
        chosen.append(case_id)
    return chosen


def _match_playbook(category: str) -> str:
    text = category.lower().replace("_", "-").replace(" ", "-")
    if text in PLAYBOOKS:
        return text
    for playbook_id in PLAYBOOKS:
        if playbook_id in text:
            return playbook_id
    return ""


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


def _miss_reason(ctx: StageContext) -> str:
    """Why one review produced no object. A refused call is the budget."""

    if getattr(ctx._local, "refused", False) or ctx.budget_exhausted:
        return "budget"
    failure = getattr(ctx._local, "failure", "")
    if isinstance(failure, str) and failure:
        return failure
    return "unparseable"


def _validate(raw: str | None, model: type[BaseModel]) -> BaseModel | None:
    if raw is None:
        return None
    try:
        payload = _coerce(model, _parse_json_object(raw))
    except (ValueError, json.JSONDecodeError):
        return None
    try:
        return model.model_validate(payload)
    except ValidationError:
        if model is not _GapList or not isinstance(payload.get("gaps"), list):
            return None
        kept: list[_GapDraft] = []
        for item in payload["gaps"]:
            if not isinstance(item, dict):
                continue
            try:
                kept.append(_GapDraft.model_validate(item))
            except ValidationError:
                continue
        if not kept:
            return None
        return _GapList(gaps=kept)


def _parse_json_object(text: str) -> dict:
    """Read the last JSON object in a reply. A fenced block is preferred."""

    fenced = re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
    candidates = [block for block in reversed(fenced) if block.strip()]
    candidates.append(text)
    last_error: Exception = ValueError("no json object")
    for candidate in candidates:
        for blob in reversed(_objects_in(candidate)):
            for attempt in (blob, _strip_trailing_commas(blob)):
                try:
                    data = json.loads(attempt)
                except json.JSONDecodeError as exc:
                    last_error = exc
                    continue
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    return {"gaps": data, "objectives": data}
    raise last_error


def _objects_in(text: str) -> list[str]:
    found: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "{":
            index += 1
            continue
        end = _match_brace(text, index)
        if end is None:
            index += 1
            continue
        found.append(text[index:end])
        index = end
    return found


def _match_brace(text: str, start: int) -> int | None:
    depth = 0
    quoted = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if quoted:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _strip_trailing_commas(text: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", text)


def _coerce(model: type[BaseModel], payload: dict) -> dict:
    data = dict(payload)
    if model is _GapList:
        gaps = data.get("gaps")
        if not isinstance(gaps, list):
            for key in ("findings", "candidates", "issues", "results"):
                if isinstance(data.get(key), list):
                    gaps = data[key]
                    break
        if isinstance(gaps, list):
            data["gaps"] = [_normalize_gap(item) for item in gaps if isinstance(item, dict)]
    elif model is _ObjectiveList:
        objectives = data.get("objectives")
        if not isinstance(objectives, list):
            for key in ("controls", "items", "results"):
                if isinstance(data.get(key), list):
                    objectives = data[key]
                    break
        if isinstance(objectives, list):
            data["objectives"] = objectives
    elif model is _ReviewDraft:
        if "verdict" not in data and isinstance(data.get("decision"), str):
            data["verdict"] = data["decision"]
    return data


def _normalize_gap(item: dict) -> dict:
    names = {
        "file": ("file", "path", "filepath", "file_path", "filename"),
        "line": ("line", "line_number", "lineno", "line_no"),
        "control_family": ("control_family", "family"),
        "playbook": ("playbook", "playbook_id"),
        "title": ("title", "name"),
        "description": ("description", "detail", "details", "evidence"),
        "remediation": ("remediation", "repair", "fix"),
        "severity": ("severity", "level"),
        "confidence": ("confidence",),
    }
    out = dict(item)
    for target, keys in names.items():
        if out.get(target) not in (None, ""):
            continue
        for key in keys:
            if item.get(key) not in (None, ""):
                out[target] = item[key]
                break
    if "line" in out:
        out["line"] = _as_line(out["line"])
    if not str(out.get("description") or "").strip():
        out["description"] = str(out.get("title") or "control gap")
    if not str(out.get("title") or "").strip():
        out["title"] = str(out.get("playbook") or out.get("control_family") or "control gap")
    return out


def _as_line(value: object) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        match = re.search(r"\d+", value)
        if match is not None:
            return int(match.group())
    return value


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
        remediation=redact(remediation)[:4000],
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
