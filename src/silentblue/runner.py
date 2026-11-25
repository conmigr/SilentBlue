"""Scan orchestration for the detect profile."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from silentblue import __version__
from silentblue.checkpoints import CheckpointStore
from silentblue.config import load_config
from silentblue.cost import actual_cost, estimate_spend, format_usd
from silentblue.envfile import load_operator_env
from silentblue.errors import SilentBlueError, UsageError
from silentblue.assess import prepare_graph
from silentblue.model import HttpModelClient, ModelClient, configured_model
from silentblue.models import (
    ANALYSIS_STAGES,
    ASSESS_STAGES,
    STAGES,
    AppConfig,
    FinalReport,
    RunState,
    ScanResult,
    StageName,
    StageOutcome,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.scope import is_source_path
from silentblue.redact import configure_logging, redact
from silentblue.report import build_report, write_report
from silentblue.runtime import StageContext
from silentblue.stages import STAGE_RUNNERS

logger = logging.getLogger(__name__)


def run_scan(
    *,
    repo: Path,
    stop_after: str = "d9",
    config_path: Path | None = None,
    state_dir: Path | None = None,
    manifest_dir: Path | None = None,
    resume: bool = False,
    cwd: Path | None = None,
    argv: list[str] | None = None,
    profile: str | None = None,
    client: ModelClient | None = None,
    formats: set[str] | None = None,
    on_status=None,
    on_progress=None,
    on_usage=None,
    stop_event=None,
    osv: bool | None = None,
    advisory_fetch=None,
    retain_advisories: bool = False,
) -> ScanResult:
    """Run the detect pipeline and write a report when the scope is non-empty."""

    configure_logging()
    outcomes: dict[str, StageOutcome] = {stage: "not_run" for stage in STAGES}
    exit_code = 0
    message = "ok"
    finding_count = 0
    report_dir: str | None = None
    findings_path: str | None = None
    manifest_path: str | None = None
    repo_name = repo.name
    run_id = ""
    profile_name = profile or "detect"
    model_calls = 0
    degraded = False
    estimated_cost: float | None = None
    actual: float | None = None
    usage_known = True
    rate_known = True
    try:
        root = _require_repo(repo)
        repo_name = root.name
        load_operator_env(root, cwd or Path.cwd())
        config = _apply_budget_env(_prepare_model(load_config(config_path, cwd or Path.cwd(), root, profile)))
        profile_name = config.profile
        selected = _stages_for(stop_after)
        state_root = resolve_state_dir(state_dir, root)
        _assert_output_available(root, config.output.dirname)
        active = _model_client(config, client)
        ctx = StageContext(config, active)
        ctx.state_dir = state_root
        ctx.on_progress = on_progress
        ctx.on_usage = on_usage
        ctx.stop_event = stop_event
        run_id = _run_id(root, config)
        store = CheckpointStore(state_root / "runs" / run_id)
        if resume:
            store.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        else:
            store.reset()
        now = datetime.now(timezone.utc)
        state = RunState(
            tool_version=__version__,
            run_id=run_id,
            repo=str(root),
            repo_name=repo_name,
            started_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            stop_after=_as_stage(stop_after),
        )
        state, outcomes = _run_stages(
            state, ctx, store, selected, outcomes, resume, on_status
        )
        osv_on = config.advisories == "osv" if osv is None else osv
        kept_note = ""
        if osv_on and outcomes.get("d5") in {"completed", "cached"} and state.scope is not None:
            from silentblue.supply import apply_advisories

            state = apply_advisories(state, fetch=advisory_fetch)
        elif retain_advisories and state.scope is not None:
            from silentblue.supply import retain_advisories as _retain_advisories

            previous = _previous_report(root, config.output.dirname)
            if previous is not None:
                state, kept_note = _retain_advisories(state, previous)
        degraded = state.degraded
        model_calls = state.model_calls
        state = _attach_cost(state, config)
        estimated_cost = state.estimated_cost_usd
        rate_known = state.rate_known
        actual, actual_rate_known = actual_cost(
            state.input_tokens,
            state.output_tokens,
            provider=state.model_provider,
            model_name=state.model_name,
            usage_known=state.usage_known,
            made_calls=state.model_calls > 0,
        )
        usage_known = state.usage_known
        rate_known = rate_known and actual_rate_known
        outcomes["d9"] = "completed"
        try:
            report = build_report(
                state,
                outcomes,
                generated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                profile=config.profile,
                state_dir=state_root,
            )
            path = write_report(report, root, config.output.dirname, now, formats=formats)
        except Exception:
            outcomes["d9"] = "not_run"
            raise
        finding_count = len(report.findings)
        report_dir = str(path.parent)
        findings_path = str(path)
        message = (
            f"scanned {report.metrics.files} files, reported {finding_count} control gaps"
        )
        if stop_event is not None and stop_event.is_set():
            message = f"{message}; scan stopped"
        if degraded and state.advisories == "degraded":
            exit_code = 1
            message = f"{message}; assessment degraded; {_advisory_failure(state.advisory_note)}"
        elif state.advisories == "degraded":
            exit_code = 1
            message = f"{message}; {_advisory_failure(state.advisory_note)}"
        elif degraded:
            exit_code = 1
            message = f"{message}; assessment degraded"
        if config.profile == "assess":
            message = f"{message}; {_assess_outcome(report, ctx)}"
        if kept_note:
            message = f"{message}; {kept_note}"
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
        logger.warning("%s", message)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
        logger.exception("scan failed")
    try:
        manifest_path = str(
            _write_manifest(
                manifest_dir or cwd or Path.cwd(),
                argv=argv or [],
                repo_name=repo_name,
                run_id=run_id,
                profile=profile_name,
                stop_after=stop_after,
                exit_code=exit_code,
                message=message,
                outcomes=outcomes,
                finding_count=finding_count,
                model_calls=model_calls,
                findings_path=findings_path,
                estimated_cost_usd=estimated_cost,
                actual_cost_usd=actual,
                usage_known=usage_known,
                rate_known=rate_known,
            )
        )
    except OSError as exc:
        logger.warning("manifest was not written: %s", exc.strerror or "unwritable")
    return ScanResult(
        exit_code=exit_code,
        message=message,
        finding_count=finding_count,
        report_dir=report_dir,
        findings_path=findings_path,
        manifest_path=manifest_path,
        estimated_cost_usd=estimated_cost,
        actual_cost_usd=actual,
        usage_known=usage_known,
        rate_known=rate_known,
    )


def estimate_repo(
    *,
    repo: Path,
    config_path: Path | None = None,
    cwd: Path | None = None,
    profile: str | None = None,
) -> tuple[int, str]:
    """Print a spend-free scope preview. Model calls stay at zero."""

    configure_logging()
    from silentblue.scope import collect_scope

    root = _require_repo(repo)
    load_operator_env(root, cwd or Path.cwd())
    config = _apply_budget_env(_prepare_model(load_config(config_path, cwd or Path.cwd(), root, profile)))
    scope = collect_scope(root, config.scope, extra_exclude_dirs={config.output.dirname})
    if not scope.files:
        raise UsageError("empty scope: no files left after exclusions")
    languages: dict[str, int] = {}
    total = 0
    for item in scope.files:
        total += item.size
        languages[item.language] = languages.get(item.language, 0) + 1
    primary = sorted(languages.items(), key=lambda item: (-item[1], item[0]))[0][0]
    source_files = sum(1 for item in scope.files if is_source_path(item.path))
    estimate = estimate_spend(
        profile=config.profile,
        source_files=source_files,
        max_calls=config.model.max_calls,
        max_units=config.budgets.max_units,
        max_files_per_unit=config.budgets.max_files_per_unit,
        max_excerpt_bytes=config.budgets.max_excerpt_bytes,
        provider=config.model.provider,
        model_name=config.model.name,
    )
    lines = [
        f"silentblue {__version__}",
        f"repo: {root.name}",
        f"files: {len(scope.files)}",
        f"bytes: {total}",
        f"primary_language: {primary}",
        "model_calls: 0",
        f"profile: {config.profile}",
        f"estimated_model_calls: {estimate.calls}",
        f"estimated_input_tokens: {estimate.input_tokens}",
        f"estimated_output_tokens: {estimate.output_tokens}",
        f"estimated_cost_usd: {format_usd(estimate.cost_usd, estimate.rate_known)}",
        f"price_table: {estimate.price_date}",
        f"workers: {config.budgets.workers}",
        f"estimated_units: {estimate.units}",
        f"source_files: {estimate.source_files}",
        f"files_in_budget: {estimate.files_covered}",
    ]
    if estimate.model_name:
        lines.append(f"model: {estimate.model_provider}/{estimate.model_name}")
    return 0, "\n".join(lines)


def resolve_state_dir(flag: Path | None, repo: Path) -> Path:
    """Choose a writable state directory outside the repository."""

    if flag is not None:
        path = flag
    elif os.environ.get("SILENTBLUE_STATE_DIR"):
        path = Path(os.environ["SILENTBLUE_STATE_DIR"])
    else:
        path = Path.home() / ".silentblue" / "state"
    resolved = path.expanduser().resolve()
    if is_within(repo, resolved):
        raise UsageError("state directory must be outside the repository")
    resolved.mkdir(parents=True, exist_ok=True)
    probe = resolved / ".write_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise UsageError(
            f"state directory is not writable: {exc.strerror or 'unwritable'}"
        ) from exc
    return resolved


def _run_stages(
    state: RunState,
    ctx: StageContext,
    store: CheckpointStore,
    selected: list[StageName],
    outcomes: dict[str, StageOutcome],
    resume: bool,
    on_status=None,
) -> tuple[RunState, dict[str, StageOutcome]]:
    reran = False
    for stage in selected:
        if stage == "d9":
            continue
        if stage == "d4" and resume:
            partial = store.load_partial(stage, repo=state.repo, tool_version=state.tool_version)
            if partial is not None:
                state = partial.model_copy(update={"stop_after": state.stop_after})
                ctx.note_loaded(state)
        if on_status is not None:
            on_status(f"stage {stage} started")
        ctx.note_progress(stage=stage, model_calls=ctx.model_calls)
        prepare_graph(ctx, state)
        if stage in ASSESS_STAGES and ctx.config.profile != "assess":
            outcomes[stage] = "skipped"
            if on_status is not None:
                on_status(f"stage {stage} skipped")
            continue
        if resume and not reran:
            loaded = store.load(stage, repo=state.repo, tool_version=state.tool_version)
            if loaded is not None:
                state = loaded.model_copy(update={"stop_after": state.stop_after})
                ctx.note_loaded(state)
                outcomes[stage] = "cached"
                continue
        reran = True
        before = ctx.degraded
        ctx.store = store
        state = STAGE_RUNNERS[stage](state, ctx)
        finished = True
        if stage == "d4":
            finished = set(state.reviewed_units) >= {unit.unit_id for unit in state.units}
        store.save(stage, state, complete=finished)
        outcomes[stage] = "degraded" if ctx.degraded and not before else "completed"
        if on_status is not None:
            on_status(f"stage {stage} {outcomes[stage]}")
    return state, outcomes


def _stages_for(stop_after: str) -> list[StageName]:
    stage = _as_stage(stop_after)
    if stage == "d9":
        return list(STAGES)
    index = ANALYSIS_STAGES.index(stage)
    return list(ANALYSIS_STAGES[: index + 1])


def _as_stage(stop_after: str) -> StageName:
    if stop_after not in STAGES:
        raise UsageError("stop-after must be d0, d1, d2, d3, d4, d5, d6, d7, d8, or d9")
    return stop_after  # type: ignore[return-value]


def _require_repo(repo: Path) -> Path:
    root = repo.expanduser().resolve()
    if not root.is_dir():
        raise UsageError("repository path is not a directory")
    return root


def _assert_output_available(repo: Path, dirname: str) -> None:
    output = repo / dirname
    if is_reparse_point(output) or (output.exists() and not output.is_dir()):
        raise UsageError("report directory must be a real directory inside the repository")
    if output.exists() and not is_within(repo, output):
        raise UsageError("report directory must be a real directory inside the repository")


def _run_id(repo: Path, config: AppConfig) -> str:
    blob = (
        f"{repo.resolve()}|{config.profile}|{config.model.provider}|"
        f"{config.model.name}|{config.scope.model_dump_json()}"
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _apply_budget_env(config: AppConfig) -> AppConfig:
    """Let an operator raise the pool and the ceilings without a config file."""

    budgets: dict[str, object] = {}
    model: dict[str, object] = {}
    workers = os.environ.get("SILENTBLUE_WORKERS", "").strip()
    units = os.environ.get("SILENTBLUE_MAX_UNITS", "").strip()
    calls = os.environ.get("SILENTBLUE_MAX_CALLS", "").strip()
    cost = os.environ.get("SILENTBLUE_MAX_COST_USD", "").strip()
    try:
        if workers:
            budgets["workers"] = int(workers)
        if units:
            budgets["max_units"] = int(units)
        if calls:
            model["max_calls"] = int(calls)
        if cost:
            budgets["max_cost_usd"] = float(cost)
    except ValueError as exc:
        raise UsageError("SILENTBLUE_WORKERS, MAX_UNITS, MAX_CALLS, and MAX_COST_USD must be numbers") from exc
    updated = config
    if budgets:
        updated = updated.model_copy(update={"budgets": updated.budgets.model_copy(update=budgets)})
    if model:
        updated = updated.model_copy(update={"model": updated.model.model_copy(update=model)})
    return updated


def _advisory_failure(note: str) -> str:
    detail = note.strip() or "The advisory check did not complete."
    if detail.startswith("The advisory check"):
        return detail
    return f"The advisory check did not complete. {detail}"


def _previous_report(root: Path, dirname: str) -> FinalReport | None:
    """Load the report a new opening scan may keep advisory rows from."""

    path = root / dirname / "findings.json"
    if is_reparse_point(path) or not path.is_file():
        return None
    try:
        return FinalReport.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def _prepare_model(config: AppConfig) -> AppConfig:
    """Fill an empty assess credential from the environment without writing it down."""

    if config.profile != "assess":
        return config
    return config.model_copy(update={"model": configured_model(config.model)})


def _assess_outcome(report: FinalReport, ctx: StageContext) -> str:
    """Say whether the model ran and why new gaps were kept or dropped."""

    added = sum(1 for finding in report.findings if finding.origin == "assessment")
    counts: dict[str, int] = {}
    for item in report.dropped:
        counts[item.reason] = counts.get(item.reason, 0) + 1
    dropped = ", ".join(f"{reason} {counts[reason]}" for reason in sorted(counts))
    failed = list(ctx.call_failures)
    made = ctx.model_calls - ctx.resumed_calls
    if made == 0 and not failed:
        head = "The model was not called"
    elif ctx.answered_calls == 0 and failed:
        head = f"{_counted(len(failed))} failed: {_unique(failed)}"
    elif ctx.answered_calls == 0:
        head = "The model ran and returned no token counts"
    else:
        head = f"{_counted(ctx.answered_calls)} returned tokens"
        if failed:
            head = f"{head}; {_counted(len(failed))} failed: {_unique(failed)}"
    sentence = f"{head}; assessment gaps added: {added}"
    if dropped:
        sentence = f"{sentence}; dropped: {dropped}"
    if ctx.budget_exhausted:
        sentence = f"{sentence}; the call budget stopped further calls"
    if report.metrics.model_review == "incomplete":
        sentence = (
            f"{sentence}; model review incomplete: "
            f"{report.metrics.model_paths_read} of {report.metrics.model_paths} list paths"
        )
    return sentence


def _counted(count: int) -> str:
    noun = "call" if count == 1 else "calls"
    return f"{count} {noun}"


def _unique(reasons: list[str]) -> str:
    ordered: list[str] = []
    for reason in reasons:
        if reason not in ordered:
            ordered.append(reason)
    return ", ".join(ordered)


def _attach_cost(state: RunState, config: AppConfig) -> RunState:
    source_files = 0
    if state.scope is not None:
        source_files = sum(1 for item in state.scope.files if is_source_path(item.path))
    estimate = estimate_spend(
        profile=config.profile,
        source_files=source_files,
        max_calls=config.model.max_calls,
        max_units=config.budgets.max_units,
        max_files_per_unit=config.budgets.max_files_per_unit,
        max_excerpt_bytes=config.budgets.max_excerpt_bytes,
        provider=config.model.provider,
        model_name=config.model.name,
    )
    return state.model_copy(
        update={
            "estimated_calls": estimate.calls,
            "estimated_input_tokens": estimate.input_tokens,
            "estimated_output_tokens": estimate.output_tokens,
            "estimated_cost_usd": estimate.cost_usd,
            "rate_known": estimate.rate_known,
            "model_provider": estimate.model_provider,
            "model_name": estimate.model_name,
        }
    )


def _model_client(config: AppConfig, client: ModelClient | None) -> ModelClient | None:
    if config.profile != "assess":
        return None
    if client is not None:
        return client
    if not config.model.api_key.strip():
        raise UsageError("assess profile requires SILENTBLUE_API_KEY")
    return HttpModelClient(config.model)


def _write_manifest(
    directory: Path,
    *,
    argv: list[str],
    repo_name: str,
    run_id: str,
    profile: str,
    stop_after: str,
    exit_code: int,
    message: str,
    outcomes: dict[str, StageOutcome],
    finding_count: int,
    model_calls: int,
    findings_path: str | None,
    estimated_cost_usd: float | None = None,
    actual_cost_usd: float | None = None,
    usage_known: bool = True,
    rate_known: bool = True,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"run_manifest_{stamp}.json"
    suffix = 1
    while path.exists():
        path = directory / f"run_manifest_{stamp}_{suffix:02d}.json"
        suffix += 1
    payload = {
        "tool": "silentblue",
        "version": __version__,
        "argv": [redact(item) for item in argv],
        "profile": profile,
        "repo_name": repo_name,
        "run_id": run_id,
        "stop_after": stop_after,
        "exit_code": exit_code,
        "message": redact(message),
        "stages": outcomes,
        "findings": finding_count,
        "model_calls": model_calls,
        "estimated_cost_usd": estimated_cost_usd,
        "actual_cost_usd": actual_cost_usd,
        "usage_known": usage_known,
        "rate_known": rate_known,
        "report": findings_path,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
