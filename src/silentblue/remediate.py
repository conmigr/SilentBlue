"""D10 remediation. Report-only writes case files. Fix mode applies an accepted patch."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from silentblue.asking import ask_json
from silentblue.envfile import load_operator_env
from silentblue.casefiles import (
    DIRNAME,
    assert_real_dir,
    findings_file,
    join_lines,
    load_report,
    read_source,
    save_case,
    span,
    split_lines,
)
from silentblue.config import load_config
from silentblue.errors import SilentBlueError
from silentblue.manifest import write_manifest
from silentblue.model import ModelClient
from silentblue.models import Finding, RemediateResult, RemediationCase
from silentblue.paths import is_reparse_point, is_within
from silentblue.playbooks import playbook_for
from silentblue.policy import review_patch
from silentblue.redact import configure_logging, redact
from silentblue.runner import _model_client, _prepare_model, _require_repo
from silentblue.triage import accepted_case_ids
from silentblue.runtime import StageContext

logger = logging.getLogger(__name__)

_SYSTEM = (
    "You are a defensive security engineer for Silent Blue. "
    "Propose a minimal source change that puts the missing control in place. "
    "The replacement is the repaired source for those lines. "
    "Do not include a proof of concept, a payload, or a comment that shows how to trigger the flaw. "
    "Edit only the file you were shown. "
    "Keep tests in place. "
    "Keep security controls enabled. "
    "Return one JSON object and nothing else."
)
_ELIGIBLE = {"confirmed", "detector"}
_MAX_STORED = 8000


class _PatchDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    summary: str = ""
    file: str = ""
    start_line: int
    end_line: int
    replacement: str


def run_remediate(
    *,
    repo: Path,
    mode: str = "report-only",
    fix: bool = False,
    findings: Path | None = None,
    config_path: Path | None = None,
    manifest_dir: Path | None = None,
    cwd: Path | None = None,
    argv: list[str] | None = None,
    client: ModelClient | None = None,
) -> RemediateResult:
    """Write one case per confirmed gap. Source changes only in fix mode."""

    configure_logging()
    selected = "fix" if fix or mode == "fix" else mode
    exit_code = 0
    message = "ok"
    cases: list[RemediationCase] = []
    model_calls = 0
    case_dir: str | None = None
    manifest_path: str | None = None
    try:
        if selected not in {"report-only", "fix"}:
            raise SilentBlueError("mode must be report-only or fix", 2)
        root = _require_repo(repo)
        load_operator_env(root, cwd or Path.cwd())
        config = _prepare_model(load_config(config_path, cwd or Path.cwd(), root, "assess"))
        active = _model_client(config, client)
        assert_real_dir(root, DIRNAME)
        report_path = findings_file(root, findings)
        report = load_report(report_path)
        ctx = StageContext(config, active)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        held = _accepted(root)
        cases = [
            _draft_case(root, ctx, finding, selected, stamp)
            for finding in report.findings
            if finding.verdict in _ELIGIBLE and finding.case_id not in held
        ]
        cases = resolve_overlaps(cases)
        if selected == "fix":
            cases = apply_fixes(root, cases)
        for case in cases:
            save_case(root, case)
        model_calls = ctx.model_calls
        if cases:
            case_dir = str(root / DIRNAME)
        proposed = sum(case.status == "proposed" for case in cases)
        refused = sum(case.status == "refused" for case in cases)
        applied = sum(case.status == "applied" for case in cases)
        if not cases:
            message = "no confirmed gaps"
        else:
            message = f"wrote {len(cases)} cases, refused {refused}, applied {applied}"
        if ctx.degraded:
            exit_code = 1
            message = f"{message}; remediation degraded"
        result_counts = (proposed, refused, applied)
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
        result_counts = (0, 0, 0)
        cases = []
        logger.warning("%s", message)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
        result_counts = (0, 0, 0)
        cases = []
        logger.exception("remediate failed")
    try:
        manifest_path = str(
            write_manifest(
                manifest_dir or cwd or Path.cwd(),
                {
                    "command": "remediate",
                    "argv": argv or [],
                    "mode": selected,
                    "exit_code": exit_code,
                    "message": message,
                    "cases": len(cases),
                    "model_calls": model_calls,
                    "case_dir": case_dir,
                },
            )
        )
    except OSError as exc:
        logger.warning("manifest was not written: %s", exc.strerror or "unwritable")
    proposed, refused, applied = result_counts
    return RemediateResult(
        exit_code=exit_code,
        message=message,
        case_count=len(cases),
        proposed_count=proposed,
        refused_count=refused,
        applied_count=applied,
        model_calls=model_calls,
        case_dir=case_dir,
        manifest_path=manifest_path,
    )


def resolve_overlaps(cases: list[RemediationCase]) -> list[RemediationCase]:
    """Refuse a later patch that shares lines with an earlier one in the same file."""

    grouped: dict[str, list[int]] = {}
    for index, case in enumerate(cases):
        if case.status == "proposed":
            grouped.setdefault(case.file, []).append(index)
    updated = list(cases)
    for indexes in grouped.values():
        ordered = sorted(indexes, key=lambda index: (updated[index].start_line, updated[index].end_line, index))
        covered = 0
        for index in ordered:
            case = updated[index]
            if case.start_line <= covered:
                updated[index] = case.model_copy(
                    update={"status": "refused", "refusal": "overlap", "applied": False}
                )
                continue
            covered = max(covered, case.end_line)
    return updated


def apply_fixes(repo: Path, cases: list[RemediationCase]) -> list[RemediationCase]:
    """Write accepted patches into the repository, one file at a time."""

    grouped: dict[str, list[int]] = {}
    for index, case in enumerate(cases):
        if case.status == "proposed":
            grouped.setdefault(case.file, []).append(index)
    updated = list(cases)
    for relative, indexes in grouped.items():
        path = repo / relative
        if not is_within(repo, path) or is_reparse_point(path) or not path.is_file():
            for index in indexes:
                updated[index] = updated[index].model_copy(
                    update={"status": "refused", "refusal": "outside_path", "applied": False}
                )
            continue
        original = read_source(repo, relative)
        if original is None:
            for index in indexes:
                updated[index] = updated[index].model_copy(
                    update={"status": "refused", "refusal": "unreadable", "applied": False}
                )
            continue
        lines, trailing = split_lines(original)
        applied_indexes: list[int] = []
        for index in sorted(indexes, key=lambda item: updated[item].start_line, reverse=True):
            case = updated[index]
            if case.start_line < 1 or case.end_line > len(lines) or case.start_line > case.end_line:
                updated[index] = case.model_copy(
                    update={"status": "refused", "refusal": "line_out_of_range", "applied": False}
                )
                continue
            lines = lines[: case.start_line - 1] + case.replacement.splitlines() + lines[case.end_line :]
            updated[index] = case.model_copy(update={"status": "applied", "applied": True, "refusal": ""})
            applied_indexes.append(index)
        if not applied_indexes:
            continue
        try:
            _replace_file(path, join_lines(lines, trailing))
        except OSError:
            for index in applied_indexes:
                updated[index] = updated[index].model_copy(
                    update={"status": "proposed", "applied": False}
                )
    return updated


def _draft_case(
    repo: Path,
    ctx: StageContext,
    finding: Finding,
    mode: str,
    generated_at: str,
) -> RemediationCase:
    playbook = playbook_for(finding.playbook or finding.control_family)
    base = {
        "case_id": finding.case_id,
        "rule_id": finding.rule_id,
        "control_family": finding.control_family,
        "playbook": playbook.playbook_id if playbook is not None else finding.playbook,
        "severity": finding.severity,
        "title": finding.title,
        "file": finding.file,
        "line": finding.line,
        "mode": mode,
        "generated_at": generated_at,
    }
    source = read_source(repo, finding.file)
    if source is None:
        return RemediationCase(
            **base,
            status="refused",
            refusal="unreadable",
        )
    lines, _trailing = split_lines(source)
    window = _window(lines, finding.line, ctx.config.budgets.max_excerpt_bytes)
    guidance = playbook.render() if playbook is not None else f"Control family: {finding.control_family}"
    user = (
        f"{guidance}\n"
        f"Repair guidance: {finding.remediation}\n"
        f"Gap: {finding.title} at {finding.file}:{finding.line}\n"
        + (f"Threat model: {finding.threat_note}\n" if finding.threat_note else "")
        + f"Rule: {finding.rule_id}\n"
        + f"Source line: {finding.snippet}\n\n"
        + f"## {finding.file}\n{window}\n\n"
        + 'Return JSON {"summary": "...", "file": "", "start_line": 1, "end_line": 1, "replacement": "..."}. '
        + "start_line and end_line are inclusive line numbers from this file. "
        + "replacement is the new text for that range. "
        + f"The only file you may change is {finding.file}."
    )
    parsed = ask_json(ctx, _SYSTEM, user, _PatchDraft)
    if not isinstance(parsed, _PatchDraft):
        reason = "budget" if ctx.budget_exhausted else "unparseable"
        return RemediationCase(**base, status="refused", refusal=reason)
    original = span(lines, parsed.start_line, parsed.end_line)
    review = review_patch(
        finding_file=finding.file,
        proposed_file=parsed.file or finding.file,
        start_line=parsed.start_line,
        end_line=parsed.end_line,
        replacement=parsed.replacement,
        line_count=len(lines),
        original_span=original,
    )
    return RemediationCase(
        **base,
        status="proposed" if review.ok else "refused",
        refusal=review.refusal,
        summary=redact(parsed.summary.strip())[:400],
        start_line=review.start_line,
        end_line=review.end_line,
        current=redact(original)[:2000],
        replacement=review.replacement if review.ok else redact(review.replacement)[:_MAX_STORED],
    )


def _accepted(repo: Path) -> set[str]:
    raw = os.environ.get("SILENTBLUE_STATE_DIR", "")
    directory = Path(raw) if raw else Path.home() / ".silentblue" / "state"
    try:
        resolved = directory.expanduser().resolve()
    except OSError:
        return set()
    if not resolved.is_dir() or is_within(repo, resolved):
        return set()
    return accepted_case_ids(resolved, repo)


def _window(lines: list[str], line: int, max_bytes: int) -> str:
    numbered = [f"{index}|{text}" for index, text in enumerate(lines, start=1)]
    blob = "\n".join(numbered)
    if len(blob.encode("utf-8")) <= max_bytes:
        return blob
    start = max(1, line - 40)
    end = min(len(lines), line + 40)
    return "\n".join(numbered[start - 1 : end])


def _replace_file(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)
