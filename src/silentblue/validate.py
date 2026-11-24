"""D11 validation. Reviewers read a temporary copy. The host computes the verdict."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from silentblue.asking import ask_json
from silentblue.casefiles import (
    DIRNAME,
    assert_real_dir,
    join_lines,
    list_cases,
    load_case,
    read_source,
    save_case,
    split_lines,
)
from silentblue.config import load_config
from silentblue.envfile import load_operator_env
from silentblue.detectors import detect
from silentblue.errors import SilentBlueError, UsageError
from silentblue.manifest import write_manifest
from silentblue.model import ModelClient
from silentblue.models import (
    CASE_ID,
    PanelVote,
    RemediationCase,
    ScopeResult,
    ScopedFile,
    ValidateResult,
    ValidationRecord,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.playbooks import playbook_for
from silentblue.redact import configure_logging, redact
from silentblue.runner import _model_client, _prepare_model, _require_repo
from silentblue.runtime import StageContext

logger = logging.getLogger(__name__)

ROLES: tuple[tuple[str, str], ...] = (
    ("security architect", "Decide whether the control now holds in the shown file."),
    ("control owner", "Decide whether the repair matches the playbook."),
    ("regression reviewer", "Decide whether the change stays in this file and keeps the surrounding behavior."),
)
_VOTES = {"fixed", "partial", "not_fixed", "inconclusive"}
_TIE = ("not_fixed", "inconclusive", "partial", "fixed")


class _VoteDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")

    vote: str
    reason: str = ""


def host_verdict(votes: list[str]) -> str:
    """Pick the majority vote. A tie breaks toward not_fixed, then inconclusive."""

    cleaned = [vote if vote in _VOTES else "inconclusive" for vote in votes]
    if not cleaned:
        return "inconclusive"
    counts = {name: cleaned.count(name) for name in _TIE}
    best = max(counts.values())
    for name in _TIE:
        if counts[name] == best:
            return name
    return "inconclusive"


def run_validate(
    *,
    repo: Path,
    case_id: str | None = None,
    config_path: Path | None = None,
    manifest_dir: Path | None = None,
    cwd: Path | None = None,
    argv: list[str] | None = None,
    client: ModelClient | None = None,
) -> ValidateResult:
    """Record a verdict on each case. The repository source is left unchanged."""

    configure_logging()
    exit_code = 0
    message = "ok"
    model_calls = 0
    verdicts: dict[str, str] = {}
    manifest_path: str | None = None
    try:
        root = _require_repo(repo)
        load_operator_env(root, cwd or Path.cwd())
        config = _prepare_model(load_config(config_path, cwd or Path.cwd(), root, "assess"))
        active = _model_client(config, client)
        directory = root / DIRNAME
        if not directory.exists():
            raise UsageError("security-remediation is missing; run remediate first")
        assert_real_dir(root, DIRNAME)
        selected = _select_cases(root, case_id)
        ctx = StageContext(config, active)
        for path in selected:
            case = load_case(path)
            updated = _review_case(root, ctx, case)
            save_case(root, updated)
            if updated.validation is not None:
                verdicts[updated.case_id] = updated.validation.verdict
        model_calls = ctx.model_calls
        message = f"validated {len(verdicts)} cases"
        if ctx.degraded:
            exit_code = 1
            message = f"{message}; validation degraded"
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
        logger.warning("%s", message)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
        logger.exception("validate failed")
    try:
        manifest_path = str(
            write_manifest(
                manifest_dir or cwd or Path.cwd(),
                {
                    "command": "validate",
                    "argv": argv or [],
                    "exit_code": exit_code,
                    "message": message,
                    "cases": len(verdicts),
                    "model_calls": model_calls,
                    "verdicts": verdicts,
                },
            )
        )
    except OSError as exc:
        logger.warning("manifest was not written: %s", exc.strerror or "unwritable")
    return ValidateResult(
        exit_code=exit_code,
        message=message,
        case_count=len(verdicts),
        model_calls=model_calls,
        verdicts=verdicts,
        manifest_path=manifest_path,
    )


def _select_cases(repo: Path, case_id: str | None) -> list[Path]:
    paths = list_cases(repo)
    if case_id is not None:
        if CASE_ID.fullmatch(case_id) is None:
            raise UsageError("case id is not a Silent Blue case")
        paths = [path for path in paths if path.stem == case_id]
        if not paths:
            raise UsageError("remediation case was not found")
        return paths
    if not paths:
        raise UsageError("no remediation cases")
    return paths


def _review_case(repo: Path, ctx: StageContext, case: RemediationCase) -> RemediationCase:
    if case.status == "refused":
        record = ValidationRecord(verdict="skipped", reason=case.refusal or "refused")
        return case.model_copy(update={"validation": record})
    source = read_source(repo, case.file)
    if source is None:
        record = ValidationRecord(verdict="skipped", reason="unreadable")
        return case.model_copy(update={"validation": record})
    patched = _patched_text(source, case)
    if patched is None:
        record = ValidationRecord(verdict="skipped", reason="line_out_of_range")
        return case.model_copy(update={"validation": record})
    with tempfile.TemporaryDirectory(prefix="silentblue-validate-") as raw:
        temp_root = Path(raw).resolve()
        if is_within(repo, temp_root) or is_reparse_point(temp_root):
            raise UsageError("validation workspace must be outside the repository")
        relative = case.file.replace("\\", "/")
        destination = temp_root / relative
        if not is_within(temp_root, destination):
            record = ValidationRecord(verdict="skipped", reason="outside_path")
            return case.model_copy(update={"validation": record})
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(patched, encoding="utf-8", newline="\n")
        cleared = _detector_cleared(temp_root, relative, case.rule_id, case.control_family)
        votes = _panel(ctx, case, destination, relative)
    verdict = host_verdict([item.vote for item in votes])
    reason = ""
    if verdict == "fixed" and not cleared:
        verdict = "partial"
        reason = "The detector still reports this control gap."
    record = ValidationRecord(
        verdict=verdict,  # type: ignore[arg-type]
        votes=votes,
        detector_cleared=cleared,
        reason=reason,
    )
    return case.model_copy(update={"validation": record})


def _patched_text(source: str, case: RemediationCase) -> str | None:
    if case.status == "applied":
        return source
    lines, trailing = split_lines(source)
    if case.start_line < 1 or case.end_line > len(lines) or case.start_line > case.end_line:
        return None
    updated = lines[: case.start_line - 1] + case.replacement.splitlines() + lines[case.end_line :]
    return join_lines(updated, trailing or bool(updated))


def _panel(
    ctx: StageContext,
    case: RemediationCase,
    destination: Path,
    relative: str,
) -> list[PanelVote]:
    playbook = playbook_for(case.playbook or case.control_family)
    guidance = playbook.render() if playbook is not None else f"Control family: {case.control_family}"
    numbered = _numbered(destination)
    votes: list[PanelVote] = []
    for role, duty in ROLES:
        system = (
            f"You are the {role} for Silent Blue. {duty} "
            "Read only the file you were shown. "
            "Vote on whether the named control holds. "
            "Return one JSON object and nothing else."
        )
        user = (
            f"{guidance}\n"
            f"Case {case.case_id} repairs {relative}:{case.line}.\n"
            f"Gap: {case.title}\n"
            f"Proposed change:\n{case.replacement}\n\n"
            f"Patched file {relative}:\n{numbered}\n\n"
            'Return JSON {"vote": "fixed" | "partial" | "not_fixed" | "inconclusive", "reason": "..."}. '
            "fixed means the control holds. "
            "partial means the repair is incomplete. "
            "not_fixed means the gap is still present. "
            "inconclusive means the file is not enough to decide."
        )
        parsed = ask_json(ctx, system, user, _VoteDraft)
        if not isinstance(parsed, _VoteDraft):
            reason = "budget" if ctx.budget_exhausted else "unparseable"
            votes.append(PanelVote(role=role, vote="inconclusive", reason=reason))
            continue
        vote = parsed.vote.strip().lower()
        if vote not in _VOTES:
            ctx.degraded = True
            votes.append(PanelVote(role=role, vote="inconclusive", reason="unparseable"))
            continue
        votes.append(
            PanelVote(role=role, vote=vote, reason=redact(parsed.reason.strip())[:400])  # type: ignore[arg-type]
        )
    return votes


def _detector_cleared(root: Path, relative: str, rule_id: str, family: str) -> bool:
    path = root / relative
    scope = ScopeResult(
        files=[
            ScopedFile(
                path=relative,
                size=path.stat().st_size,
                language="text",
            )
        ]
    )
    findings, _dropped = detect(root, scope)
    if rule_id.startswith("assessment-"):
        return not any(item.control_family == family for item in findings)
    return not any(item.rule_id == rule_id for item in findings)


def _numbered(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    return "\n".join(f"{index}|{line}" for index, line in enumerate(text.splitlines(), start=1))
