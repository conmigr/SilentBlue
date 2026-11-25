"""Defense-priority ranking and stable case ids."""

from __future__ import annotations

import hashlib

from silentblue.errors import RunError
from silentblue.models import CASE_ID, Finding

_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def case_id_for(file: str, line: int, rule_id: str, *, salt: str = "") -> str:
    """Mint ``sb1_`` plus 32 hex characters from the gap's identity."""

    bucket = (max(line, 1) - 1) // 10
    payload = f"{file}|{bucket}|{rule_id}|{salt}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return f"sb1_{digest}"


def prioritize(findings: list[Finding]) -> list[Finding]:
    """Sort by severity and confidence, then assign case ids."""

    ordered = sorted(
        findings,
        key=lambda finding: (
            _SEVERITY[finding.severity],
            -finding.confidence,
            finding.file,
            finding.line,
            finding.rule_id,
            finding.advisory_id,
        ),
    )
    seen: set[str] = set()
    ranked: list[Finding] = []
    for finding in ordered:
        if (
            finding.origin == "assessment"
            and CASE_ID.fullmatch(finding.case_id or "")
            and finding.case_id not in seen
        ):
            case_id = finding.case_id
            seen.add(case_id)
            ranked.append(finding)
            continue
        case_id = case_id_for(
            finding.file, finding.line, finding.rule_id, salt=finding.advisory_id
        )
        if case_id in seen:
            extra = finding.advisory_id or str(finding.line)
            if finding.advisory_id:
                extra = f"{finding.advisory_id}|{finding.line}"
            case_id = case_id_for(
                finding.file,
                finding.line,
                finding.rule_id,
                salt=extra,
            )
        if case_id in seen:
            raise RunError("duplicate case id")
        seen.add(case_id)
        ranked.append(finding.model_copy(update={"case_id": case_id}))
    return ranked
