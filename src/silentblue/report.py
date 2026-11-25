"""Render one typed report as JSON, Markdown, SARIF, HTML, PDF, and YAML."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from silentblue.cost import PRICE_DATE, actual_cost, format_usd
from silentblue.threat import apply_threat, threat_status
from silentblue.errors import UsageError
from silentblue.models import (
    ComponentDetail,
    FinalReport,
    Finding,
    Metrics,
    ProfileName,
    RunState,
    StageOutcome,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.scope import is_source_path
from silentblue.rank import prioritize
from silentblue.scanledger import ledger_from_state
from silentblue.redact import redact
from silentblue.repair import APPLY_MARK, apply_note

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_report(
    state: RunState,
    stages: dict[str, StageOutcome],
    generated_at: str | None = None,
    profile: ProfileName = "detect",
    state_dir: Path | None = None,
) -> FinalReport:
    """Build the typed report. Case ids exist before any artifact is written."""

    findings = state.findings
    if any(not finding.case_id for finding in findings):
        findings = prioritize(findings)
    findings = [_redact_finding(finding) for finding in findings]
    scope_files = {item.path for item in state.scope.files} if state.scope is not None else None
    directory = state_dir or (Path.home() / ".silentblue" / "state")
    model, threat_state = threat_status(Path(state.repo), directory, scope_files)
    findings = apply_threat(findings, model, threat_state)
    findings = [_present(finding, index) for index, finding in enumerate(findings, start=1)]
    metrics = _metrics(state, findings)
    hollow = _hollow(state, stages, len(findings))
    stamp = generated_at or _now()
    cost = (
        f"Estimated cost {format_usd(metrics.estimated_cost_usd, metrics.rate_known)} USD. "
        f"Actual cost {format_usd(metrics.actual_cost_usd, metrics.usage_known and metrics.rate_known)} USD."
    )
    if metrics.model_calls == 0:
        tail = f"This profile makes no model calls. {cost}"
    else:
        tail = f"The assess profile made {metrics.model_calls} model calls. {cost}"
    if metrics.model_review:
        detectors = sum(
            1
            for finding in findings
            if finding.origin == "detector" and finding.rule_id != "dependency-vulnerable"
        )
        advisories = sum(1 for finding in findings if finding.rule_id == "dependency-vulnerable")
        tail += (
            f" Detectors reported {detectors}. OSV reported {advisories}. "
            f"Model read {metrics.model_paths_read} of {metrics.model_paths} list paths."
        )
        if metrics.model_review == "incomplete":
            tail += " Model review incomplete."
        else:
            tail += " Model review complete."
    if hollow:
        tail += " This empty result is untrusted: no source was sent for review."
    if threat_state == "accepted":
        tail += " Findings are ordered by the accepted threat model."
    elif threat_state == "stale":
        tail += " The threat model acceptance no longer matches, so severity order is used."
    elif threat_state == "draft":
        tail += " A draft threat model is present and is not used for order."
    if state.scope is not None and state.scope.mirror_dirs:
        shown = ", ".join(state.scope.mirror_dirs[:8])
        tail += f" Mirror directories were not scanned: {shown}."
    coverage = ledger_from_state(state)
    if coverage.rows:
        if coverage.saturated:
            tail += " Coverage saturated."
        else:
            tail += " Coverage unsaturated."
        if coverage.unread:
            tail += f" Unread review paths: {len(coverage.unread)}."
    if state.advisories == "queried" and state.advisory_note.startswith("Kept from the last OSV query"):
        tail += f" {state.advisory_note}"
    elif state.advisories == "queried":
        tail += " Advisory data was read from OSV."
    elif state.advisories == "degraded":
        tail += " The advisory check did not complete."
        if state.advisory_note:
            tail += f" {state.advisory_note}"
    summary = redact(
        f"Silent Blue scanned {metrics.files} files ({metrics.bytes} bytes) in "
        f"{state.repo_name}. {metrics.findings} control gaps reported, "
        f"{metrics.dropped} candidates dropped. {tail}"
    )
    return FinalReport(
        version=state.tool_version,
        repo_name=state.repo_name,
        profile=profile,
        stop_after=state.stop_after,
        generated_at=stamp,
        summary=summary,
        hollow=hollow,
        threat_model=threat_state,  # type: ignore[arg-type]
        advisories=state.advisories,
        advisory_note=state.advisory_note,
        advisory_fingerprint=state.advisory_fingerprint,
        stages=stages,
        metrics=metrics,
        coverage=coverage if coverage.rows or coverage.unread else None,
        findings=findings,
        dropped=state.dropped,
    )


def write_report(
    report: FinalReport,
    repo: Path,
    dirname: str,
    when: datetime,
    formats: set[str] | None = None,
) -> Path:
    """Write the selected artifacts. Refuses a symlinked output directory."""

    selected = _normalize_formats(formats)
    root = repo.resolve()
    directory = root / dirname
    if is_reparse_point(directory) or (directory.exists() and not directory.is_dir()):
        raise UsageError("report directory must be a real directory inside the repository")
    directory.mkdir(parents=True, exist_ok=True)
    if is_reparse_point(directory) or not is_within(root, directory):
        raise UsageError("report directory must be a real directory inside the repository")
    stamp = when.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    module = _module_name(report.repo_name)
    findings = directory / "findings.json"
    written = findings
    if "json" in selected:
        payload = report.model_dump(mode="json")
        _atomic_write(findings, json.dumps(payload, indent=2) + "\n")
    if "md" in selected:
        written = directory / f"{module}_{stamp}_report.md"
        _atomic_write(written, render_markdown(report))
    if "sarif" in selected:
        written = directory / f"{module}_{stamp}_report.sarif"
        _atomic_write(written, json.dumps(render_sarif(report), indent=2) + "\n")
    if "html" in selected:
        written = directory / f"{module}_{stamp}_report.html"
        _atomic_write(written, render_html(report))
    if "pdf" in selected:
        written = directory / f"{module}_{stamp}_report.pdf"
        _atomic_write_bytes(written, render_pdf(report))
    if "yaml" in selected:
        written = directory / f"{module}_{stamp}_report.yaml"
        _atomic_write(written, render_yaml(report))
    if "json" in selected:
        return findings
    return written


_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STAGE_TITLES = {
    "d0": "Scope",
    "d1": "Context",
    "d2": "Review list",
    "d3": "Units",
    "d4": "Model review",
    "d5": "Detectors",
    "d6": "Review stamp",
    "d7": "Dedup",
    "d8": "Rank",
    "d9": "Report",
}
_DROP_GLOSS = {
    "not_a_sink": "the line is not the call the rule is about",
    "bound_parameter": "the assembled text is a bound value",
    "fixed_clause": "the inserted text is a fixed clause",
    "fixture": "the value is a fixture, not a live credential",
    "duplicate": "the same rule already covers a nearby line",
}


def render_markdown(report: FinalReport) -> str:
    """Human report. The JSON summary stays at the end, under Record."""

    metrics = report.metrics
    review = metrics.model_review or "not run"
    lines = [
        "# Control gap report",
        "",
        (
            f"{report.repo_name} · {report.profile} · silentblue {report.version} · "
            f"{report.generated_at} · schema {report.schema_version}"
        ),
        f"Advisories {report.advisories} · threat model {report.threat_model} · model review {review}",
        "",
        "## Result",
        "",
    ]
    lines.extend(_severity_table(report.findings))
    lines.append("")
    lines.extend(_category_table(report.findings))
    lines.append("")
    lines.append(
        f"Scope: {metrics.files} files, {metrics.bytes} bytes, {metrics.primary_language}."
    )
    if metrics.model_calls:
        lines.append(
            "Cost: estimated "
            f"{format_usd(metrics.estimated_cost_usd, metrics.rate_known)} USD, actual "
            f"{format_usd(metrics.actual_cost_usd, metrics.usage_known and metrics.rate_known)} USD, "
            f"{metrics.model_calls} model calls."
        )
    if report.hollow:
        lines.append("This empty result is untrusted. No source was sent for review.")
    elif not report.findings:
        lines.append("No control gaps were reported. Review the coverage ledger before treating the repository as covered.")
    if report.coverage is not None:
        lines.extend(["", "## Coverage", ""])
        lines.extend(_coverage_lines(report.coverage))
    if report.edge_passed:
        lines.append(f"Edge checks passed: {', '.join(report.edge_passed)}.")
    lines.extend(["", "## Index", ""])
    if not report.findings:
        lines.append("None.")
    else:
        lines.extend(_index_table(report.findings))
    lines.extend(["", f"## Findings ({len(report.findings)})", ""])
    if not report.findings:
        lines.append("None.")
        lines.append("")
    for index, finding in enumerate(report.findings, start=1):
        lines.extend(_finding_block(index, finding))
    lines.extend(_dropped_section(report.dropped))
    lines.extend(["", "## Appendix", "", "### Stages", ""])
    for name, outcome in report.stages.items():
        title = _STAGE_TITLES.get(name, name)
        lines.append(f"{title} ({name}): {outcome}")
    lines.extend(["", "### Record", "", report.summary, ""])
    return "\n".join(lines)


def _coverage_lines(coverage) -> list[str]:
    checked = sum(1 for row in coverage.rows if row.families)
    skipped: dict[str, int] = {}
    for row in coverage.rows:
        if row.reason:
            skipped[row.reason] = skipped.get(row.reason, 0) + 1
    lines = [
        f"Saturated: {'yes' if coverage.saturated else 'no'}",
        f"Checked: {checked}",
    ]
    for reason in sorted(skipped):
        lines.append(f"Skipped {reason}: {skipped[reason]}")
    if coverage.unread:
        shown = ", ".join(coverage.unread[:8])
        lines.append(f"Unread review paths: {shown}")
    return lines


def _metric_lines(metrics: Metrics) -> list[str]:
    return [
        f"Files: {metrics.files}",
        f"Bytes: {metrics.bytes}",
        f"Primary language: {metrics.primary_language}",
        f"Findings: {metrics.findings}",
        f"Dropped: {metrics.dropped}",
        f"Symlink escapes excluded: {metrics.symlink_escapes}",
        f"Model calls: {metrics.model_calls}",
        f"Model list: {metrics.model_paths_read} of {metrics.model_paths} read",
        f"Model review: {metrics.model_review or 'not run'}",
        f"Estimated model calls: {metrics.estimated_calls}",
        f"Estimated cost USD: {format_usd(metrics.estimated_cost_usd, metrics.rate_known)}",
        f"Actual cost USD: {format_usd(metrics.actual_cost_usd, metrics.usage_known and metrics.rate_known)}",
        f"Input tokens: {metrics.input_tokens}",
        f"Output tokens: {metrics.output_tokens}",
        f"Price table: {metrics.price_date or 'none'}",
    ]


def render_sarif(report: FinalReport) -> dict:
    """SARIF 2.1.0 built from the same typed report."""

    rules: list[dict] = []
    seen: set[str] = set()
    results: list[dict] = []
    for finding in report.findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.remediation},
                    "properties": {"controlFamily": finding.control_family},
                }
            )
        result: dict = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {
                "text": redact(
                    f"{finding.title}\n{finding.description}\nRemediation: {finding.remediation}"
                )
            },
            "locations": [_location(finding.file, finding.line)],
            "partialFingerprints": {"sbFindingId/v1": finding.case_id},
            "properties": {
                "controlFamily": finding.control_family,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "origin": finding.origin,
                "playbook": finding.playbook,
                "verdict": finding.verdict,
            },
        }
        if finding.cvss_score is not None:
            result["properties"]["cvssScore"] = finding.cvss_score
        if finding.cvss_vector:
            result["properties"]["cvssVector"] = finding.cvss_vector
            result["properties"]["cvssVersion"] = finding.cvss_version
        if finding.advisory_id:
            result["properties"]["advisoryId"] = finding.advisory_id
        if finding.component is not None:
            result["properties"]["component"] = finding.component.model_dump()
        if finding.also_at:
            result["relatedLocations"] = [
                _location(finding.file, line) for line in finding.also_at
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Silent Blue",
                        "version": report.version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "profile": report.profile,
                    "modelCalls": report.metrics.model_calls,
                    "files": report.metrics.files,
                    "hollow": report.hollow,
                    "advisories": report.advisories,
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 0,
                    }
                ],
            }
        ],
    }


def finding_fields(finding: Finding) -> list[tuple[str, str]]:
    """Labeled facts. Empty optional values are left out."""

    fields = [
        ("Severity", finding.severity),
        ("Rule", finding.rule_id),
        ("Control family", finding.control_family),
        ("File", finding.file),
        ("Line", str(finding.line)),
        ("Case", finding.case_id),
        ("Confidence", format(finding.confidence, "g")),
        ("Verdict", finding.verdict),
    ]
    if finding.category:
        fields.append(("Category", finding.category))
    if finding.playbook:
        fields.append(("Playbook", finding.playbook))
    if finding.cvss_score is not None:
        fields.append(("CVSS score", format(finding.cvss_score, ".1f")))
    if finding.cvss_version:
        fields.append(("CVSS version", finding.cvss_version))
    if finding.cvss_vector:
        fields.append(("CVSS vector", finding.cvss_vector))
    if finding.advisory_id:
        fields.append(("Advisory", finding.advisory_id))
    component = finding.component
    if component is not None and component.purl.startswith("pkg:"):
        fields.append(
            ("Component", f"{component.ecosystem} {component.name} {component.version}".strip())
        )
        fields.append(("Package URL", component.purl))
        if component.fixed_version:
            fields.append(("Fixed", component.fixed_version))
        if component.relationship:
            fields.append(("Relationship", component.relationship))
    if finding.also_at:
        fields.append(("Also at", ", ".join(str(line) for line in finding.also_at)))
    if finding.also_in:
        fields.append(("Also in", ", ".join(finding.also_in)))
    return fields


def finding_sections(finding: Finding) -> list[tuple[str, str]]:
    """Headed prose. Every finding uses the same three headings."""

    sections = [
        ("Description", finding.description),
        ("Evidence", finding.snippet),
    ]
    if finding.threat_note:
        sections.append(("Threat model", finding.threat_note))
    sections.append(("Remediation", finding.remediation))
    return sections


def finding_lines(finding: Finding, index: int) -> list[str]:
    """The finding block printed by the report and by /finding."""

    return _finding_block(index, finding)


def _finding_block(index: int, finding: Finding) -> list[str]:
    number = finding.number or index
    lines = [
        f"## Finding {number}: {finding.title}",
        "",
        _identity(finding),
    ]
    cvss = _cvss_line(finding)
    if cvss:
        lines.append(cvss)
    extra = _extra_line(finding)
    if extra:
        lines.append(extra)
    lines.append("")
    for label, text in finding_sections(finding):
        lines.append(f"{label}:")
        if label == "Evidence":
            lines.extend(_fence(finding.file, text))
        elif text:
            lines.append(text.rstrip("\n"))
        lines.append("")
    return lines


def _identity(finding: Finding) -> str:
    case = finding.case_id or "unassigned"
    return f"{finding.severity} · {finding.rule_id} · {finding.file}:{finding.line} · {case}"


def _cvss_line(finding: Finding) -> str:
    if finding.cvss_score is None:
        return ""
    version = finding.cvss_version or "3.1"
    score = format(finding.cvss_score, ".1f")
    vector = f" {finding.cvss_vector}" if finding.cvss_vector else ""
    return f"CVSS {version} {score}{vector}"


def _extra_line(finding: Finding) -> str:
    parts: list[str] = []
    if finding.verdict:
        parts.append(f"Verdict {finding.verdict}")
    if finding.playbook:
        parts.append(f"Playbook {finding.playbook}")
    if finding.category:
        parts.append(f"Category {finding.category}")
    if finding.advisory_id:
        parts.append(f"Advisory {finding.advisory_id}")
    component = finding.component
    if component is not None and component.purl.startswith("pkg:"):
        parts.append(
            f"Component {component.ecosystem} {component.name} {component.version}".strip()
        )
        if component.fixed_version:
            parts.append(f"Fixed {component.fixed_version}")
    if finding.also_at:
        parts.append("Also at " + ", ".join(str(line) for line in finding.also_at))
    if finding.also_in:
        parts.append("Also in " + ", ".join(finding.also_in))
    return " · ".join(parts)


def _fence(path: str, snippet: str) -> list[str]:
    if not snippet:
        return []
    marker = "```"
    while marker in snippet:
        marker += "`"
    return [f"{marker}{path}", *snippet.splitlines(), marker]


def _severity_table(findings: list[Finding]) -> list[str]:
    counts = {name: 0 for name in _SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    header = "| Severity | " + " | ".join(name.capitalize() for name in _SEVERITIES) + " |"
    rule = "| --- | " + " | ".join("---" for _ in _SEVERITIES) + " |"
    row = "| Count | " + " | ".join(str(counts[name]) for name in _SEVERITIES) + " |"
    return [header, rule, row]


def _category_table(findings: list[Finding]) -> list[str]:
    buckets: dict[str, dict[str, int]] = {}
    for finding in findings:
        key = finding.control_family or "unspecified"
        bucket = buckets.setdefault(key, {name: 0 for name in (*_SEVERITIES, "confirmed", "unsettled")})
        bucket[finding.severity] = bucket.get(finding.severity, 0) + 1
        if finding.verdict == "inconclusive":
            bucket["unsettled"] += 1
        else:
            bucket["confirmed"] += 1
    header = (
        "| Control category | "
        + " | ".join(name.capitalize() for name in _SEVERITIES)
        + " | Confirmed | Unsettled |"
    )
    rule = "| --- | " + " | ".join("---" for _ in (*_SEVERITIES, "c", "u")) + " |"
    lines = [header, rule]
    if not buckets:
        lines.append("| None | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")
        return lines
    for key in sorted(buckets, key=lambda item: (-sum(buckets[item][name] for name in _SEVERITIES), item)):
        bucket = buckets[key]
        cells = " | ".join(str(bucket[name]) for name in _SEVERITIES)
        lines.append(
            f"| {_category_label(key)} | {cells} | {bucket['confirmed']} | {bucket['unsettled']} |"
        )
    return lines


def _index_table(findings: list[Finding]) -> list[str]:
    lines = [
        "| # | Severity | Rule | Location | Case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for index, finding in enumerate(findings, start=1):
        number = finding.number or index
        rule = finding.advisory_id or finding.rule_id
        lines.append(
            f"| {number} | {finding.severity} | {rule} | {finding.file}:{finding.line} | {finding.case_id} |"
        )
    return lines


def _dropped_section(dropped: list) -> list[str]:
    lines = ["", f"## Dropped ({len(dropped)})", ""]
    if not dropped:
        lines.extend(["None.", ""])
        return lines
    reasons = sorted({item.reason for item in dropped})
    gloss = "; ".join(f"{reason}: {_DROP_GLOSS.get(reason, reason)}" for reason in reasons)
    lines.extend([gloss, ""])
    grouped: dict[str, list] = {}
    for item in dropped:
        grouped.setdefault(item.reason, []).append(item)
    for reason in sorted(grouped):
        lines.append(f"### {reason}")
        lines.append("")
        for item in grouped[reason]:
            lines.append(f"{item.file}:{item.line}  {item.rule_id}  {item.reason}")
        lines.append("")
    return lines


def _category_label(family: str) -> str:
    return " ".join(part.capitalize() for part in family.replace("_", "-").split("-"))


def _present(finding: Finding, number: int) -> Finding:
    """Give every finding a report number, a CVSS pair, and a component."""

    from silentblue.supply import cvss_for

    if finding.cvss_score is not None and finding.cvss_vector:
        score = finding.cvss_score
        vector = finding.cvss_vector
        version = finding.cvss_version or "3.1"
    else:
        score, vector = cvss_for(finding.rule_id, finding.severity)
        version = "3.1"
    component = finding.component or ComponentDetail(
        ecosystem="file",
        name=finding.file,
        version="",
        purl=finding.file,
    )
    remediation = finding.remediation
    if APPLY_MARK not in remediation:
        remediation = apply_note(finding.file, finding.line, remediation, origin=finding.origin)
    return finding.model_copy(
        update={
            "number": number,
            "cvss_score": score,
            "cvss_vector": vector,
            "cvss_version": version,
            "component": component,
            "remediation": remediation,
        }
    )


def _location(path: str, line: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }
    }


def _metrics(state: RunState, findings: list[Finding]) -> Metrics:
    scope = state.scope
    languages: dict[str, int] = {}
    total = 0
    files = 0
    escapes = 0
    if scope is not None:
        files = len(scope.files)
        escapes = len(scope.symlink_escapes)
        for item in scope.files:
            total += item.size
            languages[item.language] = languages.get(item.language, 0) + 1
    primary = "unknown"
    manifests: list[str] = []
    hints: list[str] = []
    if state.context is not None:
        primary = state.context.primary_language
        languages = state.context.languages
        total = state.context.total_bytes
        files = state.context.file_count
        manifests = state.context.manifests
        hints = state.context.control_hints
    elif languages:
        primary = sorted(languages.items(), key=lambda item: (-item[1], item[0]))[0][0]
    source_files = 0
    if scope is not None:
        source_files = sum(1 for item in scope.files if is_source_path(item.path))
    reviewed = set(state.reviewed_units)
    files_reviewed = len(
        {path for unit in state.units if unit.unit_id in reviewed for path in unit.paths}
    )
    model_paths = len(state.review_paths)
    model_paths_read = len(
        {
            path
            for unit in state.units
            if unit.unit_id in reviewed
            for path in unit.paths
            if path in set(state.review_paths)
        }
    )
    if state.review_note or state.review_paths:
        model_review = "complete" if model_paths_read == model_paths else "incomplete"
    else:
        model_review = ""
    made_calls = state.model_calls > 0
    spent, spent_rate_known = actual_cost(
        state.input_tokens,
        state.output_tokens,
        provider=state.model_provider,
        model_name=state.model_name,
        usage_known=state.usage_known,
        made_calls=made_calls,
    )
    return Metrics(
        files=files,
        bytes=total,
        languages=dict(sorted(languages.items())),
        primary_language=primary,
        manifests=manifests,
        control_hints=hints,
        findings=len(findings),
        dropped=len(state.dropped),
        source_files=source_files,
        files_reviewed=files_reviewed,
        symlink_escapes=escapes,
        model_calls=state.model_calls,
        estimated_calls=state.estimated_calls,
        estimated_cost_usd=state.estimated_cost_usd,
        actual_cost_usd=spent,
        input_tokens=state.input_tokens,
        output_tokens=state.output_tokens,
        estimated_input_tokens=state.estimated_input_tokens,
        estimated_output_tokens=state.estimated_output_tokens,
        usage_known=state.usage_known,
        rate_known=state.rate_known and spent_rate_known,
        price_date=PRICE_DATE,
        model_provider=state.model_provider,
        model_name=state.model_name,
        model_paths=model_paths,
        model_paths_read=model_paths_read,
        model_review=model_review,
    )


def _hollow(state: RunState, stages: dict[str, StageOutcome], finding_count: int) -> bool:
    files = len(state.scope.files) if state.scope is not None else 0
    reviewed = stages.get("d2") in {"completed", "cached", "degraded"}
    walked = bool(state.units)
    return files > 0 and reviewed and not walked and finding_count == 0


def _redact_finding(finding: Finding) -> Finding:
    return finding.model_copy(
        update={
            "title": redact(finding.title),
            "description": redact(finding.description),
            "remediation": redact(finding.remediation),
            "snippet": redact(finding.snippet),
            "threat_note": redact(finding.threat_note),
        }
    )


def _html_finding(finding: Finding, index: int, escape) -> str:
    number = finding.number or index
    sections: list[str] = []
    for label, text in finding_sections(finding):
        escaped = escape(text)
        if label == "Evidence":
            block = f"<pre><code>{escaped}</code></pre>"
        else:
            block = "<p>" + escaped.replace("\n", "<br>\n") + "</p>"
        sections.append(f"<h3>{escape(label)}</h3>{block}")
    extra = _extra_line(finding)
    cvss = _cvss_line(finding)
    meta = "".join(
        f"<p class='meta'>{escape(line)}</p>" for line in (_identity(finding), cvss, extra) if line
    )
    return (
        f"<article class='gap {escape(finding.severity)}' id='finding-{number}'>"
        f"<h2>Finding {number}: {escape(finding.title)}</h2>"
        f"{meta}"
        + "".join(sections)
        + "</article>"
    )


_PROSE = frozenset({"summary", "advisory_note", "description", "remediation", "snippet", "threat_note"})


def render_yaml(report: FinalReport) -> str:
    """The typed report as YAML. Field names match findings.json."""

    import yaml

    class _Literal(str):
        pass

    class _Dumper(yaml.SafeDumper):
        pass

    def _represent_literal(dumper: yaml.SafeDumper, data: str):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")

    _Dumper.add_representer(_Literal, _represent_literal)

    def mark(value: object, key: str = "") -> object:
        if isinstance(value, str) and value and (key in _PROSE or "\n" in value):
            return _Literal(value)
        if isinstance(value, dict):
            return {name: mark(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [mark(item) for item in value]
        return value

    text = yaml.dump(
        mark(report.model_dump(mode="json")),
        Dumper=_Dumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=1000,
    )
    return text if text.endswith("\n") else text + "\n"


def _module_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned or "repository"


REPORT_FORMATS = frozenset({"json", "md", "sarif", "html", "pdf", "yaml"})
DEFAULT_FORMATS = frozenset({"json", "md", "sarif", "html", "pdf"})
_FORMAT_HELP = "format must be a list of json, md, sarif, html, pdf, yaml"


def parse_formats(value: str) -> set[str]:
    """Split a comma-separated format list."""

    selected = {item.strip().lower() for item in value.split(",") if item.strip()}
    if not selected or not selected <= REPORT_FORMATS:
        raise UsageError(_FORMAT_HELP)
    return selected


def _normalize_formats(formats: set[str] | None) -> set[str]:
    if formats is None:
        return set(DEFAULT_FORMATS)
    if not formats or not formats <= REPORT_FORMATS:
        raise UsageError(_FORMAT_HELP)
    return formats


def render_html(report: FinalReport) -> str:
    """One self-contained HTML file. It loads nothing from the network."""

    from html import escape

    metrics = report.metrics
    rows = [_html_finding(finding, index, escape) for index, finding in enumerate(report.findings, start=1)]
    body = "\n".join(rows) or "<p>No control gaps were reported.</p>"
    actual_known = metrics.usage_known and metrics.rate_known
    review = metrics.model_review or "not run"
    index_rows = []
    for index, finding in enumerate(report.findings, start=1):
        number = finding.number or index
        rule = finding.advisory_id or finding.rule_id
        index_rows.append(
            "<tr>"
            f"<td><a href='#finding-{number}'>{number}</a></td>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(rule)}</td>"
            f"<td>{escape(finding.file)}:{finding.line}</td>"
            f"<td>{escape(finding.case_id)}</td>"
            "</tr>"
        )
    index = (
        "<table><thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Location</th><th>Case</th></tr></thead>"
        f"<tbody>{''.join(index_rows) or '<tr><td colspan=5>None</td></tr>'}</tbody></table>"
    )
    cost = ""
    if metrics.model_calls:
        cost = (
            "<p>Cost: estimated "
            f"{escape(format_usd(metrics.estimated_cost_usd, metrics.rate_known))} USD, actual "
            f"{escape(format_usd(metrics.actual_cost_usd, actual_known))} USD, "
            f"{metrics.model_calls} model calls.</p>"
        )
    else:
        cost = (
            "<p>Estimated cost USD "
            f"{escape(format_usd(metrics.estimated_cost_usd, metrics.rate_known))}.</p>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Control gap report {escape(report.repo_name)}</title>
<style>
body {{ font: 15px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; color: #1c1917; background: #fff; font-variant-numeric: tabular-nums; }}
h1 {{ font-size: 1.5rem; font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.6rem 0 1.2rem; }}
th, td {{ text-align: left; padding: 0.25rem 0.6rem; border-bottom: 1px solid #e7e5e4; }}
.gap {{ border: 1px solid #e7e5e4; border-left-width: 4px; padding: 1rem 1.2rem; margin: 1rem 0; }}
.critical {{ border-left-color: #7f1d1d; }}
.high {{ border-left-color: #9a3412; }}
.medium {{ border-left-color: #a16207; }}
.low, .info {{ border-left-color: #57534e; }}
.meta {{ margin: 0.15rem 0; color: #44403c; }}
h3 {{ font-size: 0.95rem; margin: 0.9rem 0 0.3rem; }}
pre {{ white-space: pre-wrap; background: #f5f5f4; padding: 0.6rem; }}
@media print {{
  body {{ margin: 0.5in; }}
  .gap {{ break-inside: avoid; }}
  a {{ color: inherit; text-decoration: none; }}
}}
</style>
</head>
<body>
<h1>Control gap report</h1>
<p>{escape(report.repo_name)} · {escape(report.profile)} · silentblue {escape(report.version)} · {escape(report.generated_at)} · schema {escape(report.schema_version)}</p>
<p>Advisories {escape(report.advisories)} · threat model {escape(report.threat_model)} · model review {escape(review)}</p>
{cost}
<h2>Index</h2>
{index}
{body}
<h2>Record</h2>
<p>{escape(report.summary)}</p>
</body>
</html>
"""


def render_pdf(report: FinalReport) -> bytes:
    """A text PDF of the Markdown, with a running header and a page number."""

    lines = _wrap(render_markdown(report).splitlines(), 90)
    pages = [lines[index : index + 44] for index in range(0, len(lines), 44)] or [[""]]
    return _pdf_document(pages, report.repo_name)


def _wrap(lines: list[str], width: int) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        text = line.replace("\t", "    ")
        if not text:
            wrapped.append("")
            continue
        while len(text) > width:
            wrapped.append(text[:width])
            text = text[width:]
        wrapped.append(text)
    return wrapped


def _pdf_document(pages: list[list[str]], repo_name: str) -> bytes:
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    total = len(pages)
    for number, lines in enumerate(pages, start=1):
        content_ids.append(add(_page_stream(lines, f"{repo_name}  {number} / {total}")))
    for content_id in content_ids:
        page_ids.append(
            add(
                b"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 612 792] "
                + f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font} 0 R >> >> >>".encode()
            )
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    pages_id = add(f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode())
    for index, page_id in enumerate(page_ids):
        objects[page_id - 1] = objects[page_id - 1].replace(b"/Parent 0 0 R", f"/Parent {pages_id} 0 R".encode())
    catalog = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
    return _serialize(objects, catalog)


def _page_stream(lines: list[str], header: str) -> bytes:
    commands = [
        "BT",
        "/F1 9 Tf",
        "50 770 Td",
        f"({_pdf_escape(header)}) Tj",
        "0 -22 Td",
        "/F1 11 Tf",
        "14 TL",
    ]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.append("ET")
    stream = "\n".join(commands).encode("latin-1", errors="replace")
    return b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"


def _pdf_escape(text: str) -> str:
    encoded = text.encode("latin-1", errors="replace").decode("latin-1")
    return encoded.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _serialize(objects: list[bytes], root: int) -> bytes:
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    chunks = [header]
    offsets = [0]
    cursor = len(header)
    for number, body in enumerate(objects, start=1):
        offsets.append(cursor)
        piece = f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
        chunks.append(piece)
        cursor += len(piece)
    xref_at = cursor
    xref = [f"xref\n0 {len(objects) + 1}\n".encode(), b"0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n".encode())
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {root} 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return b"".join([*chunks, *xref, trailer])


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
