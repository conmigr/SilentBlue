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
from silentblue.redact import redact

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


def render_markdown(report: FinalReport) -> str:
    """Human report. Each finding is a labeled block."""

    lines = [
        "# Silent Blue control-gap report",
        "",
        f"Repository: {report.repo_name}",
        f"Profile: {report.profile}",
        f"Schema: {report.schema_version}",
        f"Advisories: {report.advisories}",
        "",
        "## Summary",
        "",
        report.summary,
        "",
    ]
    if report.hollow:
        lines.append(
            "This empty result is untrusted. No source was sent for review, "
            "and the detectors reported no gaps."
        )
    elif report.findings:
        lines.append("Findings are candidates for a person to review.")
    else:
        lines.append(
            "No control gaps were reported by the deterministic detectors. "
            "Review the scope before treating the repository as covered."
        )
    metrics = report.metrics
    lines.extend(["", "## Scan metrics", ""])
    lines.extend(_metric_lines(metrics))
    lines.extend(["", "## Stages", ""])
    for name, outcome in report.stages.items():
        lines.append(f"{name}: {outcome}")
    lines.extend(["", f"## Findings ({len(report.findings)})", ""])
    if not report.findings:
        lines.append("None.")
        lines.append("")
    for index, finding in enumerate(report.findings, start=1):
        lines.extend(_finding_block(index, finding))
    lines.extend([f"## Dropped findings ({len(report.dropped)})", ""])
    if not report.dropped:
        lines.append("None.")
        lines.append("")
    else:
        for item in report.dropped:
            lines.extend(
                [
                    f"File: {item.file}",
                    f"Line: {item.line}",
                    f"Rule: {item.rule_id}",
                    f"Reason: {item.reason}",
                    "",
                ]
            )
    return "\n".join(lines)


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
    return fields


def finding_sections(finding: Finding) -> list[tuple[str, str]]:
    """Headed prose. Description, evidence, and remediation are always present."""

    impact = "Impact" if finding.origin == "assessment" else "Description"
    repair = "Recommendation" if finding.origin == "assessment" else "Remediation"
    sections = [
        (impact, finding.description),
        ("Evidence", finding.snippet),
    ]
    if finding.threat_note:
        sections.append(("Threat model", finding.threat_note))
    sections.append((repair, finding.remediation))
    return sections


def _finding_block(index: int, finding: Finding) -> list[str]:
    number = finding.number or index
    lines = [f"## Finding {number}: {finding.title}", ""]
    lines.extend(f"{label}: {value}" for label, value in finding_fields(finding))
    lines.append("")
    for label, text in finding_sections(finding):
        lines.append(f"{label}:")
        if label == "Evidence":
            lines.extend(_evidence_lines(text))
        elif text:
            lines.append(text.rstrip("\n"))
        lines.append("")
    return lines


def _evidence_lines(snippet: str) -> list[str]:
    if not snippet:
        return []
    return [f"    {line}" if line else "" for line in snippet.splitlines()]


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
    return finding.model_copy(
        update={
            "number": number,
            "cvss_score": score,
            "cvss_vector": vector,
            "cvss_version": version,
            "component": component,
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
    facts = "".join(
        f"<dt>{escape(label)}:</dt><dd>{escape(value)}</dd>"
        for label, value in finding_fields(finding)
    )
    sections: list[str] = []
    for label, text in finding_sections(finding):
        escaped = escape(text)
        if label == "Evidence":
            block = f"<pre>{escaped}</pre>"
        else:
            block = "<p>" + escaped.replace("\n", "<br>\n") + "</p>"
        sections.append(f"<h3>{escape(label)}:</h3>{block}")
    return (
        '<article class="gap">'
        f"<h2>Finding {number}: {escape(finding.title)}</h2>"
        f"<dl>{facts}</dl>"
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
    facts = "".join(
        f"<dt>{escape(label)}:</dt><dd>{escape(value)}</dd>"
        for label, value in (
            ("Repository", report.repo_name),
            ("Profile", report.profile),
            ("Advisories", report.advisories),
            ("Estimated cost USD", format_usd(metrics.estimated_cost_usd, metrics.rate_known)),
            ("Actual cost USD", format_usd(metrics.actual_cost_usd, actual_known)),
            ("Model calls", str(metrics.model_calls)),
            ("Model list", f"{metrics.model_paths_read} of {metrics.model_paths} read"),
            ("Model review", metrics.model_review or "not run"),
            ("Price table", metrics.price_date or "none"),
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Silent Blue {escape(report.repo_name)}</title>
<style>
body {{ font: 16px/1.45 "Segoe UI", sans-serif; margin: 2rem auto; max-width: 48rem; color: #1c1917; background: #fafaf9; }}
h1 {{ font-size: 1.6rem; }}
.gap {{ background: #fff; border: 1px solid #e7e5e4; padding: 1rem; margin: 1rem 0; }}
dl {{ display: grid; grid-template-columns: 12rem 1fr; gap: 0.2rem 0.8rem; margin: 0.6rem 0 1rem; }}
dt {{ color: #57534e; }}
dd {{ margin: 0; }}
h3 {{ font-size: 1rem; margin: 0.8rem 0 0.3rem; }}
pre {{ white-space: pre-wrap; background: #f5f5f4; padding: 0.6rem; }}
</style>
</head>
<body>
<h1>Silent Blue · {escape(report.repo_name)}</h1>
<p>{escape(report.summary)}</p>
<dl>
{facts}
</dl>
{body}
</body>
</html>
"""


def render_pdf(report: FinalReport) -> bytes:
    """A text PDF of the same sections, with no native library."""

    lines = _wrap(render_markdown(report).splitlines(), 90)
    pages = [lines[index : index + 46] for index in range(0, len(lines), 46)] or [[""]]
    return _pdf_document(pages)


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


def _pdf_document(pages: list[list[str]]) -> bytes:
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    for lines in pages:
        content_ids.append(add(_page_stream(lines)))
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


def _page_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 11 Tf", "50 760 Td", "14 TL"]
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
