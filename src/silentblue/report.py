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
from silentblue.confirm import confirm_status, line_hash
from silentblue.roles import path_role
from silentblue.scanledger import ledger_from_state
from silentblue.redact import redact
from silentblue.repair import APPLY_MARK, apply_note
from silentblue.playbooks import why_it_matters

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
    findings = [_annotate(finding, Path(state.repo), directory) for finding in findings]
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
            tail += " Partial assessment. Resume with /scan resume."
        else:
            tail += " Model review complete."
        tail += _pass_sentence("Refute", coverage_status(state, "refute"))
        tail += _pass_sentence("Miss", coverage_status(state, "miss"))
        if state.review_stop == "budget":
            tail += " The call budget stopped the review."
        elif state.review_stop == "owner":
            tail += " The owner stopped the review."
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
        if state.review_paths:
            if coverage.model_saturated:
                tail += " Model coverage saturated."
            else:
                tail += " Model coverage unsaturated."
        if coverage.unread:
            shown = ", ".join(coverage.unread[:16])
            extra = len(coverage.unread) - 16
            more = f" and {extra} more" if extra > 0 else ""
            tail += f" Unread review paths: {len(coverage.unread)}. The paths are {shown}{more}."
        skipped = [row for row in coverage.rows if row.model_state.startswith("skipped:")]
        if skipped:
            tail += f" Model skipped {len(skipped)}."
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
        f"{_product_phrase(findings)}, "
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


def render_markdown(report: FinalReport) -> str:
    """The assessment reading copy. The JSON summary stays under Record."""

    from silentblue.reading import render_markdown as _render

    return _render(report)


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
        _why, _impact = why_it_matters(finding.control_family)
        result: dict = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {
                "text": redact(
                    f"{finding.title}\n{finding.description}\n"
                    f"Why it matters: {_why}\nImpact: {_impact}\n"
                    f"Remediation: {finding.remediation}"
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


def finding_lines(finding: Finding, index: int, repo_name: str = "") -> list[str]:
    """The finding block printed by the report and by /finding."""

    from silentblue.reading import finding_markdown

    return finding_markdown(finding, index, repo_name or "repository")


def _annotate(finding: Finding, repo: Path, state_dir: Path) -> Finding:
    """Set the path role and whether an owner confirm still matches the line."""

    role = path_role(finding.file)
    status = ""
    if role == "test" and finding.rule_id == "hardcoded-secret" and finding.case_id:
        status = confirm_status(
            state_dir,
            repo,
            finding.case_id,
            line_hash(repo, finding.file, finding.line),
        )
    return finding.model_copy(update={"role": role, "owner_confirm": status})


def _product_phrase(findings: list[Finding]) -> str:
    count = sum(1 for finding in findings if finding.role in {"", "product"})
    noun = "product gap" if count == 1 else "product gaps"
    return f"{count} {noun}"


def coverage_status(state: RunState, name: str) -> str:
    if name == "refute":
        return state.refute_status
    return state.miss_status


def _pass_sentence(label: str, status: str) -> str:
    if status == "not_started":
        return f" {label} did not start."
    if status == "finished":
        return f" {label} finished."
    if status == "stopped":
        return f" {label} did not finish."
    return ""


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
    skipped = set(state.review_skips)
    files_reviewed = len(
        {
            path
            for unit in state.units
            if unit.unit_id in reviewed
            for path in unit.paths
            if path not in skipped
        }
    )
    listed = set(state.review_paths)
    model_paths = len(state.review_paths)
    model_paths_read = len(
        {
            path
            for unit in state.units
            if unit.unit_id in reviewed
            for path in unit.paths
            if path in listed and path not in skipped
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

    from silentblue.reading import render_html as _render

    return _render(report)


def render_pdf(report: FinalReport) -> bytes:
    """Pages drawn from the same sections as the HTML assessment."""

    from silentblue.reading import render_pdf as _render

    return _render(report)


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
