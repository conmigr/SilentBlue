"""Import SARIF 2.1.0 results. Locations outside the repository are not opened."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from silentblue import __version__
from silentblue.casefiles import read_source
from silentblue.errors import RunError, SilentBlueError, UsageError
from silentblue.manifest import write_manifest
from silentblue.models import (
    CASE_ID,
    STAGES,
    DroppedFinding,
    FinalReport,
    Finding,
    IngestResult,
    Metrics,
    Severity,
)
from silentblue.paths import is_reparse_point, is_within
from silentblue.playbooks import PLAYBOOKS
from silentblue.rank import case_id_for
from silentblue.redact import configure_logging, redact
from silentblue.report import _present, write_report
from silentblue.runner import _assert_output_available, _require_repo

logger = logging.getLogger(__name__)

_MAX_BYTES = 2_000_000
_MAX_RESULTS = 200
_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_FROM_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_REMEDIATION = "Review the imported result and put the named control in place."
_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
}


def run_ingest(
    *,
    repo: Path,
    sarif: Path,
    manifest_dir: Path | None = None,
    cwd: Path | None = None,
    argv: list[str] | None = None,
) -> IngestResult:
    """Write a Silent Blue report from SARIF. This command makes no model calls."""

    configure_logging()
    exit_code = 0
    message = "ok"
    finding_count = 0
    dropped_count = 0
    findings_path: str | None = None
    manifest_path: str | None = None
    try:
        root = _require_repo(repo)
        _assert_output_available(root, "security-scan")
        document = _load_sarif(sarif)
        findings, dropped, files, total_bytes = _collect(root, document)
        findings = _assign_ids(findings)
        findings = _ordered(findings)
        now = datetime.now(timezone.utc)
        report = _report(root, findings, dropped, files, total_bytes, now)
        path = write_report(report, root, "security-scan", now)
        finding_count = len(findings)
        dropped_count = len(dropped)
        findings_path = str(path)
        message = f"imported {finding_count} results, dropped {dropped_count}"
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
        logger.warning("%s", message)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
        logger.exception("ingest failed")
    try:
        manifest_path = str(
            write_manifest(
                manifest_dir or cwd or Path.cwd(),
                {
                    "command": "ingest",
                    "argv": argv or [],
                    "exit_code": exit_code,
                    "message": message,
                    "findings": finding_count,
                    "dropped": dropped_count,
                    "model_calls": 0,
                    "report": findings_path,
                },
            )
        )
    except OSError as exc:
        logger.warning("manifest was not written: %s", exc.strerror or "unwritable")
    return IngestResult(
        exit_code=exit_code,
        message=message,
        finding_count=finding_count,
        dropped_count=dropped_count,
        findings_path=findings_path,
        manifest_path=manifest_path,
        model_calls=0,
    )


def _load_sarif(path: Path) -> dict:
    if is_reparse_point(path) or not path.is_file():
        raise UsageError("SARIF path must be a real file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UsageError("SARIF path must be a real file") from exc
    if len(raw) > _MAX_BYTES or b"\0" in raw[:1024]:
        raise UsageError("SARIF file is too large")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UsageError("SARIF file is not JSON") from exc
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise UsageError("SARIF version must be 2.1.0")
    if not isinstance(document.get("runs"), list):
        raise UsageError("SARIF file has no runs")
    return document


def _collect(
    repo: Path,
    document: dict,
) -> tuple[list[Finding], list[DroppedFinding], int, int]:
    findings: list[Finding] = []
    dropped: list[DroppedFinding] = []
    seen_bytes: dict[str, int] = {}
    produced = 0
    for run in document["runs"]:
        if not isinstance(run, dict):
            continue
        help_text = _rule_help(run)
        for result in run.get("results") or []:
            if produced >= _MAX_RESULTS:
                dropped.append(DroppedFinding(rule_id="sarif", file=".", line=1, reason="limit"))
                continue
            produced += 1
            if not isinstance(result, dict):
                dropped.append(DroppedFinding(rule_id="sarif", file=".", line=1, reason="unparseable"))
                continue
            parsed = _one_result(repo, result, help_text, seen_bytes)
            if isinstance(parsed, Finding):
                findings.append(parsed)
            else:
                dropped.append(parsed)
    return findings, dropped, len(seen_bytes), sum(seen_bytes.values())


def _one_result(
    repo: Path,
    result: dict,
    help_text: dict[str, str],
    seen_bytes: dict[str, int],
) -> Finding | DroppedFinding:
    rule_id = str(result.get("ruleId") or "").strip()
    if not rule_id or len(rule_id) > 120 or any(char in rule_id for char in "\r\n/\\"):
        return DroppedFinding(rule_id="sarif", file=".", line=1, reason="rule")
    located = _location(result)
    if located is None:
        return DroppedFinding(rule_id=rule_id, file=".", line=1, reason="location")
    uri, line = located
    relative = _relative_uri(repo, uri)
    if relative is None:
        return DroppedFinding(rule_id=rule_id, file=_safe_name(uri), line=line, reason="outside_root")
    path = repo / relative
    if is_reparse_point(path) or not is_within(repo, path):
        return DroppedFinding(rule_id=rule_id, file=relative, line=line, reason="outside_root")
    text = read_source(repo, relative)
    if text is None:
        return DroppedFinding(rule_id=rule_id, file=relative, line=line, reason="unreadable")
    rows = text.splitlines()
    if line > len(rows):
        return DroppedFinding(rule_id=rule_id, file=relative, line=line, reason="line_out_of_range")
    seen_bytes.setdefault(relative, len(text.encode("utf-8")))
    properties = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    message = _message(result)
    title = _title(result, help_text, rule_id, message)
    severity = _severity(result, properties)
    family = _family(properties)
    fingerprint = ((result.get("partialFingerprints") or {}) if isinstance(result.get("partialFingerprints"), dict) else {}).get("sbFindingId/v1", "")
    case_id = fingerprint if isinstance(fingerprint, str) and CASE_ID.fullmatch(fingerprint) else ""
    confidence = properties.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
        confidence = 0.5
    playbook = properties.get("playbook") if isinstance(properties.get("playbook"), str) else ""
    if playbook not in PLAYBOOKS:
        playbook = family if family in PLAYBOOKS else ""
    remediation = help_text.get(rule_id, "").strip() or _REMEDIATION
    return Finding(
        case_id=case_id,
        rule_id=rule_id,
        control_family=family,
        severity=severity,
        title=redact(title)[:200],
        file=relative,
        line=line,
        description=redact(message)[:800],
        remediation=redact(remediation)[:800],
        snippet=redact(rows[line - 1])[:240],
        confidence=float(confidence),
        origin="imported",
        playbook=playbook,
        verdict="imported",
    )


def _relative_uri(repo: Path, uri: str) -> str | None:
    text = unquote(uri.strip())
    if not text:
        return None
    if text.startswith("file:"):
        parsed = urlparse(text)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            return None
        raw = parsed.path
        if raw.startswith("/") and len(raw) > 2 and raw[2] == ":":
            raw = raw[1:]
        candidate = Path(raw)
        if not is_within(repo, candidate):
            return None
        try:
            return candidate.resolve().relative_to(repo.resolve()).as_posix()
        except (OSError, ValueError):
            return None
    normalized = text.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        return None
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _location(result: dict) -> tuple[str, int] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    uri = artifact.get("uri")
    line = region.get("startLine")
    if not isinstance(uri, str) or not isinstance(line, int) or line < 1:
        return None
    return uri, line


def _rule_help(run: dict) -> dict[str, str]:
    driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else {}
    rules = driver.get("rules") if isinstance(driver, dict) else []
    found: dict[str, str] = {}
    if not isinstance(rules, list):
        return found
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            continue
        help_block = rule.get("help") if isinstance(rule.get("help"), dict) else {}
        text = help_block.get("text") if isinstance(help_block.get("text"), str) else ""
        name = rule.get("name") if isinstance(rule.get("name"), str) else ""
        found[rule["id"]] = text
        if name:
            found[f"name:{rule['id']}"] = name
    return found


def _message(result: dict) -> str:
    message = result.get("message") if isinstance(result.get("message"), dict) else {}
    text = message.get("text") if isinstance(message.get("text"), str) else ""
    if not text and isinstance(message.get("markdown"), str):
        text = message["markdown"]
    return text.strip() or "Imported SARIF result."


def _title(result: dict, help_text: dict[str, str], rule_id: str, message: str) -> str:
    named = help_text.get(f"name:{rule_id}", "").strip()
    if named:
        return named
    first = message.splitlines()[0].strip() if message else ""
    return first or rule_id


def _severity(result: dict, properties: dict) -> Severity:
    named = properties.get("severity")
    if isinstance(named, str) and named in _SEVERITY:
        return named  # type: ignore[return-value]
    level = result.get("level")
    if isinstance(level, str) and level in _FROM_LEVEL:
        return _FROM_LEVEL[level]  # type: ignore[return-value]
    return "medium"


def _family(properties: dict) -> str:
    named = properties.get("controlFamily")
    if isinstance(named, str) and named in PLAYBOOKS:
        return named
    return "imported"


def _assign_ids(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    assigned: list[Finding] = []
    for index, finding in enumerate(findings):
        case_id = finding.case_id
        if CASE_ID.fullmatch(case_id) is None or case_id in seen:
            case_id = case_id_for(finding.file, finding.line, finding.rule_id)
        if case_id in seen:
            case_id = case_id_for(finding.file, finding.line, finding.rule_id, salt=str(finding.line))
        if case_id in seen:
            case_id = case_id_for(
                finding.file,
                finding.line,
                finding.rule_id,
                salt=f"{finding.line}:{index}",
            )
        if case_id in seen:
            raise RunError("duplicate case id")
        seen.add(case_id)
        assigned.append(finding.model_copy(update={"case_id": case_id}))
    return assigned


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY[finding.severity],
            -finding.confidence,
            finding.file,
            finding.line,
            finding.rule_id,
        ),
    )


def _report(
    repo: Path,
    findings: list[Finding],
    dropped: list[DroppedFinding],
    files: int,
    total_bytes: int,
    now: datetime,
) -> FinalReport:
    languages: dict[str, int] = {}
    for finding in findings:
        language = _LANG.get(Path(finding.file).suffix.lower(), "text")
        languages[language] = languages.get(language, 0) + 1
    primary = "unknown"
    if languages:
        primary = sorted(languages.items(), key=lambda item: (-item[1], item[0]))[0][0]
    summary = redact(
        f"Silent Blue imported SARIF results for {repo.name}. "
        f"{len(findings)} control gaps reported, {len(dropped)} candidates dropped. "
        "This profile makes no model calls."
    )
    return FinalReport(
        version=__version__,
        repo_name=repo.name,
        profile="detect",
        stop_after="d9",
        generated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        summary=summary,
        hollow=False,
        stages={stage: "not_run" for stage in STAGES},
        metrics=Metrics(
            files=files,
            bytes=total_bytes,
            languages=dict(sorted(languages.items())),
            primary_language=primary,
            manifests=[],
            control_hints=[],
            findings=len(findings),
            dropped=len(dropped),
            model_calls=0,
        ),
        findings=[_present(finding, index) for index, finding in enumerate(findings, start=1)],
        dropped=dropped,
    )


def _safe_name(uri: str) -> str:
    cleaned = uri.replace("\\", "/").split("/")[-1] or "."
    return cleaned[:120]
