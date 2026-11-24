"""A reviewed map of assets and trust boundaries for one repository.

The file in the repository is always a draft. Acceptance is a hash stored
outside the repository. A draft never reorders findings.
"""

from __future__ import annotations

import hashlib
import json
from html import escape
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from silentblue.errors import UsageError
from silentblue.models import Finding
from silentblue.paths import is_reparse_point, is_within

MODEL_FILENAME = "threat-model.json"
HTML_FILENAME = "threat-model.html"
_DIRNAME = "security-scan"

_GROUPS: tuple[tuple[str, str, frozenset[str], str], ...] = (
    (
        "session-token",
        "Session token",
        frozenset({"token-in-web-storage", "credential-logged"}),
        "Keep the session token where page script cannot read it, and do not write it to a log.",
    ),
    (
        "credentials",
        "Credentials",
        frozenset({"hardcoded-secret", "default-credential"}),
        "Load credentials at runtime from outside the source tree.",
    ),
    (
        "stored-data",
        "Stored records",
        frozenset({"sql-unparameterized", "nosql-unparameterized"}),
        "Keep query text constant and pass values as bound parameters.",
    ),
    (
        "process",
        "Process execution",
        frozenset({"shell-command", "shell-enabled", "dynamic-eval", "ldap-filter-assembled", "template-from-string", "header-from-request"}),
        "Call programs with an argument list and do not evaluate assembled strings as code.",
    ),
    (
        "page-markup",
        "Page markup",
        frozenset({"html-parsed-from-string"}),
        "Build documents with DOM methods or a fixed template.",
    ),
    (
        "transport",
        "Server authentication",
        frozenset({"tls-verify-disabled"}),
        "Leave certificate verification enabled.",
    ),
    (
        "origins",
        "Cross-origin callers",
        frozenset({"cors-wildcard"}),
        "Name the origins allowed to call the application.",
    ),
    (
        "configuration",
        "Shared configuration",
        frozenset({"debug-enabled", "security-header-disabled"}),
        "Leave debug mode off, and leave browser and host controls enabled.",
    ),
    (
        "outbound-request",
        "Outbound requests",
        frozenset({"request-url-from-input", "redirect-from-request", "path-from-request"}),
        "Call fixed URLs, keep file paths under a fixed root, and allow-list redirect targets.",
    ),
    (
        "password-storage",
        "Password storage",
        frozenset({"weak-password-hash", "weak-token-random", "weak-cipher"}),
        "Use a password hash, a cryptographic generator, and an authenticated cipher.",
    ),
    (
        "object-decoder",
        "Object decoder",
        frozenset({"unsafe-deserialization"}),
        "Decode data with a parser that does not construct objects.",
    ),
    (
        "account-login",
        "Account login",
        frozenset({"jwt-verify-disabled", "cookie-flag-disabled", "csrf-disabled", "request-body-expanded"}),
        "Verify tokens, keep cookie flags on, keep CSRF checks on, and copy a named field list.",
    ),
    (
        "request-budget",
        "Request budget",
        frozenset({"rate-limit-disabled"}),
        "Leave a request limit enabled on login, signup, password, and upload routes.",
    ),
    (
        "audit-log",
        "Audit log",
        frozenset({"logging-disabled"}),
        "Leave logging enabled and record the event name only.",
    ),
    (
        "build",
        "Build inputs",
        frozenset(
            {
                "dependency-unpinned",
                "dependency-cleartext",
                "dependency-vulnerable",
                "install-verification-disabled",
                "ca-bundle-missing",
                "piped-download",
                "workflow-permissions-wide",
            }
        ),
        "Pin dependencies to an exact version, fetch them over TLS with a CA bundle, and name workflow permissions.",
    ),
    (
        "edge",
        "Public edge",
        frozenset(
            {
                "deploy-origin-public",
                "deploy-listener-cleartext",
                "deploy-waf-unattached",
                "deploy-admin-exposed",
                "deploy-forwarded-header",
                "deploy-certificate-untrusted",
                "deploy-certificate-name",
                "deploy-certificate-expiring",
                "deploy-cookie-flags",
                "deploy-url-unreachable",
                "deploy-redirect-elsewhere",
            }
        ),
        "Keep the origin behind the proxy, attach a WAF to the public listener, and keep admin and data ports private.",
    ),
)


class ThreatAsset(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset_id: str
    name: str
    files: list[str] = Field(default_factory=list)
    expected_control: str = ""


class ThreatBoundary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    boundary_id: str
    name: str
    files: list[str] = Field(default_factory=list)
    expected_control: str = ""


class ThreatEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    file: str


class ThreatLink(BaseModel):
    model_config = ConfigDict(extra="ignore")

    case_id: str
    asset_id: str
    file: str


class ThreatModel(BaseModel):
    """Citations a person can check. Status in this file is always draft."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    repo_name: str
    status: str = "draft"
    source: str = "detect"
    generated_at: str
    assets: list[ThreatAsset] = Field(default_factory=list)
    boundaries: list[ThreatBoundary] = Field(default_factory=list)
    entry_points: list[ThreatEntry] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    links: list[ThreatLink] = Field(default_factory=list)

    def cited_files(self) -> set[str]:
        files: set[str] = set()
        for asset in self.assets:
            files.update(asset.files)
        for boundary in self.boundaries:
            files.update(boundary.files)
        for entry in self.entry_points:
            files.add(entry.file)
        return {item.replace("\\", "/") for item in files if item}

    def note_for(self, finding: Finding) -> str:
        asset = next((item for item in self.assets if finding.file in item.files), None)
        if asset is None:
            return "Not named by the threat model."
        boundary = next((item for item in self.boundaries if finding.file in item.files), None)
        if boundary is None:
            return f"Asset: {asset.name}."
        return f"Asset: {asset.name}. Boundary: {boundary.name}."


def model_path(repo: Path) -> Path:
    return repo / _DIRNAME / MODEL_FILENAME


def html_path(repo: Path) -> Path:
    return repo / _DIRNAME / HTML_FILENAME


def draft_from_findings(
    repo_name: str,
    findings: list[Finding],
    generated_at: str,
    *,
    source: str = "detect",
) -> ThreatModel:
    """Build a draft from findings already on disk. Makes no model call."""

    grouped: dict[str, list[Finding]] = {}
    labels: dict[str, tuple[str, str]] = {}
    for finding in findings:
        asset_id, name, control = _group_for(finding)
        grouped.setdefault(asset_id, []).append(finding)
        labels[asset_id] = (name, control)
    assets: list[ThreatAsset] = []
    boundaries: list[ThreatBoundary] = []
    entries: list[ThreatEntry] = []
    links: list[ThreatLink] = []
    seen_entries: set[str] = set()
    for asset_id, rows in grouped.items():
        name, control = labels[asset_id]
        files = sorted({row.file for row in rows})
        assets.append(
            ThreatAsset(asset_id=asset_id, name=name, files=files, expected_control=control)
        )
        boundaries.append(
            ThreatBoundary(
                boundary_id=asset_id,
                name=f"{name} boundary",
                files=files,
                expected_control=control,
            )
        )
        for path in files:
            if path not in seen_entries:
                seen_entries.add(path)
                entries.append(ThreatEntry(name=path.rsplit("/", 1)[-1], file=path))
        for row in rows:
            if row.case_id:
                links.append(ThreatLink(case_id=row.case_id, asset_id=asset_id, file=row.file))
    return ThreatModel(
        repo_name=repo_name,
        status="draft",
        source=source,
        generated_at=generated_at,
        assets=assets,
        boundaries=boundaries,
        entry_points=entries,
        links=links,
    )


def save_model(repo: Path, model: ThreatModel) -> Path:
    """Write the draft JSON and HTML inside the repository report directory."""

    root = repo.resolve()
    directory = root / _DIRNAME
    if is_reparse_point(directory) or (directory.exists() and not directory.is_dir()):
        raise UsageError("report directory must be a real directory inside the repository")
    directory.mkdir(parents=True, exist_ok=True)
    if is_reparse_point(directory) or not is_within(root, directory):
        raise UsageError("report directory must be a real directory inside the repository")
    stored = model.model_copy(update={"status": "draft"})
    payload = json.dumps(stored.model_dump(mode="json"), indent=2) + "\n"
    path = directory / MODEL_FILENAME
    path.write_text(payload, encoding="utf-8", newline="\n")
    (directory / HTML_FILENAME).write_text(render_html(stored), encoding="utf-8", newline="\n")
    return path


def load_model(repo: Path) -> ThreatModel | None:
    """Load a draft. A status value inside the file is ignored."""

    path = model_path(repo)
    if not path.is_file() or is_reparse_point(path):
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    data["status"] = "draft"
    try:
        return ThreatModel.model_validate(data)
    except ValueError:
        return None


def canonical_bytes(model: ThreatModel) -> bytes:
    stored = model.model_copy(update={"status": "draft"})
    return json.dumps(stored.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()


def model_hash(model: ThreatModel) -> str:
    return hashlib.sha256(canonical_bytes(model)).hexdigest()


def acceptance_path(state_dir: Path, repo: Path) -> Path:
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir / "acceptances" / f"{digest}.json"


def accept_model(repo: Path, state_dir: Path, model: ThreatModel) -> str:
    """Record the draft hash outside the repository."""

    if is_within(repo.resolve(), state_dir.resolve()):
        raise UsageError("state directory must be outside the repository")
    digest = model_hash(model)
    path = acceptance_path(state_dir, repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "repo": str(repo.resolve()),
        "model_sha256": digest,
        "model_file": MODEL_FILENAME,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return digest


def threat_status(repo: Path, state_dir: Path, scope_files: set[str] | None) -> tuple[ThreatModel | None, str]:
    """Return the draft and none, draft, accepted, or stale."""

    model = load_model(repo)
    if model is None:
        return None, "none"
    path = acceptance_path(state_dir, repo)
    if not path.is_file():
        return model, "draft"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return model, "draft"
    if not isinstance(record, dict) or record.get("model_sha256") != model_hash(model):
        return model, "stale"
    if scope_files is not None:
        missing = [item for item in model.cited_files() if item not in scope_files]
        if missing:
            return model, "stale"
    return model, "accepted"


def apply_threat(
    findings: list[Finding],
    model: ThreatModel | None,
    status: str,
) -> list[Finding]:
    """Reorder only when the model is accepted. Every finding stays."""

    if model is None or status != "accepted":
        return findings
    cited = model.cited_files()
    ordered = sorted(findings, key=lambda finding: (0 if finding.file in cited else 1))
    return [
        finding.model_copy(update={"threat_note": model.note_for(finding)})
        for finding in ordered
    ]


def priority_bands(repo: Path, state_dir: Path, scope) -> dict[str, int]:
    """Files an accepted model wants read first, then files that already have a gap."""

    scope_files = {item.path for item in scope.files}
    model, status = threat_status(repo, state_dir, scope_files)
    if model is None or status != "accepted":
        return {}
    from silentblue.detectors import detect

    detected, _dropped = detect(repo, scope)
    bands = {path: 0 for path in model.cited_files()}
    for finding in detected:
        bands.setdefault(finding.file, 1)
    return bands


def render_text(model: ThreatModel, status: str) -> str:
    """Terminal view of the draft or its acceptance state."""

    lines = [
        f"Threat model for {model.repo_name}",
        f"State: {status}",
        f"Source: {model.source}",
        f"Assets: {len(model.assets)}",
        f"Boundaries: {len(model.boundaries)}",
        f"Entry points: {len(model.entry_points)}",
    ]
    for asset in model.assets:
        files = ", ".join(asset.files) or "none"
        lines.append(f"Asset: {asset.name}")
        lines.append(f"  Files: {files}")
        lines.append(f"  Expected control: {asset.expected_control}")
    for boundary in model.boundaries:
        lines.append(f"Boundary: {boundary.name}")
    if model.assumptions:
        lines.append("Assumptions:")
        lines.extend(f"  - {item}" for item in model.assumptions)
    else:
        lines.append("Assumptions: none")
    linked = {link.case_id for link in model.links}
    if linked:
        lines.append(f"Linked findings: {len(linked)}")
    return "\n".join(lines)


def render_html(model: ThreatModel) -> str:
    """One HTML file for the draft. It loads nothing from the network."""

    assets = []
    for asset in model.assets:
        files = ", ".join(escape(path) for path in asset.files) or "none"
        assets.append(
            "<article>"
            f"<h2>{escape(asset.name)}</h2>"
            f"<p>Files: {files}</p>"
            f"<p>Expected control: {escape(asset.expected_control)}</p>"
            "</article>"
        )
    body = "\n".join(assets) or "<p>No assets named.</p>"
    assumptions = "".join(f"<li>{escape(item)}</li>" for item in model.assumptions) or "<li>None yet.</li>"
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>Threat model {escape(model.repo_name)}</title>"
        "<style>body{font:16px/1.45 sans-serif;margin:2rem auto;max-width:48rem}"
        "article{border:1px solid #e7e5e4;padding:1rem;margin:1rem 0}</style></head><body>"
        f"<h1>Threat model · {escape(model.repo_name)}</h1>"
        "<p>This file is a draft until you accept it from the session. "
        "Acceptance is stored outside the repository.</p>"
        f"{body}<h2>Assumptions</h2><ul>{assumptions}</ul></body></html>\n"
    )


def _group_for(finding: Finding) -> tuple[str, str, str]:
    for asset_id, name, rules, control in _GROUPS:
        if finding.rule_id in rules:
            return asset_id, name, control
    family = finding.control_family or "unspecified"
    return (
        family,
        family.replace("-", " ").title(),
        finding.remediation or "Review the cited file and add the missing control.",
    )
