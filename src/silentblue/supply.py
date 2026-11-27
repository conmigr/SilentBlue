"""Dependency pins, install trust, and an opt-in OSV query.

Pin, install, and CA-bundle checks read the tree and send nothing.
The OSV query runs only when a scan asks for it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import re
import ssl
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from silentblue.models import ComponentDetail, FinalReport, Finding, RunState, ScopeResult
from silentblue.paths import is_reparse_point, is_within
from silentblue.redact import redact
from silentblue.repair import choose_fixed, upgrade_remediation

KEPT_NOTE = "Kept from the last OSV query. Resolved packages are unchanged."
CHANGED_NOTE = "OSV rows were not kept. The resolved packages changed. Type /scan osv."
UNRECORDED_NOTE = "OSV rows were not kept. The last query did not record the package set. Type /scan osv."

_DEFAULT_OSV_URL = "https://api.osv.dev/v1/querybatch"


def system_ca_note() -> str:
    """Tell the operator how to give this Python a CA store. No network."""

    base = (
        f"No CA certificates are visible to {sys.executable}, so OSV cannot be contacted."
        " Certificates installed for a different Python are not used."
        " Quit this session and start it again after fixing this Python."
    )
    if sys.platform == "darwin":
        return (
            base
            + " On a Mac, open Applications, open the Python folder for this same Python,"
            + " and double-click Install Certificates.command."
            + " Leave SILENTBLUE_CA_BUNDLE unset."
        )
    if sys.platform == "win32":
        return (
            base
            + " Install Python from python.org and install Windows root certificate updates."
            + " Quit Silent Blue and start it again. Leave SILENTBLUE_CA_BUNDLE unset."
        )
    return (
        base
        + " Install this operating system's CA certificates for Python."
        + " Silent Blue also uses certifi for this same Python when that file sits outside the repository."
        + " Quit Silent Blue and start it again. Leave SILENTBLUE_CA_BUNDLE unset."
    )


_CA_FILE = (
    "SILENTBLUE_CA_BUNDLE is not a readable CA file. "
    "Set it to a certificate bundle outside the repository."
)
_CA_INSIDE = (
    "SILENTBLUE_CA_BUNDLE points inside the repository. "
    "Move the CA file outside the repository and update .env."
)
_CA_INVALID = (
    "SILENTBLUE_CA_BUNDLE could not be loaded as a CA bundle. "
    "Use a PEM bundle of CA certificates that sits outside the repository."
)
_BATCH = 1000
_TIMEOUT_S = 20
_MAX_BODY = 2_000_000

_REQ_LINE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\]]*\])?"
    r"\s*(.*)$"
)
_EXACT_PYTHON = re.compile(r"(?:===|==)\s*([A-Za-z0-9*][A-Za-z0-9.*+!_-]*)\s*$")
_NPM_EXACT = re.compile(r"^(?:=|v)?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_POETRY_EXACT = re.compile(r"(?:===|==)\s*([A-Za-z0-9*][A-Za-z0-9.*+!_-]*)\s*$")
_LOCK_NAME = re.compile(r'(?m)^name\s*=\s*"([^"]+)"')
_TRUSTED = re.compile(r"(?i)--trusted-host\b")
_NPM_SSL = re.compile(r"(?i)strict-ssl\s*=\s*false")
_NODE_TLS = re.compile(r"(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0\b")
_CURL_K = re.compile(r"(?i)\bcurl\b[^\n]*(?:\s-k\b|\s--insecure\b)")
_WGET = re.compile(r"(?i)\bwget\b[^\n]*--no-check-certificate\b")
_CA_ASSIGN = re.compile(
    r"(?i)\b(?:SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|NODE_EXTRA_CA_CERTS)"
    r"\s*[:=]\s*['\"]?([^'\"\s#]+)"
)
_PIP_CERT = re.compile(r"(?i)^\s*cert\s*=\s*(\S+)")
_NPM_CAFILE = re.compile(r"(?i)^\s*cafile\s*=\s*(\S+)")

_INSTALL_REPAIR = (
    "Delete the installer setting that turns certificate verification off. "
    "Fetch the package over https and leave the default trust store in place."
)
_CA_REPAIR = (
    "Point the install config at a CA bundle file that exists in the repository, "
    "or delete the relative path and use the system trust store."
)
_PIN_REPAIR = (
    "Replace the version range with an exact version, commit the lockfile, and fetch over https. "
    "Delete cleartext http:// URLs and --trusted-host."
)
_OSV_FAMILY = "supply-chain"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass(frozen=True)
class _Package:
    ecosystem: str
    name: str
    version: str
    file: str
    line: int
    text: str
    exact: bool
    direct: bool | None = None


def offline_findings(repo: Path, scope: ScopeResult) -> list[Finding]:
    """Return pin, install-verification, and CA-bundle findings. No network."""

    root = repo.resolve()
    findings: list[Finding] = []
    for item in scope.files:
        path = root / item.path
        if not is_within(root, path) or is_reparse_point(path):
            continue
        text = _read(path)
        if text is None:
            continue
        findings.extend(_pin_findings(root, item.path, text))
        findings.extend(_install_findings(root, item.path, text))
    return findings


def apply_advisories(state: RunState, *, fetch=None) -> RunState:
    """Append one finding per OSV id for pinned PyPI and npm packages."""

    if state.scope is None:
        return state
    root = Path(state.repo)
    ready, note = load_ca(root)
    if not ready:
        return state.model_copy(
            update={
                "advisories": "degraded",
                "advisory_note": note,
            }
        )
    url, _host, _source, url_note = osv_endpoint()
    if url_note:
        return state.model_copy(
            update={
                "advisories": "degraded",
                "advisory_note": url_note,
            }
        )
    packages = _advisory_packages(root, state.scope)
    fingerprint = fingerprint_packages(packages)
    if not packages:
        return state.model_copy(
            update={
                "advisories": "queried",
                "advisory_note": "No resolved or pinned packages were declared.",
                "advisory_fingerprint": fingerprint,
            }
        )
    context = _ssl_context(root)
    if context is None:
        return state.model_copy(
            update={
                "advisories": "degraded",
                "advisory_note": "CA bundle could not be loaded.",
            }
        )
    caller = fetch or _default_fetch
    try:
        documents = _batches(packages, caller, context)
    except (OSError, TimeoutError, json.JSONDecodeError, UnicodeError, ValueError):
        return state.model_copy(
            update={
                "advisories": "degraded",
                "advisory_note": (
                    f"OSV could not be reached at {url}. "
                    "Check that this machine can open that HTTPS address. "
                    "Certificate verification stays on. The query waits 20 seconds."
                ),
            }
        )
    findings = list(state.findings)
    for package, document in documents:
        findings.extend(_findings_for(package, document))
    return state.model_copy(
        update={
            "findings": findings,
            "advisories": "queried",
            "advisory_note": "",
            "advisory_fingerprint": fingerprint,
        }
    )


def fingerprint_packages(packages: list[_Package]) -> str:
    """Hash the resolved name and version list. File and line are not part of it."""

    lines = []
    for package in packages:
        name = package.name.lower() if package.ecosystem in {"PyPI", "NuGet"} else package.name
        lines.append(f"{package.ecosystem}\t{name}\t{package.version}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def retain_advisories(state: RunState, previous: FinalReport) -> tuple[RunState, str]:
    """Copy advisory rows when the resolved packages still match the last query."""

    if previous.advisories != "queried" or state.scope is None:
        return state, ""
    if not previous.advisory_fingerprint:
        return state, UNRECORDED_NOTE
    current = fingerprint_packages(_advisory_packages(Path(state.repo), state.scope))
    if current != previous.advisory_fingerprint:
        return state, CHANGED_NOTE
    seen = {finding.case_id for finding in state.findings if finding.case_id}
    carried = []
    for finding in previous.findings:
        if finding.rule_id != "dependency-vulnerable" or finding.case_id in seen:
            continue
        carried.append(finding.model_copy(update={"number": 0, "threat_note": ""}))
        seen.add(finding.case_id)
    return (
        state.model_copy(
            update={
                "findings": [*state.findings, *carried],
                "advisories": "queried",
                "advisory_note": KEPT_NOTE,
                "advisory_fingerprint": current,
            }
        ),
        KEPT_NOTE,
    )


def preview_advisories(repo: Path) -> str:
    """Describe the OSV query without sending it."""

    from silentblue.models import ScopeConfig
    from silentblue.scope import collect_scope

    root = repo.expanduser().resolve()
    scope = collect_scope(root, ScopeConfig(), extra_exclude_dirs={"security-scan"})
    pinned = _advisory_packages(root, scope)
    ready, ca_note = load_ca(root)
    url, _host, source, url_note = osv_endpoint()
    lines = [
        f"OSV URL: {url or 'missing'}",
        f"OSV source: {source}",
        f"Packages: {len(pinned)}",
        f"CA bundle: {'ok' if ready else 'missing'}",
    ]
    if url_note:
        lines.append(url_note)
    if not ready:
        lines.append(ca_note)
        lines.append("The advisory check will not complete until the CA bundle loads.")
    elif not pinned:
        lines.append(
            "No resolved or pinned packages were found. A version range is sent only when a lockfile resolves it."
        )
    return "\n".join(lines)


def ca_bundle_label(repo: Path | None) -> str:
    """Return ``ok`` or ``missing`` for setup and doctor. No network."""

    ready, _note = load_ca(repo)
    return "ok" if ready else "missing"


def load_ca(repo: Path | None) -> tuple[bool, str]:
    """Return whether a CA bundle can be loaded for an advisory query."""

    context, note = ca_context(repo)
    return context is not None, "ok" if context is not None else note


def ca_context(repo: Path | None) -> tuple[ssl.SSLContext | None, str]:
    """Return a verifying context for this Python, or the reason none is available."""

    override = os.environ.get("SILENTBLUE_CA_BUNDLE", "").strip()
    if override:
        path = Path(override).expanduser()
        if is_reparse_point(path) or not path.is_file():
            return None, _CA_FILE
        if not _outside_repo(repo, path):
            return None, _CA_INSIDE
        context = _context_from(path)
        return (context, "ok") if context is not None else (None, _CA_INVALID)
    try:
        context = ssl.create_default_context()
    except (OSError, ssl.SSLError):
        context = None
    if _usable(context):
        return context, "ok"
    certifi_path = _certifi_bundle(repo)
    if certifi_path is not None:
        context = _context_from(certifi_path)
        if context is not None:
            return context, "ok"
    return None, system_ca_note()


def _context_from(path: Path) -> ssl.SSLContext | None:
    try:
        context = ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError):
        return None
    return context if _usable(context) else None


def _usable(context: ssl.SSLContext | None) -> bool:
    if context is None:
        return False
    try:
        count = context.cert_store_stats().get("x509_ca", 0)
    except (AttributeError, OSError, ssl.SSLError):
        return False
    return context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname and count > 0


def _certifi_bundle(repo: Path | None) -> Path | None:
    """Use certifi when this Python's default store is empty and the file is outside the repo."""

    try:
        import certifi
    except ImportError:
        return None
    path = Path(str(certifi.where())).expanduser()
    if is_reparse_point(path) or not path.is_file() or not _outside_repo(repo, path):
        return None
    return path


def _outside_repo(repo: Path | None, path: Path) -> bool:
    if repo is None:
        return True
    try:
        return not is_within(repo.resolve(), path.resolve())
    except OSError:
        return False


def osv_endpoint() -> tuple[str, str, str, str]:
    """Return the query URL, its host, where it came from, and an error note."""

    configured = os.environ.get("SILENTBLUE_OSV_URL", "").strip()
    raw = configured or _DEFAULT_OSV_URL
    source = (
        "SILENTBLUE_OSV_URL"
        if configured
        else "default. Set SILENTBLUE_OSV_URL in .env to change this endpoint."
    )
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        return (
            "",
            "",
            source,
            "SILENTBLUE_OSV_URL must be an https URL. "
            f"The public endpoint is {_DEFAULT_OSV_URL}.",
        )
    return raw, host, source, ""


_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_HIGH_CHANGE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_HIGH_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
_MEDIUM_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_MEDIUM_UI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

_BY_SEVERITY: dict[str, tuple[float, str]] = {
    "critical": (9.8, _CRITICAL),
    "high": (7.5, _HIGH_READ),
    "medium": (5.3, _MEDIUM_READ),
    "low": (3.1, _LOW),
    "info": (0.0, _INFO),
}
_BY_RULE: dict[str, tuple[float, str]] = {
    "sql-unparameterized": (8.8, _HIGH_CHANGE),
    "nosql-unparameterized": (8.8, _HIGH_CHANGE),
    "ldap-filter-assembled": (8.8, _HIGH_CHANGE),
    "template-from-string": (8.8, _HIGH_CHANGE),
    "dynamic-eval": (8.8, _HIGH_CHANGE),
    "shell-command": (8.8, _HIGH_CHANGE),
    "unsafe-deserialization": (8.8, _HIGH_CHANGE),
    "jwt-verify-disabled": (8.8, _HIGH_CHANGE),
    "piped-download": (8.8, _HIGH_CHANGE),
    "request-url-from-input": (8.8, _HIGH_CHANGE),
    "hardcoded-secret": (7.5, _HIGH_READ),
    "default-credential": (7.5, _HIGH_READ),
    "weak-password-hash": (7.5, _HIGH_READ),
    "token-in-web-storage": (7.5, _HIGH_READ),
    "path-from-request": (7.5, _HIGH_READ),
    "html-parsed-from-string": (6.1, _MEDIUM_UI),
    "redirect-from-request": (6.1, _MEDIUM_UI),
    "header-from-request": (6.1, _MEDIUM_UI),
    "cors-wildcard": (6.1, _MEDIUM_UI),
}


def cvss_for(rule_id: str, severity: str) -> tuple[float, str]:
    """Return a CVSS v3.1 score and vector for a control-gap rule."""

    chosen = _BY_RULE.get(rule_id) or _BY_SEVERITY.get(severity) or _BY_SEVERITY["medium"]
    return chosen


def cvss_v3_score(vector: str) -> float | None:
    """Return the CVSS v3 base score for a vector, or None when it is incomplete."""

    body = vector.split("/", 1)[1] if "/" in vector else vector
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    needed = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in metrics for key in needed):
        return None
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if changed:
        raw = min(1.08 * (impact + exploitability), 10)
    else:
        raw = min(impact + exploitability, 10)
    return _roundup(raw)


def _roundup(value: float) -> float:
    """CVSS roundup: the next tenth, and an exact tenth stays put."""

    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def _advisory_packages(repo: Path, scope: ScopeResult) -> list[_Package]:
    """Versions to send to OSV. A lockfile replaces manifest pins in that directory."""

    from silentblue.locks import resolved_packages

    resolved = resolved_packages(repo)
    covered = {(_directory(item.file), item.ecosystem) for item in resolved}
    packages = [
        _Package(
            item.ecosystem,
            item.name,
            item.version,
            item.file,
            item.line,
            item.text,
            True,
            item.direct,
        )
        for item in resolved
        if item.version
    ]
    for item in _declarations(repo, scope):
        if not item.exact or not item.version:
            continue
        if (_directory(item.file), item.ecosystem) in covered:
            continue
        packages.append(
            _Package(
                item.ecosystem,
                item.name,
                item.version,
                item.file,
                item.line,
                item.text,
                True,
                True,
            )
        )
    return _dedupe_packages(packages)


def _dedupe_packages(packages: list[_Package]) -> list[_Package]:
    chosen: dict[tuple[str, str, str], _Package] = {}
    for package in packages:
        name = package.name.lower() if package.ecosystem in {"PyPI", "NuGet"} else package.name
        key = (package.ecosystem, name, package.version)
        current = chosen.get(key)
        if current is None or _direct_rank(package.direct) > _direct_rank(current.direct):
            chosen[key] = package
    return sorted(chosen.values(), key=lambda item: (item.file, item.line, item.name, item.version))


def _direct_rank(value: bool | None) -> int:
    if value is True:
        return 2
    if value is False:
        return 1
    return 0


def _directory(relative: str) -> str:
    relative = relative.replace("\\", "/")
    if "/" not in relative:
        return ""
    return relative.rsplit("/", 1)[0]


def _declarations(repo: Path, scope: ScopeResult) -> list[_Package]:
    root = repo.resolve()
    found: list[_Package] = []
    for item in scope.files:
        path = root / item.path
        if not is_within(root, path) or is_reparse_point(path):
            continue
        text = _read(path)
        if text is None:
            continue
        found.extend(_packages(root, item.path, text))
    return found


def _packages(repo: Path, relative: str, text: str) -> list[_Package]:
    name = _basename(relative)
    if name.startswith("requirements") or name == "constraints.txt":
        return _requirement_packages(repo, relative, text)
    if name == "package.json":
        return _npm_packages(repo, relative, text)
    if name == "pyproject.toml":
        return _pyproject_packages(repo, relative, text)
    if name == "pipfile":
        return _pipfile_packages(repo, relative, text)
    return []


def _pin_findings(repo: Path, relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for package in _packages(repo, relative, text):
        if package.exact or _has_upper_bound(package.version):
            continue
        if _locked(repo, relative, package):
            continue
        findings.append(
            _gap(
                package.file,
                package.line,
                package.text,
                "dependency-unpinned",
                "medium",
                "Dependency version is unpinned",
                "A manifest accepts a range, a wildcard, or no version.",
                _PIN_REPAIR,
                0.8,
            )
        )
    return findings


def _install_findings(repo: Path, relative: str, text: str) -> list[Finding]:
    if not _install_file(relative):
        return []
    findings: list[Finding] = []
    name = _basename(relative)
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _TRUSTED.search(line) or _NPM_SSL.search(line) or _NODE_TLS.search(line) or _CURL_K.search(line) or _WGET.search(line):
            findings.append(
                _gap(
                    relative,
                    number,
                    line,
                    "install-verification-disabled",
                    "medium",
                    "Install turns certificate verification off",
                    "An install fetches a package with verification disabled.",
                    _INSTALL_REPAIR,
                    0.85,
                )
            )
        for match in _CA_ASSIGN.finditer(line):
            if _missing_bundle(repo, relative, match.group(1)):
                findings.append(_ca_gap(relative, number, line))
        if name in {"pip.conf", "pip.ini"}:
            cert = _PIP_CERT.search(stripped)
            if cert and _missing_bundle(repo, relative, cert.group(1)):
                findings.append(_ca_gap(relative, number, line))
        if name == ".npmrc":
            cafile = _NPM_CAFILE.search(stripped)
            if cafile and _missing_bundle(repo, relative, cafile.group(1)):
                findings.append(_ca_gap(relative, number, line))
    return findings


def _requirement_packages(repo: Path, relative: str, text: str) -> list[_Package]:
    packages: list[_Package] = []
    for number, line in enumerate(text.splitlines(), start=1):
        parsed = _parse_requirement(line)
        if parsed is None:
            continue
        name, version, exact = parsed
        packages.append(_Package("PyPI", name, version, relative, number, line, exact))
    return packages


def _parse_requirement(line: str) -> tuple[str, str, bool] | None:
    body = line.split("#", 1)[0].strip()
    if not body or body.startswith("-"):
        return None
    body = body.split(";", 1)[0].strip()
    if " @ " in body:
        name = body.split(" @ ", 1)[0].split("[", 1)[0].strip()
        if not name:
            return None
        return name, "", False
    match = _REQ_LINE.match(body)
    if match is None:
        return None
    name, spec = match.group(1), match.group(2).strip()
    if not spec:
        return name, "", False
    if "," in spec:
        return name, spec, False
    exact = _EXACT_PYTHON.fullmatch(spec)
    if exact is None or "*" in exact.group(1):
        return name, spec, False
    return name, exact.group(1), True


def _npm_packages(repo: Path, relative: str, text: str) -> list[_Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    packages: list[_Package] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            version = spec.strip()
            exact = _NPM_EXACT.fullmatch(version) is not None
            pinned_version = version[1:] if exact and version.startswith("=") else version
            if exact and pinned_version.startswith("v") and pinned_version[1:2].isdigit():
                pinned_version = pinned_version[1:]
            line_no, line = _line_containing(text, name)
            packages.append(
                _Package(
                    "npm",
                    name,
                    pinned_version if exact else version,
                    relative,
                    line_no,
                    line,
                    exact,
                )
            )
    return packages


def _pyproject_packages(repo: Path, relative: str, text: str) -> list[_Package]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    packages: list[_Package] = []
    project = data.get("project")
    if isinstance(project, dict):
        deps = list(project.get("dependencies") or [])
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    deps.extend(values)
        for item in deps:
            if not isinstance(item, str):
                continue
            parsed = _parse_requirement(item)
            if parsed is None:
                continue
            name, version, exact = parsed
            line_no, line = _line_containing(text, name)
            packages.append(_Package("PyPI", name, version, relative, line_no, line, exact))
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        packages.extend(_poetry_table(relative, text, poetry.get("dependencies")))
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict):
                    packages.extend(_poetry_table(relative, text, group.get("dependencies")))
    return packages


def _poetry_table(relative: str, text: str, table: object) -> list[_Package]:
    if not isinstance(table, dict):
        return []
    packages: list[_Package] = []
    for name, value in table.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        spec = ""
        if isinstance(value, str):
            spec = value.strip()
        elif isinstance(value, dict):
            raw = value.get("version")
            spec = raw.strip() if isinstance(raw, str) else ""
        if not spec:
            continue
        exact_match = _POETRY_EXACT.fullmatch(spec)
        exact = exact_match is not None and "*" not in exact_match.group(1)
        version = exact_match.group(1) if exact and exact_match is not None else spec
        line_no, line = _line_containing(text, name)
        packages.append(_Package("PyPI", name, version, relative, line_no, line, exact))
    return packages


def _pipfile_packages(repo: Path, relative: str, text: str) -> list[_Package]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    packages: list[_Package] = []
    for section in ("packages", "dev-packages"):
        packages.extend(_poetry_table(relative, text, data.get(section)))
    return packages


def _locked(repo: Path, relative: str, package: _Package) -> bool:
    directory = (repo / relative).parent
    names = _lock_names(repo, directory, package.ecosystem)
    if package.ecosystem == "PyPI":
        return package.name.lower() in names
    return package.name in names


def _lock_names(repo: Path, directory: Path, ecosystem: str) -> set[str]:
    names: set[str] = set()
    if ecosystem == "npm":
        files = ("package-lock.json",)
    else:
        files = ("poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock")
    for filename in files:
        path = directory / filename
        if not path.is_file() or is_reparse_point(path) or not is_within(repo, path):
            continue
        text = _read(path)
        if text is None:
            continue
        if filename == "package-lock.json":
            names.update(_npm_lock_names(text))
        elif filename == "Pipfile.lock":
            names.update(name.lower() for name in _pipfile_lock_names(text))
        else:
            names.update(name.lower() for name in _LOCK_NAME.findall(text))
    return names


def _has_upper_bound(spec: str) -> bool:
    """True when the specifier cannot float upward forever."""

    text = spec.strip()
    if not text or text in {"*", "latest"}:
        return False
    if "~=" in text:
        return True
    if re.search(r"(?:^|[\s,])<[>=]?\s*\d", text):
        return True
    if re.search(r"(?:^|[\s,])[\^~]\d", text):
        return True
    if re.search(r"\d\.(?:x|\*)\b", text):
        return True
    return False


def _npm_lock_names(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, value in packages.items():
            if not isinstance(key, str) or not isinstance(value, dict) or not value.get("version"):
                continue
            parts = key.split("node_modules/")
            if len(parts) < 2 or not parts[-1]:
                continue
            names.add(parts[-1])
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, value in deps.items():
            if isinstance(name, str) and isinstance(value, dict) and value.get("version"):
                names.add(name)
    return names


def _pipfile_lock_names(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    for section in ("default", "develop"):
        block = data.get(section)
        if isinstance(block, dict):
            names.update(name for name in block if isinstance(name, str))
    return names


def _install_file(relative: str) -> bool:
    name = _basename(relative)
    portable = relative.replace("\\", "/")
    if name.startswith("requirements") or name in {
        "constraints.txt",
        "pipfile",
        "pip.conf",
        "pip.ini",
        ".npmrc",
        "dockerfile",
        "containerfile",
    }:
        return True
    if name.endswith(".dockerfile"):
        return True
    return "/.github/workflows/" in f"/{portable}"


def _missing_bundle(repo: Path, relative: str, value: str) -> bool:
    raw = value.strip().strip("'\"")
    if not raw or raw.startswith(("$", "%", "~", "/", "\\")) or "://" in raw:
        return False
    candidate = Path(raw)
    if candidate.is_absolute():
        return False
    root = repo.resolve()
    file_path = root / relative
    for item in (file_path.parent / candidate, root / candidate):
        try:
            if item.is_file() and is_within(root, item) and not is_reparse_point(item):
                return False
        except OSError:
            continue
    return True


def _batches(packages: list[_Package], fetch, context: ssl.SSLContext) -> list[tuple[_Package, dict]]:
    paired: list[tuple[_Package, dict]] = []
    for start in range(0, len(packages), _BATCH):
        chunk = packages[start : start + _BATCH]
        payload = {
            "queries": [
                {
                    "package": {"name": item.name, "ecosystem": item.ecosystem},
                    "version": item.version,
                }
                for item in chunk
            ]
        }
        data = fetch(payload, context)
        if not isinstance(data, dict):
            raise ValueError("OSV returned a response that is not a document")
        results = data.get("results")
        if not isinstance(results, list):
            raise ValueError("OSV returned a response that is not a document")
        for package, result in zip(chunk, results, strict=False):
            paired.append((package, result if isinstance(result, dict) else {}))
    return paired


def _findings_for(package: _Package, result: dict) -> list[Finding]:
    vulns = result.get("vulns") or []
    if not isinstance(vulns, list):
        return []
    findings: list[Finding] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        advisory_id = str(vuln.get("id") or "").strip()
        if not advisory_id:
            continue
        score, vector, version = _best_cvss(vuln)
        severity, confidence = _rank(score)
        summary = str(vuln.get("summary") or "An advisory names this version.").strip()
        if len(summary) > 400:
            summary = summary[:400]
        aliases = [str(item) for item in (vuln.get("aliases") or []) if isinstance(item, str)]
        alias_text = f" Aliases: {', '.join(aliases[:6])}." if aliases else ""
        relationship = {True: "direct", False: "transitive"}.get(package.direct, "")
        relation = {"direct": " Direct dependency.", "transitive": " Transitive dependency."}.get(
            relationship, ""
        )
        fixes = _fixed_versions(vuln, package)
        fixed, reason = choose_fixed(package.version, fixes)
        component = ComponentDetail(
            ecosystem=package.ecosystem,
            name=package.name,
            version=package.version,
            purl=_purl(package),
            fixed_version=fixed,
            relationship=relationship,  # type: ignore[arg-type]
        )
        remediation = upgrade_remediation(
            ecosystem=package.ecosystem,
            name=package.name,
            version=package.version,
            file=package.file,
            line=package.line,
            advisory_id=advisory_id,
            fixed=fixed,
            reason=reason,
            fixes=fixes,
            direct=package.direct,
        )
        findings.append(
            Finding(
                rule_id="dependency-vulnerable",
                control_family=_OSV_FAMILY,
                severity=severity,  # type: ignore[arg-type]
                title=f"{package.name} {package.version} is named by {advisory_id}",
                file=package.file,
                line=package.line,
                description=(
                    f"{advisory_id} affects {package.ecosystem} package {package.name} "
                    f"{package.version}.{alias_text} {summary}{relation}"
                ),
                remediation=remediation,
                snippet=_snippet(package.text),
                confidence=confidence,
                cvss_score=score,
                cvss_vector=vector,
                cvss_version=version,
                advisory_id=advisory_id,
                component=component,
            )
        )
    return findings


def _best_cvss(vuln: dict) -> tuple[float | None, str, str]:
    best_score: float | None = None
    best_vector = ""
    best_version = ""
    entries = vuln.get("severity") or []
    if not isinstance(entries, list):
        return None, "", ""
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type") or "")
        if kind not in {"CVSS_V3", "CVSS_V4"}:
            continue
        raw = str(entry.get("score") or "").strip()
        if not raw:
            continue
        number: float | None = None
        vector = ""
        version = ""
        if raw.upper().startswith("CVSS:"):
            vector = raw
            version = raw.split("/", 1)[0].split(":", 1)[1]
            if version.startswith("3"):
                number = cvss_v3_score(raw)
        else:
            try:
                number = float(raw)
            except ValueError:
                continue
            if not 0 <= number <= 10:
                continue
            version = "3.1" if kind == "CVSS_V3" else "4.0"
        if number is None and not vector:
            continue
        take = False
        if number is not None and (best_score is None or number > best_score):
            take = True
        elif number is not None and number == best_score and vector and not best_vector:
            take = True
        elif number is None and best_score is None and vector and not best_vector:
            take = True
        if not take:
            continue
        if number is not None:
            best_score = number
            best_vector = vector
            best_version = version
        else:
            best_vector = vector
            best_version = version
    return best_score, best_vector, best_version


def _rank(score: float | None) -> tuple[str, float]:
    if score is None:
        return "medium", 0.6
    if score >= 9:
        return "critical", 0.9
    if score >= 7:
        return "high", 0.9
    if score >= 4:
        return "medium", 0.9
    return "low", 0.9


def _fixed_versions(vuln: dict, package: _Package) -> list[str]:
    affected = vuln.get("affected") or []
    if not isinstance(affected, list):
        return []
    found: list[str] = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        named = item.get("package") or {}
        if not isinstance(named, dict):
            continue
        if str(named.get("name") or "").lower() != package.name.lower():
            continue
        ecosystem = str(named.get("ecosystem") or "")
        if ecosystem and ecosystem.lower() != package.ecosystem.lower():
            continue
        ranges = item.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events") or []
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict) or not event.get("fixed"):
                    continue
                text = str(event["fixed"]).strip()
                if text and text not in found:
                    found.append(text)
    return found


def _purl(package: _Package) -> str:
    version = package.version
    if package.ecosystem == "PyPI":
        return f"pkg:pypi/{package.name.lower()}@{version}"
    if package.ecosystem == "npm":
        if package.name.startswith("@") and "/" in package.name:
            scope, name = package.name[1:].split("/", 1)
            return f"pkg:npm/%40{scope}/{name}@{version}"
        return f"pkg:npm/{package.name}@{version}"
    if package.ecosystem == "Go":
        return f"pkg:golang/{package.name}@{version}"
    if package.ecosystem == "crates.io":
        return f"pkg:cargo/{package.name}@{version}"
    if package.ecosystem == "RubyGems":
        return f"pkg:gem/{package.name}@{version}"
    if package.ecosystem == "Packagist":
        return f"pkg:composer/{package.name}@{version}"
    if package.ecosystem == "Maven" and ":" in package.name:
        group, artifact = package.name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{version}"
    if package.ecosystem == "NuGet":
        return f"pkg:nuget/{package.name}@{version}"
    if package.ecosystem == "ConanCenter":
        return f"pkg:conan/{package.name}@{version}"
    return f"pkg:{package.ecosystem.lower()}/{package.name}@{version}"


def _default_fetch(payload: dict, context: ssl.SSLContext) -> dict:
    url, host, _source, note = osv_endpoint()
    if not url:
        raise OSError(note or "OSV URL is missing")
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _SameHost(),
    )
    try:
        with opener.open(request, timeout=_TIMEOUT_S) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if (final.hostname or "").lower() != host:
                raise OSError("redirect to another host")
            raw = response.read(_MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        raise OSError(f"OSV returned {exc.code}") from exc
    if len(raw) > _MAX_BODY:
        raise OSError("OSV response is too large")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("OSV returned a response that is not a document")
    return data


def _ssl_context(repo: Path) -> ssl.SSLContext | None:
    context, _note = ca_context(repo)
    return context


class _SameHost(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect whose host is not the host we requested."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        new = urllib.parse.urlsplit(newurl)
        old = urllib.parse.urlsplit(req.full_url)
        if (new.hostname or "").lower() != (old.hostname or "").lower():
            raise OSError("redirect to another host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ca_gap(relative: str, number: int, line: str) -> Finding:
    return _gap(
        relative,
        number,
        line,
        "ca-bundle-missing",
        "medium",
        "Install names a CA bundle that is not in the repository",
        "An install config sets a relative CA bundle path, and that file is not in the repository.",
        _CA_REPAIR,
        0.8,
    )


def _gap(
    path: str,
    number: int,
    line: str,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    confidence: float,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        control_family=_OSV_FAMILY,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        file=path,
        line=number,
        description=description,
        remediation=remediation,
        snippet=_snippet(line),
        confidence=confidence,
    )


def _snippet(line: str) -> str:
    snippet = redact(line.strip())
    if len(snippet) > 240:
        return snippet[:240]
    return snippet


def _line_containing(text: str, needle: str) -> tuple[int, str]:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number, line
    return 1, needle


def _basename(relative: str) -> str:
    return relative.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _read(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")
