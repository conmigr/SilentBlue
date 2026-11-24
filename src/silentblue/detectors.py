"""Deterministic control-gap detectors.

Each rule records a missing or weak control and a defensive repair note.
Detectors read only paths the scope walk already accepted.
"""

from __future__ import annotations

import re
from pathlib import Path

from silentblue.coverage import extra_findings
from silentblue.languages import language_findings
from silentblue.models import DroppedFinding, Finding, ScopeResult
from silentblue.supply import offline_findings
from silentblue.paths import is_within
from silentblue.redact import redact

_PLACEHOLDER = re.compile(
    r"(?i)^(changeme|password|secret|example|placeholder|todo|xxx+|your[-_].*|"
    r"<.*>|\$\{.*\}|\*+)$"
)
_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_GITHUB = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_ASSIGNED_SECRET = re.compile(
    r"""(?ix)
    \b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|
    auth[_-]?token|password|passwd)\b
    \s*[:=]\s*
    (['\"])([^'\"]{8,})\1
    """
)
_SQL = re.compile(
    r"(?is)(?:\bexecute\s*\(|\bquery\s*\(|\.query\s*\()[^)\n]*(?:f['\"]|`[^`\n]*\$\{|\+\s*|\.format\s*\(|%\s*[\(\w])"
)
_OS_SYSTEM = re.compile(r"(?is)\bos\.system\s*\(\s*(?:f['\"]|[^)\n]*\+)")
_SHELL_TRUE = re.compile(r"(?i)\bshell\s*=\s*True\b")
_ASSEMBLED = re.compile(r"""f['\"]|\+\s*|\.format\s*\(""")
_EVAL = re.compile(r"(?i)\b(?:eval|exec)\s*\(")
_EXTERNAL = re.compile(r"(?i)\b(?:request|input|argv|params|form|query|body)\b")
_TLS = re.compile(
    r"(?i)\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
)
_NODE_EXEC = re.compile(r"(?i)\bexecSync\s*\(|\bchild_process\s*\.\s*exec(?:Sync)?\s*\(")
_HTML_ASSIGN = re.compile(r"(?i)\.innerHTML\s*=")
_HTML_WRITE = re.compile(r"(?i)\b(?:document\.write|insertAdjacentHTML)\s*\(")
_PLAIN_HTML = re.compile(r"""(?is)(?:document\.write|insertAdjacentHTML)\s*\(\s*['\"][^'\"]*['\"]\s*\)""")
_PLAIN_ASSIGN = re.compile(r"""(?is)^['\"][^'\"]*['\"]\s*;?$""")
_WEB_STORAGE = re.compile(
    r"(?i)\b(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem)\s*\("
)
_STORED_SECRET = re.compile(
    r"(?i)auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"\bjwts?\b|\btokens?\b|password|passwd|\bsecret\b|credential|api[_-]?key|apikey"
)
_CONSOLE = re.compile(r"(?i)\bconsole\.(?:log|debug|info|warn|error|trace)\s*\(")
_CRED_IDENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\w$#.]*(?:tokens|token|passwords|password|passwd|secrets|secret|credentials|credential|apikey|api_key)(?![A-Za-z0-9_])"
)
_BOOL_CRED = re.compile(
    r"(?i)!\s*!?\s*[\w$#.]*(?:tokens|token|passwords|password|passwd|secrets|secret|credentials|credential|apikey|api_key)\b"
)
_QUOTED = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")
_TEMPLATE = re.compile(r"`(?:\\.|\$\{[^}]*\}|[^`$])*`")
_DEBUG = re.compile(r"(?i)\bdebug\s*[:=]\s*(?:true|1|'1'|\"1\")\b")
_CORS = re.compile(
    r"""(?ix)
    allow_origins\s*=\s*\[\s*['\"]\*['\"]
    | access-control-allow-origin['\"]?\s*[:=]\s*['\"]\*['\"]
    | \bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b
    """
)
_CONFIG_NAMES = {
    "settings.py",
    "config.py",
    "application.yml",
    "application.yaml",
    "appsettings.json",
    ".env",
}
_LONG_LINE = 4000

_SECRET_REMEDIATION = (
    "Remove the value from source, rotate the credential, and load it from "
    "an environment variable or a secret manager at runtime."
)
_SQL_REMEDIATION = (
    "Keep the SQL text constant and pass values as bound parameters."
)
_SHELL_REMEDIATION = (
    "Call the program with an argument list and leave shell execution disabled."
)
_EVAL_REMEDIATION = (
    "Remove eval and exec. Decode structured input with a parser and handle "
    "an explicit set of cases."
)
_TLS_REMEDIATION = (
    "Leave certificate verification enabled. Point the client at a private "
    "trust bundle when the service uses an internal certificate authority."
)
_DEBUG_REMEDIATION = (
    "Turn debug mode off for shared configuration. Keep a local-only override "
    "outside the repository when a developer needs it."
)
_CORS_REMEDIATION = (
    "Set an explicit origin allow-list. Credentialed routes should name the "
    "origins that are allowed to call them."
)
_STORAGE_REMEDIATION = (
    "Keep the session token in an HttpOnly, Secure cookie set by the server. "
    "Do not store it where page script can read it."
)
_LOG_REMEDIATION = "Remove credential values from log calls. Log the event name only."
_HTML_REMEDIATION = (
    "Build the document with DOM methods or a fixed template. Do not pass "
    "assembled markup to an HTML parser."
)


def detect(repo: Path, scope: ScopeResult) -> tuple[list[Finding], list[DroppedFinding]]:
    """Run every detector over the in-scope inventory."""

    root = repo.resolve()
    findings: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for item in scope.files:
        path = root / item.path
        if not is_within(root, path):
            dropped.append(
                DroppedFinding(rule_id="file", file=item.path, line=1, reason="outside_root")
            )
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            dropped.append(
                DroppedFinding(rule_id="file", file=item.path, line=1, reason="unreadable")
            )
            continue
        if b"\0" in raw[:8192]:
            continue
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            if _is_comment(line):
                continue
            findings.extend(_rules_for_line(item.path, number, line))
            findings.extend(language_findings(item.path, number, line, item.language))
    findings.extend(offline_findings(root, scope))
    findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
    return findings, dropped


def deduplicate(
    findings: list[Finding],
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Collapse nearby hits of the same rule in the same file."""

    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in sorted(findings, key=lambda item: (item.file, item.rule_id, item.line)):
        grouped.setdefault((finding.file, finding.rule_id), []).append(finding)
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for group in grouped.values():
        cluster: list[Finding] = []
        for finding in group:
            if (
                cluster
                and finding.line - cluster[-1].line <= 3
                and finding.advisory_id == cluster[-1].advisory_id
            ):
                cluster.append(finding)
                continue
            if cluster:
                kept.append(_collapse(cluster, dropped))
            cluster = [finding]
        if cluster:
            kept.append(_collapse(cluster, dropped))
    kept.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
    return kept, dropped


def _collapse(cluster: list[Finding], dropped: list[DroppedFinding]) -> Finding:
    primary = cluster[0]
    also_at = [item.line for item in cluster[1:]]
    for item in cluster[1:]:
        dropped.append(
            DroppedFinding(
                rule_id=item.rule_id,
                file=item.file,
                line=item.line,
                reason="duplicate",
            )
        )
    if not also_at:
        return primary
    return primary.model_copy(update={"also_at": also_at})


def _rules_for_line(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    long_line = len(line) > _LONG_LINE
    secret = _secret_finding(path, number, line)
    if secret is not None:
        hits.append(secret)
    if long_line:
        return hits
    sql = _match_simple(
        path,
        number,
        line,
        pattern=_SQL,
        rule_id="sql-unparameterized",
        control_family="injection",
        severity="high",
        title="SQL built by string assembly",
        description=(
            "A database execute call builds a statement with interpolation, "
            "concatenation, or formatting."
        ),
        remediation=_SQL_REMEDIATION,
        confidence=0.7,
    )
    if sql is not None:
        hits.append(sql)
    hits.extend(_shell_findings(path, number, line))
    if _EVAL.search(line) and _EXTERNAL.search(line):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="dynamic-eval",
                control_family="injection",
                severity="high",
                title="Dynamic code execution of external input",
                description=(
                    "eval or exec is invoked on a line that also references "
                    "external input."
                ),
                remediation=_EVAL_REMEDIATION,
                confidence=0.8,
            )
        )
    if _TLS.search(line):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="tls-verify-disabled",
                control_family="transport",
                severity="medium",
                title="TLS certificate verification disabled",
                description="A call turns certificate verification off.",
                remediation=_TLS_REMEDIATION,
                confidence=0.95,
            )
        )
    if _is_config_name(path) and _DEBUG.search(line):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="debug-enabled",
                control_family="configuration",
                severity="low",
                title="Debug mode enabled in configuration",
                description="A configuration file turns debug mode on.",
                remediation=_DEBUG_REMEDIATION,
                confidence=0.6,
            )
        )
    if _CORS.search(line):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="cors-wildcard",
                control_family="access-control",
                severity="medium",
                title="Cross-origin access allows every origin",
                description="A cross-origin setting allows any website origin.",
                remediation=_CORS_REMEDIATION,
                confidence=0.85,
            )
        )
    html = _html_finding(path, number, line)
    if html is not None:
        hits.append(html)
    if _WEB_STORAGE.search(line) and _STORED_SECRET.search(line):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="token-in-web-storage",
                control_family="access-control",
                severity="high",
                title="Session token readable by page script",
                description=(
                    "A session token is stored in localStorage or sessionStorage, "
                    "where script running on the page can read it."
                ),
                remediation=_STORAGE_REMEDIATION,
                confidence=0.8,
            )
        )
    if _CONSOLE.search(line) and _CRED_IDENT.search(_logged_values(line)):
        hits.append(
            _make(
                path,
                number,
                line,
                rule_id="credential-logged",
                control_family="secrets",
                severity="medium",
                title="Credential written to a log",
                description="A log call receives a credential value.",
                remediation=_LOG_REMEDIATION,
                confidence=0.75,
            )
        )
    hits.extend(extra_findings(path, number, line))
    return hits


def _secret_finding(path: str, number: int, line: str) -> Finding | None:
    assigned = _ASSIGNED_SECRET.search(line)
    if assigned is not None and _PLACEHOLDER.fullmatch(assigned.group(2).strip()):
        assigned = None
    if assigned is None and not (
        _AWS.search(line)
        or _PRIVATE_KEY.search(line)
        or _GITHUB.search(line)
        or _SLACK.search(line)
    ):
        return None
    return _make(
        path,
        number,
        line,
        rule_id="hardcoded-secret",
        control_family="secrets",
        severity="high",
        title="Hardcoded secret",
        description="A secret-shaped value is embedded in source.",
        remediation=_SECRET_REMEDIATION,
        confidence=0.9,
    )


def _shell_findings(path: str, number: int, line: str) -> list[Finding]:
    assembled = _ASSEMBLED.search(line) is not None or "${" in line
    node_shell = _NODE_EXEC.search(line) is not None
    if _OS_SYSTEM.search(line) or ((_SHELL_TRUE.search(line) or node_shell) and assembled):
        return [
            _make(
                path,
                number,
                line,
                rule_id="shell-command",
                control_family="injection",
                severity="high",
                title="Shell command built from a string",
                description="A process call sends an assembled command through a shell.",
                remediation=_SHELL_REMEDIATION,
                confidence=0.75,
            )
        ]
    if _SHELL_TRUE.search(line) or node_shell:
        return [
            _make(
                path,
                number,
                line,
                rule_id="shell-enabled",
                control_family="injection",
                severity="medium",
                title="Shell execution enabled",
                description="A process call enables the shell for its command.",
                remediation=_SHELL_REMEDIATION,
                confidence=0.7,
            )
        ]
    return []


def _match_simple(
    path: str,
    number: int,
    line: str,
    *,
    pattern: re.Pattern[str],
    rule_id: str,
    control_family: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    confidence: float,
) -> Finding | None:
    if pattern.search(line) is None:
        return None
    return _make(
        path,
        number,
        line,
        rule_id=rule_id,
        control_family=control_family,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        description=description,
        remediation=remediation,
        confidence=confidence,
    )


def _make(
    path: str,
    number: int,
    line: str,
    *,
    rule_id: str,
    control_family: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    confidence: float,
) -> Finding:
    snippet = redact(line.strip())
    if len(snippet) > 240:
        snippet = snippet[:240]
    return Finding(
        rule_id=rule_id,
        control_family=control_family,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        file=path,
        line=number,
        description=description,
        remediation=remediation,
        snippet=snippet,
        confidence=confidence,
    )


def _html_finding(path: str, number: int, line: str) -> Finding | None:
    assigned = _HTML_ASSIGN.search(line)
    if assigned is not None:
        rhs = line.split("=", 1)[1].strip()
        if _PLAIN_ASSIGN.fullmatch(rhs):
            return None
    elif _HTML_WRITE.search(line) is None or _PLAIN_HTML.search(line) is not None:
        return None
    return _make(
        path,
        number,
        line,
        rule_id="html-parsed-from-string",
        control_family="injection",
        severity="medium",
        title="Markup parsed from a string",
        description="A call parses a string as HTML instead of building the document with DOM methods.",
        remediation=_HTML_REMEDIATION,
        confidence=0.7,
    )


def _logged_values(line: str) -> str:
    """Drop log text and boolean checks so only a passed credential value remains."""

    return _BOOL_CRED.sub("", _code_without_literals(line))


def _code_without_literals(line: str) -> str:
    """Drop quoted text so a log message that merely mentions a token is ignored."""

    def _template(match: re.Match[str]) -> str:
        return " ".join(re.findall(r"\$\{([^}]*)\}", match.group(0)))

    return _QUOTED.sub("''", _TEMPLATE.sub(_template, line))


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith("//")


def _is_config_name(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in _CONFIG_NAMES or name.endswith(".env")
