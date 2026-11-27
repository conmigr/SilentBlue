"""Deterministic control-gap detectors.

Each rule records a missing or weak control and a defensive repair note.
Detectors read only paths the scope walk already accepted. A hit is confirmed,
left unsettled, or closed before it becomes a finding.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from silentblue.coverage import extra_findings
from silentblue.coverage import mention_patterns as coverage_mentions
from silentblue.evidence import fixture_secret, is_document, literal_masks, live_secret, quote_only, sql_clusters
from silentblue.languages import language_findings
from silentblue.languages import mention_patterns as language_mentions
from silentblue.models import DroppedFinding, Finding, ScopedFile, ScopeResult
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
_SQL_TOKEN = re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|execute|executemany|query)\b")
_DETECTOR_MENTIONS = {
    "shell-command": (_OS_SYSTEM, _SHELL_TRUE, _NODE_EXEC),
    "shell-enabled": (_SHELL_TRUE, _NODE_EXEC),
    "dynamic-eval": (_EVAL, _EXTERNAL),
    "tls-verify-disabled": (_TLS,),
    "debug-enabled": (_DEBUG,),
    "cors-wildcard": (_CORS,),
    "html-parsed-from-string": (_HTML_ASSIGN, _HTML_WRITE),
    "token-in-web-storage": (_WEB_STORAGE, _STORED_SECRET),
    "sql-unparameterized": (_SQL_TOKEN,),
}

_SECRET_REMEDIATION = (
    "Delete the literal from the tracked file and revoke it at the issuer. "
    "Read the replacement from the process environment or a secret manager at process start. "
    "Do not commit the new value, and do not leave the old value in git history on a pushed branch."
)
_SQL_REMEDIATION = (
    "Make the SQL statement a constant. Pass caller values only in the driver's parameter "
    "argument, for example cursor.execute(sql, params) or the equivalent bind call. "
    "An f-string or concatenation that builds the statement is still the statement, even when a parameter tuple is also present."
)
_SHELL_REMEDIATION = (
    "Pass the program and its arguments as a list. In Python use subprocess.run([program, arg], shell=False). "
    "In Node use execFile or spawn with an args array. Do not set shell=True, and do not interpolate caller text into the command string."
)
_EVAL_REMEDIATION = (
    "Remove eval, exec, and new Function. Parse structured input with a JSON or schema parser "
    "and branch on an explicit set of keys. Do not compile caller text as code."
)
_TLS_REMEDIATION = (
    "Delete the setting that turns verification off: verify=False, rejectUnauthorized: false, "
    "InsecureSkipVerify: true, or CURLOPT_SSL_VERIFYPEER set false. "
    "For a private certificate authority, set the client's trust store to that CA bundle file and leave hostname checks on."
)
_DEBUG_REMEDIATION = (
    "Set DEBUG, debug, and equivalent flags false in shared configuration such as settings.py, "
    "application.yml, and appsettings.json. Keep a developer override in an untracked local file."
)
_CORS_REMEDIATION = (
    "Replace the wildcard origin with an explicit list of scheme, host, and port. "
    "On a credentialed route, set Access-Control-Allow-Origin to one of those origins and "
    "Access-Control-Allow-Credentials to true. Do not combine a credentialed response with *."
)
_STORAGE_REMEDIATION = (
    "Stop writing the session token to localStorage or sessionStorage. "
    "Set it in a cookie with HttpOnly, Secure, and SameSite=Strict or Lax, from the server response."
)
_LOG_REMEDIATION = (
    "Remove the credential variable from the log call. Log a stable event name and a non-secret identifier. "
    "Do not pass password, token, secret, or authorization header values to the logger."
)
_HTML_REMEDIATION = (
    "Stop passing assembled text to innerHTML, document.write, insertAdjacentHTML, "
    "dangerouslySetInnerHTML, or v-html. Build the nodes with DOM APIs or a template that does not interpolate HTML."
)


def detect(repo: Path, scope: ScopeResult) -> tuple[list[Finding], list[DroppedFinding]]:
    """Run every detector over the in-scope inventory."""

    root = repo.resolve()
    findings: list[Finding] = []
    dropped: list[DroppedFinding] = []
    canonical, copies = _canonical_files(root, scope)
    for item in canonical:
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
        file_findings, file_dropped = _file_findings(item.path, item.language, text)
        also_in = copies.get(item.path, [])
        if also_in:
            file_findings = [
                finding.model_copy(update={"also_in": also_in}) for finding in file_findings
            ]
        findings.extend(file_findings)
        dropped.extend(file_dropped)
    narrowed = scope.model_copy(update={"files": canonical})
    findings.extend(offline_findings(root, narrowed))
    findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
    return findings, dropped


def deduplicate(
    findings: list[Finding],
) -> tuple[list[Finding], list[DroppedFinding]]:
    """Collapse nearby hits of the same rule in the same file."""

    assessment = [finding for finding in findings if finding.origin == "assessment"]
    grouped: dict[tuple[str, str], list[Finding]] = {}
    for finding in sorted(
        (item for item in findings if item.origin != "assessment"),
        key=lambda item: (item.file, item.rule_id, item.line),
    ):
        grouped.setdefault((finding.file, finding.rule_id), []).append(finding)
    kept: list[Finding] = []
    dropped: list[DroppedFinding] = []
    for group in grouped.values():
        cluster: list[Finding] = []
        for finding in group:
            if (
                cluster
                and finding.rule_id != "sql-unparameterized"
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
    return [*assessment, *kept], dropped


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
    if len(line) > _LONG_LINE:
        return hits
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


def _file_findings(path: str, language: str, text: str) -> tuple[list[Finding], list[DroppedFinding]]:
    findings: list[Finding] = []
    dropped: list[DroppedFinding] = []
    lines = text.splitlines()
    masks = literal_masks(text)
    document = is_document(path)
    for cluster in sql_clusters(path, text):
        if cluster.status == "closed":
            dropped.append(
                DroppedFinding(
                    rule_id="sql-unparameterized",
                    file=path,
                    line=cluster.line,
                    reason=cluster.reason,
                )
            )
            continue
        source_line = lines[cluster.line - 1] if cluster.line <= len(lines) else ""
        finding = _make(
            path,
            cluster.line,
            source_line,
            rule_id="sql-unparameterized",
            control_family="injection",
            severity="high",
            title="SQL built by string assembly",
            description=(
                "A database call builds a statement with interpolation, "
                "concatenation, or formatting."
                if cluster.status == "detector"
                else "A database call builds a statement, and this line does not show whether the inserted value is caller-controlled."
            ),
            remediation=_SQL_REMEDIATION,
            confidence=0.7 if cluster.status == "detector" else 0.4,
            verdict=cluster.status,
            also_at=list(cluster.also_at),
        )
        _keep(findings, dropped, finding, source_line, _mask_at(masks, cluster.line, source_line), document)
    for number, line in enumerate(lines, start=1):
        if _is_comment(line):
            continue
        secret = _secret_finding(path, number, line)
        if isinstance(secret, DroppedFinding):
            dropped.append(secret)
        elif secret is not None:
            findings.append(secret)
        if len(line) > _LONG_LINE:
            continue
        mask = _mask_at(masks, number, line)
        for finding in (
            *_rules_for_line(path, number, line),
            *language_findings(path, number, line, language),
        ):
            _keep(findings, dropped, finding, line, mask, document)
    return findings, dropped


def _keep(
    findings: list[Finding],
    dropped: list[DroppedFinding],
    finding: Finding,
    line: str,
    mask: list[bool],
    document: bool,
) -> None:
    if document:
        dropped.append(
            DroppedFinding(rule_id=finding.rule_id, file=finding.file, line=finding.line, reason="document")
        )
        return
    patterns = _mention_table().get(finding.rule_id, ())
    if patterns and quote_only(line, mask, patterns):
        dropped.append(
            DroppedFinding(rule_id=finding.rule_id, file=finding.file, line=finding.line, reason="mentioned")
        )
        return
    findings.append(finding)


def _mask_at(masks: list[list[bool]], number: int, line: str) -> list[bool]:
    if 1 <= number <= len(masks) and len(masks[number - 1]) == len(line):
        return masks[number - 1]
    return [False] * len(line)


def _mention_table() -> dict[str, tuple[re.Pattern[str], ...]]:
    merged: dict[str, tuple[re.Pattern[str], ...]] = {}
    for table in (coverage_mentions(), language_mentions(), _DETECTOR_MENTIONS):
        for rule_id, patterns in table.items():
            merged[rule_id] = merged.get(rule_id, ()) + patterns
    return merged


def _canonical_files(root: Path, scope: ScopeResult) -> tuple[list[ScopedFile], dict[str, list[str]]]:
    """Scan each distinct file once. Empty files stay separate."""

    groups: dict[bytes, list[ScopedFile]] = {}
    order: list[bytes] = []
    for item in scope.files:
        path = root / item.path
        try:
            raw = path.read_bytes() if item.size else b""
        except OSError:
            raw = item.path.encode("utf-8")
        if not item.size:
            digest = item.path.encode("utf-8")
        else:
            digest = hashlib.sha256(raw).digest()
        if digest not in groups:
            order.append(digest)
            groups[digest] = []
        groups[digest].append(item)
    canonical: list[ScopedFile] = []
    copies: dict[str, list[str]] = {}
    for digest in order:
        grouped = sorted(groups[digest], key=lambda item: (len(item.path), item.path))
        canonical.append(grouped[0])
        if item_size(grouped) and len(grouped) > 1:
            copies[grouped[0].path] = [item.path for item in grouped[1:]]
    return canonical, copies


def item_size(grouped: list[ScopedFile]) -> bool:
    return any(item.size for item in grouped)


def _secret_finding(path: str, number: int, line: str) -> Finding | DroppedFinding | None:
    if live_secret(line):
        return _secret_hit(path, number, line)
    assigned = _ASSIGNED_SECRET.search(line)
    if assigned is None:
        if not (_AWS.search(line) or _PRIVATE_KEY.search(line) or _GITHUB.search(line) or _SLACK.search(line)):
            return None
        return _secret_hit(path, number, line)
    value = assigned.group(2).strip()
    if _PLACEHOLDER.fullmatch(value) or fixture_secret(value):
        return DroppedFinding(
            rule_id="hardcoded-secret",
            file=path,
            line=number,
            reason="fixture",
        )
    return _secret_hit(path, number, line)


def _secret_hit(path: str, number: int, line: str) -> Finding:
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
    from silentblue.evidence import caller_controlled

    assembled = _ASSEMBLED.search(line) is not None or "${" in line
    node_shell = _NODE_EXEC.search(line) is not None
    literal_command = bool(re.search(r"""(?is)(?:os\.system|execSync|exec)\s*\(\s*['\"][^'\"]*['\"]\s*\)""", line))
    if literal_command and not assembled:
        return []
    verdict = "detector" if caller_controlled(line) or _EXTERNAL.search(line) else "inconclusive"
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
                verdict=verdict,
            )
        ]
    if (_SHELL_TRUE.search(line) or node_shell) and not literal_command:
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
                verdict="inconclusive",
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
    verdict: str = "detector",
    also_at: list[int] | None = None,
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
        verdict=verdict,  # type: ignore[arg-type]
        also_at=also_at or [],
    )


def _html_finding(path: str, number: int, line: str) -> Finding | None:
    assigned = _HTML_ASSIGN.search(line)
    if assigned is not None:
        rhs = line.split("=", 1)[1].strip()
        if _PLAIN_ASSIGN.fullmatch(rhs):
            return None
    elif _HTML_WRITE.search(line) is None or _PLAIN_HTML.search(line) is not None:
        return None
    from silentblue.evidence import caller_controlled

    verdict = "detector" if caller_controlled(line) or _EXTERNAL.search(line) else "inconclusive"
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
        verdict=verdict,
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
