"""Language-shaped control checks.

These rules run only on files the inventory labeled with that language.
They record a missing control and a repair. They do not try a payload.
"""

from __future__ import annotations

import re

from silentblue.evidence import assembled_sql_verdict
from silentblue.models import Finding
from silentblue.redact import redact

_JS = frozenset({"javascript", "typescript", "tsx", "html"})
_C = frozenset({"c", "cpp"})

_SHELL_REPAIR = (
    "Pass the program and its arguments as a list and leave the shell off: "
    "subprocess.run([...], shell=False), execFile or spawn, exec.Command without sh -c, "
    "or the language equivalent. Do not interpolate caller text into the command string."
)
_SQL_REPAIR = (
    "Make the SQL text a constant. Pass values through the driver's bind API: "
    "PreparedStatement placeholders, database/sql arguments, sqlx bind parameters, or the equivalent. "
    "Do not build the statement with format!, sprintf, concatenation, or an f-string."
)
_EVAL_REPAIR = (
    "Remove eval, exec, new Function, and shell_exec of caller text. "
    "Parse structured input with a JSON or schema parser and branch on an explicit set of keys."
)
_TLS_REPAIR = (
    "Delete the call that disables verification, including rejectUnauthorized: false, "
    "InsecureSkipVerify: true, VERIFY_NONE, CURLOPT_SSL_VERIFYPEER false, and danger_accept_invalid_certs(true). "
    "For a private CA, install that bundle as the trust store and leave hostname checks on."
)

_JS_FUNCTION = re.compile(r"(?i)\bnew\s+Function\s*\(")
_RUBY_INTERP = re.compile(r"#\{")
_RUBY_SHELL = re.compile(r"(?i)\b(?:system|exec)\s*\(|`[^`]*#\{")
_RUBY_EVAL = re.compile(r"(?i)\beval\s*\(")
_RUBY_TLS = re.compile(r"VERIFY_NONE|\bverify_mode\s*=")
_C_SHELL = re.compile(r"\b(?:system|popen)\s*\(")
_C_BUILT = re.compile(r"%s|\+\s*|strcat\s*\(")
_C_TLS = re.compile(r"SSL_VERIFY_NONE|CURLOPT_SSL_VERIFYPEER\s*,\s*0")
_RUST_SHELL = re.compile(r"""Command::new\(\s*"(?:sh|bash|cmd)""")
_RUST_SQL = re.compile(r"""(?i)format!\(\s*"[^"]*SELECT""")
_RUST_TLS = re.compile(r"danger_accept_invalid_certs\(\s*true\s*\)")
_GO_SHELL = re.compile(r"""exec\.Command\(\s*"(?:sh|bash|cmd)""")
_GO_SQL = re.compile(r"""(?i)fmt\.Sprintf\(\s*"[^"]*SELECT""")
_GO_TLS = re.compile(r"InsecureSkipVerify:\s*true")
_JAVA_SHELL = re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(")
_JAVA_SQL = re.compile(r"""(?i)"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+""")
_JAVA_TLS = re.compile(r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAll")
_PHP_SHELL = re.compile(r"(?i)\b(?:shell_exec|passthru|system|exec)\s*\(")
_PHP_EVAL = re.compile(r"(?i)\beval\s*\(")
_PHP_TLS = re.compile(r"(?i)CURLOPT_SSL_VERIFYPEER\s*,\s*false")
_CS_SHELL = re.compile(r"(?i)UseShellExecute\s*=\s*true|Process\.Start\s*\(")
_CS_SQL = re.compile(r"""(?i)"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+""")
_CS_TLS = re.compile(r"ServerCertificateCustomValidationCallback")
_SH_EVAL = re.compile(r"(?i)\beval\s+")
_SH_TLS = re.compile(r"(?i)(?:curl|wget)\b.*(?:\s-k\b|--insecure)|SkipCertificateCheck")
_PLAIN_CALL = re.compile(r"""(?i)(?:system|exec|popen|Function)\s*\(\s*['\"][^'\"]*['\"]\s*\)""")


def mention_patterns() -> dict[str, tuple[re.Pattern[str], ...]]:
    """Patterns that decide whether a language-rule hit is only a quotation."""

    return {
        "dynamic-eval": (_JS_FUNCTION, _RUBY_EVAL, _PHP_EVAL, _SH_EVAL),
        "shell-command": (
            _RUBY_SHELL,
            _C_SHELL,
            _RUST_SHELL,
            _GO_SHELL,
            _JAVA_SHELL,
            _PHP_SHELL,
            _CS_SHELL,
        ),
        "shell-enabled": (
            _RUBY_SHELL,
            _C_SHELL,
            _RUST_SHELL,
            _GO_SHELL,
            _JAVA_SHELL,
            _PHP_SHELL,
            _CS_SHELL,
        ),
        "tls-verify-disabled": (_RUBY_TLS, _C_TLS, _RUST_TLS, _GO_TLS, _JAVA_TLS, _PHP_TLS, _CS_TLS, _SH_TLS),
        "sql-unparameterized": (_RUST_SQL, _GO_SQL, _JAVA_SQL, _CS_SQL),
    }


def language_findings(path: str, number: int, line: str, language: str) -> list[Finding]:
    """Return control gaps that belong to this file's language."""

    if language in _JS:
        return _js(path, number, line)
    if language == "ruby":
        return _ruby(path, number, line)
    if language in _C:
        return _c(path, number, line)
    if language == "rust":
        return _rust(path, number, line)
    if language == "go":
        return _go(path, number, line)
    if language == "java":
        return _java(path, number, line)
    if language == "php":
        return _php(path, number, line)
    if language == "csharp":
        return _csharp(path, number, line)
    if language in {"shell", "powershell"}:
        return _shell(path, number, line)
    return []


def _js(path: str, number: int, line: str) -> list[Finding]:
    if _JS_FUNCTION.search(line) is None or _PLAIN_CALL.search(line) is not None:
        return []
    return [
        _hit(
            path,
            number,
            line,
            rule_id="dynamic-eval",
            control_family="injection",
            severity="high",
            title="Dynamic code execution",
            description="A function is built from a string at runtime.",
            remediation=_EVAL_REPAIR,
            confidence=0.8,
        )
    ]


def _ruby(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _RUBY_SHELL.search(line):
        assembled = _RUBY_INTERP.search(line) is not None or "+" in line
        hits.append(_shell_hit(path, number, line, assembled))
    if _RUBY_EVAL.search(line) and _PLAIN_CALL.search(line) is None:
        hits.append(
            _hit(
                path,
                number,
                line,
                rule_id="dynamic-eval",
                control_family="injection",
                severity="high",
                title="Dynamic code execution",
                description="eval is invoked on a value that is not a fixed literal.",
                remediation=_EVAL_REPAIR,
                confidence=0.75,
            )
        )
    if _RUBY_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _c(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _C_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, _C_BUILT.search(line) is not None))
    if _C_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _rust(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _RUST_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, "format!" in line))
    if _RUST_SQL.search(line):
        found = _sql(path, number, line)
        if found is not None:
            hits.append(found)
    if _RUST_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _go(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _GO_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, "Sprintf" in line or "+" in line))
    if _GO_SQL.search(line):
        found = _sql(path, number, line)
        if found is not None:
            hits.append(found)
    if _GO_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _java(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _JAVA_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, "+" in line))
    if _JAVA_SQL.search(line):
        found = _sql(path, number, line)
        if found is not None:
            hits.append(found)
    if _JAVA_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _php(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _PHP_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, "$" in line or "." in line))
    if _PHP_EVAL.search(line) and _PLAIN_CALL.search(line) is None:
        hits.append(
            _hit(
                path,
                number,
                line,
                rule_id="dynamic-eval",
                control_family="injection",
                severity="high",
                title="Dynamic code execution",
                description="eval is invoked on a value that is not a fixed literal.",
                remediation=_EVAL_REPAIR,
                confidence=0.75,
            )
        )
    if _PHP_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _csharp(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _CS_SHELL.search(line):
        hits.append(_shell_hit(path, number, line, "+" in line))
    if _CS_SQL.search(line):
        found = _sql(path, number, line)
        if found is not None:
            hits.append(found)
    if _CS_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _shell(path: str, number: int, line: str) -> list[Finding]:
    hits: list[Finding] = []
    if _SH_EVAL.search(line):
        hits.append(
            _hit(
                path,
                number,
                line,
                rule_id="dynamic-eval",
                control_family="injection",
                severity="high",
                title="Dynamic code execution",
                description="The shell evaluates a string as code.",
                remediation=_EVAL_REPAIR,
                confidence=0.7,
            )
        )
    if _SH_TLS.search(line):
        hits.append(_tls(path, number, line))
    return hits


def _shell_hit(path: str, number: int, line: str, assembled: bool) -> Finding:
    if assembled:
        return _hit(
            path,
            number,
            line,
            rule_id="shell-command",
            control_family="injection",
            severity="high",
            title="Shell command built from a string",
            description="A process call sends an assembled command through a shell.",
            remediation=_SHELL_REPAIR,
            confidence=0.75,
        )
    return _hit(
        path,
        number,
        line,
        rule_id="shell-enabled",
        control_family="injection",
        severity="medium",
        title="Shell execution enabled",
        description="A process call sends a command through a shell.",
        remediation=_SHELL_REPAIR,
        confidence=0.7,
    )


def _sql(path: str, number: int, line: str) -> Finding | None:
    verdict = assembled_sql_verdict(line)
    if verdict is None:
        return None
    return _hit(
        path,
        number,
        line,
        rule_id="sql-unparameterized",
        control_family="injection",
        severity="high",
        title="SQL built by string assembly",
        description="A query is built with interpolation or concatenation.",
        remediation=_SQL_REPAIR,
        confidence=0.7 if verdict == "detector" else 0.4,
        verdict=verdict,
    )


def _tls(path: str, number: int, line: str) -> Finding:
    return _hit(
        path,
        number,
        line,
        rule_id="tls-verify-disabled",
        control_family="transport",
        severity="medium",
        title="TLS certificate verification disabled",
        description="A call turns certificate verification off.",
        remediation=_TLS_REPAIR,
        confidence=0.9,
    )


def _hit(
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
    )
