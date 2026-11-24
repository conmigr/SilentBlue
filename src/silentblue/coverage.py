"""Additional control-gap checks for the review families.

Each rule records a weak control that is visible on one line. None of them
sends a request, tries an input, or looks up an advisory.
"""

from __future__ import annotations

import re

from silentblue.models import Finding
from silentblue.redact import redact

_REQUEST = re.compile(
    r"(?i)(?:request\.(?:args|form|values|json|data|GET|POST|body|query|params|files)|"
    r"req\.(?:query|body|params|originalUrl|url)|params\[|input\s*\()"
)
_BUILT = re.compile(r"""f['\"]|\+\s*|\$\{|#\{|\.format\s*\(""")
_HTTP = re.compile(
    r"(?i)(?:requests\.(?:get|post|put|patch|delete|head|request)|"
    r"httpx\.(?:get|post|request)|urllib\.request\.urlopen|\burlopen|"
    r"axios\.(?:get|post|put|request)|\bfetch|\bgot(?:\.(?:get|post))?|"
    r"http\.Get|http\.Post)\s*\("
)
_REDIRECT = re.compile(r"(?i)(?:\bredirect\s*\(|\blocation\s*=)")
_PATH = re.compile(
    r"(?i)(?:send_file|sendFile|os\.path\.join|path\.join|filepath\.Join|path\.resolve)\s*\("
)
_NOSQL = re.compile(r"(?i)\$where\b")
_LDAP = re.compile(r"(?i)\bldap\b|search_s\s*\(|DirectorySearcher")
_TEMPLATE = re.compile(r"(?i)render_template_string\s*\(|jinja2\.Template\s*\(")
_TEMPLATE_LITERAL = re.compile(
    r"""(?is)(?:render_template_string|jinja2\.Template)\s*\(\s*['\"][^'\"]*['\"]\s*\)"""
)
_HEADER = re.compile(r"(?i)(?:setHeader|set_header|add_header|headers\s*\[)")
_XSS = re.compile(
    r"(?i)dangerouslySetInnerHTML|v-html\s*=|bypassSecurityTrust(?:Html|Url|ResourceUrl|Script)"
)
_FAST_HASH = re.compile(
    r"(?i)hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*['\"](?:md5|sha1)['\"]|"
    r"MessageDigest\.getInstance\(\s*['\"](?:MD5|SHA-1|SHA1)['\"]|MD5\.Create\s*\(|SHA1\.Create\s*\("
)
_SECRET_WORD = re.compile(r"(?i)password|passwd|secret")
_WEAK_RANDOM = re.compile(r"(?i)Math\.random\s*\(|random\.random\s*\(|\brand\s*\(\s*\)")
_TOKEN_WORD = re.compile(r"(?i)token|password|secret|session|api[_-]?key")
_WEAK_CIPHER = re.compile(
    r"(?i)AES/ECB|DES/ECB|Cipher\.getInstance\(\s*['\"](?:DES|RC4|Blowfish)|"
    r"createCipher\(\s*['\"](?:des|rc4|bf)"
)
_PICKLE = re.compile(r"(?i)\bpickle\.loads?\s*\(")
_YAML = re.compile(r"(?i)\byaml\.load\s*\(")
_YAML_SAFE = re.compile(r"(?i)safe_load|SafeLoader")
_UNSAFE_LOAD = re.compile(
    r"(?i)\bunserialize\s*\(|BinaryFormatter|ObjectInputStream|Marshal\.load\s*\(|"
    r"jsonpickle\.decode\s*\(|serialize\.unserialize\s*\("
)
_JWT = re.compile(r"(?i)\bjwt\b|jsonwebtoken")
_JWT_OFF = re.compile(
    r"(?i)verify(?:_signature)?['\"]?\s*[:=]\s*(?:false|0)|['\"]none['\"]"
)
_COOKIE = re.compile(r"(?i)(?:set_cookie|setCookie|\.cookie\s*\()")
_COOKIE_OFF = re.compile(r"(?i)(?:httpOnly|httponly|secure)\s*[:=]\s*(?:false|0)")
_CSRF_OFF = re.compile(
    r"(?i)@csrf_exempt|csrf\(\)\.disable|WTF_CSRF_ENABLED\s*=\s*False|"
    r"\bcsrf\s*[:=]\s*false|IgnoreAntiforgeryToken"
)
_MASS = re.compile(
    r"(?is)(?:\*\*\s*request\.(?:get_json\(\)|json|data|body))|"
    r"(?:Object\.assign\s*\([^)\n]{0,160}req\.body)|"
    r"(?:\.(?:create|update|save)\s*\(\s*req\.body\s*\))"
)
_RATE_OFF = re.compile(
    r"(?i)RATELIMIT_ENABLED\s*=\s*False|@limiter\.exempt|"
    r"rateLimit\(\s*\{[^)\n]*max\s*:\s*0|Throttle\s*[:=]\s*false"
)
_DEFAULT = re.compile(
    r"""(?ix)
    \b(?:password|passwd)\b
    \s*[:=]\s*
    (['\"])(admin|root|guest|letmein|welcome|qwerty|passw0rd|postgres|toor)\1
    """
)
_HOSTS = re.compile(r"""(?i)ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]""")
_HEADER_OFF = re.compile(
    r"(?i)contentSecurityPolicy\s*:\s*false|frameguard\s*:\s*false|hsts\s*:\s*false|"
    r"SECURE_SSL_REDIRECT\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False|"
    r"CSRF_COOKIE_SECURE\s*=\s*False"
)
_LOG_OFF = re.compile(r"(?i)logging\.disable\s*\(|logger\.disabled\s*=\s*True")
_WILDCARD_VERSION = re.compile(r""":\s*['\"](?:\*|latest)['\"]""")
_CLEARTEXT_DEP = re.compile(r"(?i)(?:git\+)?http://|--trusted-host\b")
_PIPED = re.compile(
    r"(?i)(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash)\b|iwr\b[^|\n]*\|\s*iex\b|"
    r"Invoke-WebRequest\b[^|\n]*\|\s*Invoke-Expression\b"
)
_PIPELINE = re.compile(r"pull_request_target|write-all")

_INJECTION = (
    "Keep the command, query, template, header, and path text constant. "
    "Pass values through a parameter, an argument list, or a DOM method."
)
_ROUTE = (
    "Call fixed URLs from configuration. Accept a redirect target only when it is "
    "a relative path on an allow-list you control."
)
_PATH_REPAIR = "Join a path under a fixed root and reject a result that escapes that root."
_CRYPTO = "Use a password hash for passwords, and a CSPRNG for tokens and session identifiers."
_CIPHER = "Use an authenticated cipher such as AES-GCM. Leave ECB, DES, and RC4 unused."
_LOAD = "Decode data with a parser that does not construct objects from the stream."
_JWT_REPAIR = "Verify the token signature and accept only an explicit algorithm list."
_COOKIE_REPAIR = "Set HttpOnly and Secure on session cookies, and keep the token off the page."
_CSRF_REPAIR = "Keep CSRF checks enabled on state-changing routes."
_MASS_REPAIR = "Copy an explicit field list from the request. Leave the request body unexpanded."
_RATE_REPAIR = "Leave a limit enabled on login, signup, password, and upload routes."
_DEFAULT_REPAIR = "Remove the default password and load the credential from outside the source tree."
_HEADER_REPAIR = "Leave the security headers and secure-cookie flags at their safe settings."
_LOG_REPAIR = "Leave logging enabled for authentication and authorization failures."
_DEP_REPAIR = "Pin the dependency to a reviewed version and fetch it over TLS."
_PIPE_REPAIR = "Download a release, check its digest, and run it as a file. Leave the shell out of the pipe."
_PIPELINE_REPAIR = "Run untrusted pull requests with read permissions, and name the permissions the job needs."


def extra_findings(path: str, number: int, line: str) -> list[Finding]:
    """Return control gaps that sit outside the original five line rules."""

    hits: list[Finding] = []
    request = _REQUEST.search(line) is not None
    built = _BUILT.search(line) is not None
    if _NOSQL.search(line) and (built or request):
        hits.append(_hit(path, number, line, "nosql-unparameterized", "injection", "high", "Query filter built from a string", "A query uses $where with assembled or request data.", _INJECTION, 0.75))
    if _LDAP.search(line) and built:
        hits.append(_hit(path, number, line, "ldap-filter-assembled", "injection", "high", "Directory filter built from a string", "A directory search builds its filter by assembly.", _INJECTION, 0.7))
    if _TEMPLATE.search(line) and _TEMPLATE_LITERAL.search(line) is None:
        hits.append(_hit(path, number, line, "template-from-string", "injection", "high", "Template rendered from a string", "A template engine compiles a string that is not a fixed literal.", _INJECTION, 0.8))
    if _HEADER.search(line) and request:
        hits.append(_hit(path, number, line, "header-from-request", "injection", "medium", "Response header taken from the request", "A response header is assigned from request data.", _INJECTION, 0.7))
    if _XSS.search(line):
        hits.append(_hit(path, number, line, "html-parsed-from-string", "injection", "medium", "Markup parsed from a string", "A call parses a string as HTML instead of building the document with DOM methods.", _INJECTION, 0.75))
    if _PATH.search(line) and request:
        hits.append(_hit(path, number, line, "path-from-request", "request-routing", "high", "File path taken from the request", "A file path is joined or sent from request data.", _PATH_REPAIR, 0.75))
    if _HTTP.search(line) and request:
        hits.append(_hit(path, number, line, "request-url-from-input", "request-routing", "high", "Outbound URL taken from the request", "An HTTP client is given a URL from request data.", _ROUTE, 0.75))
    if _REDIRECT.search(line) and request:
        hits.append(_hit(path, number, line, "redirect-from-request", "request-routing", "medium", "Redirect target taken from the request", "A redirect target comes from request data.", _ROUTE, 0.7))
    if _FAST_HASH.search(line) and _SECRET_WORD.search(line):
        hits.append(_hit(path, number, line, "weak-password-hash", "cryptography", "high", "Password passed to a fast hash", "A password or secret is passed to MD5 or SHA-1.", _CRYPTO, 0.85))
    if _WEAK_RANDOM.search(line) and _TOKEN_WORD.search(line):
        hits.append(_hit(path, number, line, "weak-token-random", "cryptography", "medium", "Token drawn from a weak generator", "A token, password, or session value uses a non-cryptographic random source.", _CRYPTO, 0.7))
    if _WEAK_CIPHER.search(line):
        hits.append(_hit(path, number, line, "weak-cipher", "cryptography", "medium", "Cipher without authentication", "The call selects ECB, DES, RC4, or Blowfish.", _CIPHER, 0.85))
    if _PICKLE.search(line) or _UNSAFE_LOAD.search(line) or (_YAML.search(line) and _YAML_SAFE.search(line) is None):
        hits.append(_hit(path, number, line, "unsafe-deserialization", "deserialization", "high", "Decoder can construct objects", "A loader can turn a stream into objects.", _LOAD, 0.85))
    if _JWT.search(line) and _JWT_OFF.search(line):
        hits.append(_hit(path, number, line, "jwt-verify-disabled", "authentication", "high", "Token signature check disabled", "A JWT call turns verification off or allows the none algorithm.", _JWT_REPAIR, 0.9))
    if _COOKIE.search(line) and _COOKIE_OFF.search(line):
        hits.append(_hit(path, number, line, "cookie-flag-disabled", "authentication", "medium", "Session cookie flag turned off", "A cookie call sets HttpOnly or Secure to false.", _COOKIE_REPAIR, 0.8))
    if _CSRF_OFF.search(line):
        hits.append(_hit(path, number, line, "csrf-disabled", "access-control", "medium", "CSRF check disabled", "A setting turns CSRF protection off for a route or the application.", _CSRF_REPAIR, 0.85))
    if _MASS.search(line):
        hits.append(_hit(path, number, line, "request-body-expanded", "access-control", "medium", "Request body copied into a model", "A create or update takes the request body instead of a named field list.", _MASS_REPAIR, 0.7))
    if _RATE_OFF.search(line):
        hits.append(_hit(path, number, line, "rate-limit-disabled", "resource-limits", "medium", "Request limit turned off", "A limiter is exempted or its maximum is zero.", _RATE_REPAIR, 0.8))
    if _DEFAULT.search(line):
        hits.append(_hit(path, number, line, "default-credential", "secrets", "high", "Default password in source", "A password is set to a well-known default.", _DEFAULT_REPAIR, 0.9))
    if _HOSTS.search(line) or _HEADER_OFF.search(line):
        hits.append(_hit(path, number, line, "security-header-disabled", "configuration", "medium", "Browser or host control turned off", "A host allow-list, security header, or secure-cookie setting is disabled.", _HEADER_REPAIR, 0.8))
    if _LOG_OFF.search(line):
        hits.append(_hit(path, number, line, "logging-disabled", "logging", "low", "Logging turned off", "A call disables the logger.", _LOG_REPAIR, 0.7))
    hits.extend(_supply(path, number, line))
    return hits


def _supply(path: str, number: int, line: str) -> list[Finding]:
    name = path.rsplit("/", 1)[-1].lower()
    portable = path.replace("\\", "/")
    hits: list[Finding] = []
    if name in {"package.json", "composer.json"} and _WILDCARD_VERSION.search(line):
        hits.append(_hit(path, number, line, "dependency-unpinned", "supply-chain", "medium", "Dependency version is unpinned", "A manifest accepts any version, or latest.", _DEP_REPAIR, 0.8))
    if name.startswith("requirements") or name in {"pipfile", "constraints.txt"}:
        if _CLEARTEXT_DEP.search(line):
            hits.append(_hit(path, number, line, "dependency-cleartext", "supply-chain", "medium", "Dependency fetched without TLS", "A dependency line uses cleartext HTTP or trusts a host.", _DEP_REPAIR, 0.85))
    if _PIPED.search(line):
        hits.append(_hit(path, number, line, "piped-download", "supply-chain", "high", "Downloaded script piped into a shell", "A download is executed by a shell.", _PIPE_REPAIR, 0.9))
    if "/.github/workflows/" in f"/{portable}" and _PIPELINE.search(line):
        hits.append(_hit(path, number, line, "workflow-permissions-wide", "supply-chain", "medium", "Workflow grants a wide permission", "A workflow uses pull_request_target or write-all.", _PIPELINE_REPAIR, 0.75))
    return hits


def _hit(
    path: str,
    number: int,
    line: str,
    rule_id: str,
    family: str,
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
        control_family=family,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        file=path,
        line=number,
        description=description,
        remediation=remediation,
        snippet=snippet,
        confidence=confidence,
    )
