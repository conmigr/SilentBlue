"""Deployment review. Declared files, one named URL, and an optional account snapshot.

The command appends candidate gaps to the existing report. It does not sweep
ports, send a payload, or follow a redirect to another host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError

from silentblue.casefiles import findings_file, load_report
from silentblue.envfile import load_operator_env
from silentblue.errors import SilentBlueError, UsageError
from silentblue.manifest import write_manifest
from silentblue.models import DeployResult, Finding
from silentblue.paths import is_reparse_point, is_within
from silentblue.rank import case_id_for
from silentblue.redact import configure_logging, redact
from silentblue.report import write_report
from silentblue.runner import _require_repo

_ADMIN_PORTS = frozenset({22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 2379, 11211, 5985, 5986})
_WORLD = ("0.0.0.0/0", "::/0")
_EDGE_DIRS = frozenset(
    {"deploy", "deployment", "infra", "terraform", "k8s", "kubernetes", "helm", "charts", "nginx", "proxy", "gateway", "envoy"}
)
_COMPOSE_NAMES = frozenset(
    {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
)
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "vendor", "security-scan", "security-remediation", ".silentblue", "__pycache__", ".venv", "venv", "dist", "build"}
)
_MAX_FILES = 200
_MAX_BYTES = 256 * 1024
_WINDOW = 30
_AUTH_WINDOW = timedelta(minutes=10)
_CERT_SOON = timedelta(days=14)

_EDGE = re.compile(
    r"aws_lb|aws_alb|aws_elb|kind:\s*Ingress\b|listen\s+80\b|listen\s+443\b|load_balancer|cloudfront|traefik",
    re.IGNORECASE,
)
_WAF = re.compile(r"\bwaf\b|aws_waf|web_acl|modsecurity|cloud_armor|cloudarmor|frontdoor", re.IGNORECASE)
_HTTP_LISTENER = re.compile(r"""protocol\s*=\s*["']HTTP["']|listen\s+80\b""", re.IGNORECASE)
_HTTPS_LISTENER = re.compile(
    r"""protocol\s*=\s*["']HTTPS["']|listen\s+443\b|return\s+301\s+https|type\s*=\s*["']redirect["']""",
    re.IGNORECASE,
)
_FORWARDED = re.compile(r"\$http_x_forwarded_for", re.IGNORECASE)
_PORT_PUBLISH = re.compile(
    r"""["']?(?:\d{1,3}(?:\.\d{1,3}){3}:)?(\d{1,5})\s*:\s*(\d{1,5})["']?"""
)
_PORT_ASSIGN = re.compile(
    r"""(?:from_port|to_port|host_port|hostPort|containerPort|port)\s*[:=]\s*["']?(\d{1,5})""",
    re.IGNORECASE,
)


class _Listener(BaseModel):
    model_config = ConfigDict(extra="ignore")

    port: int
    protocol: str = ""
    redirect_to_https: bool = False


class _Rule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    port: int
    cidr: str = ""


class _Snapshot(BaseModel):
    model_config = ConfigDict(extra="ignore")

    listeners: list[_Listener] = []
    rules: list[_Rule] = []
    waf_attached: bool | None = None
    public_origin: bool | None = None


@dataclass
class UrlObservation:
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    cert: dict | None = None
    error: str = ""
    final_scheme: str = ""
    location: str = ""


class DeployAuthorization(BaseModel):
    """Confirmation for one host. The window closes with the command."""

    model_config = ConfigDict(extra="forbid")

    host: str
    confirmed_at: str
    expires_at: str


def open_authorization(state_dir: Path, repo: Path, host: str) -> DeployAuthorization:
    """Record the host and the window outside the repository."""

    if is_within(repo.resolve(), state_dir.resolve()):
        raise UsageError("state directory must be outside the repository")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    record = DeployAuthorization(
        host=host.lower(),
        confirmed_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + _AUTH_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    path = _authorization_path(state_dir, repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    return record


def authorization_allows(record: DeployAuthorization, host: str, now: datetime | None = None) -> bool:
    """True when this host is the confirmed host and the window is open."""

    current = now or datetime.now(timezone.utc)
    try:
        expires = datetime.strptime(record.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return bool(host) and record.host.lower() == host.lower() and current <= expires


def _authorization_path(state_dir: Path, repo: Path) -> Path:
    digest = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir / "deploy" / f"{digest}.json"


def run_deploy(
    *,
    repo: Path,
    url: str | None = None,
    snapshot: Path | None = None,
    deploy_dir: Path | None = None,
    findings: Path | None = None,
    manifest_dir: Path | None = None,
    cwd: Path | None = None,
    argv: list[str] | None = None,
    transport=None,
    authorization: DeployAuthorization | None = None,
) -> DeployResult:
    """Append deployment gaps to the current report. Source stays unchanged."""

    configure_logging()
    exit_code = 0
    message = "ok"
    declared: list[Finding] = []
    observed: list[Finding] = []
    findings_path: str | None = None
    manifest_path: str | None = None
    account_observed = False
    url_observed = False
    try:
        root = _require_repo(repo)
        load_operator_env(root, cwd or Path.cwd())
        named_url = (url if url is not None else os.environ.get("SILENTBLUE_DEPLOY_URL", "")).strip()
        snapshot_path = snapshot
        if snapshot_path is None and os.environ.get("SILENTBLUE_DEPLOY_SNAPSHOT", "").strip():
            snapshot_path = Path(os.environ["SILENTBLUE_DEPLOY_SNAPSHOT"].strip())
        report_path = findings_file(root, findings)
        report = load_report(report_path)
        declared = _declared_findings(root, deploy_dir)
        if snapshot_path is not None:
            account_observed = True
            observed.extend(_snapshot_findings(_read_snapshot(root, snapshot_path)))
        edge_passed: list[str] = []
        if named_url:
            host = urlsplit(named_url).hostname or ""
            if authorization is not None and not authorization_allows(authorization, host):
                raise UsageError("deploy authorization does not match this host")
            observation = transport(named_url) if transport is not None else fetch_url(named_url)
            url_observed = observation.error != "unreachable"
            found, edge_passed = _url_findings(named_url, observation, report.findings)
            observed.extend(found)
        merged = _merge(report, declared, observed, account_observed, url_observed, edge_passed)
        written = write_report(merged, root, "security-scan", datetime.now(timezone.utc))
        findings_path = str(written)
        message = (
            f"recorded {len(declared)} declared gaps and {len(observed)} observed gaps"
        )
    except SilentBlueError as exc:
        exit_code = exc.exit_code
        message = str(exc)
    except Exception as exc:
        exit_code = 1
        message = redact(str(exc))
    try:
        manifest_path = str(
            write_manifest(
                manifest_dir or cwd or Path.cwd(),
                {
                    "command": "deploy",
                    "argv": argv or [],
                    "exit_code": exit_code,
                    "message": message,
                    "declared": len(declared),
                    "observed": len(observed),
                    "account_observed": account_observed,
                    "url_observed": url_observed,
                },
            )
        )
    except OSError:
        manifest_path = None
    return DeployResult(
        exit_code=exit_code,
        message=message,
        finding_count=len(declared) + len(observed),
        declared_count=len(declared),
        observed_count=len(observed),
        findings_path=findings_path,
        manifest_path=manifest_path,
        account_observed=account_observed,
        url_observed=url_observed,
    )


def deploy_preview(repo: Path, *, url: str = "", snapshot: str = "", deploy_dir: Path | None = None) -> str:
    """Text the session prints before asking for yes."""

    files = _collect(repo, deploy_dir)
    lines = [
        f"deployment files  {len(files)}",
        f"url  {url or 'not set'}",
        f"account  {snapshot or 'not observed'}",
    ]
    return "\n".join(lines)


def fetch_url(url: str, timeout: float = 10.0) -> UrlObservation:
    """Request the named URL once. A redirect to another host is not followed."""

    parts = _require_url(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        if parts.scheme == "https":
            connection = HTTPSConnection(parts.hostname, port, timeout=timeout, context=ssl.create_default_context())
        else:
            connection = HTTPConnection(parts.hostname, port, timeout=timeout)
        connection.request("GET", path, headers={"User-Agent": "silentblue", "Accept": "text/html"})
        response = connection.getresponse()
        headers = response.getheaders()
        status = response.status
        cert = None
        sock = getattr(connection, "sock", None)
        if isinstance(sock, ssl.SSLSocket):
            cert = sock.getpeercert()
        response.close()
        connection.close()
    except ssl.SSLCertVerificationError:
        return UrlObservation(error="untrusted", final_scheme=parts.scheme)
    except OSError:
        return UrlObservation(error="unreachable", final_scheme=parts.scheme)
    location = ""
    for name, value in headers:
        if name.lower() == "location":
            location = value
            break
    return UrlObservation(
        status=status,
        headers=headers,
        cert=cert,
        final_scheme=parts.scheme,
        location=location,
    )


def _require_url(url: str):
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UsageError("deploy URL must be http or https and name a host")
    if parts.username or parts.password:
        raise UsageError("deploy URL must not carry a secret")
    if parts.hostname in {"0.0.0.0"}:
        raise UsageError("deploy URL must name one host")
    return parts


def _read_snapshot(repo: Path, path: Path) -> _Snapshot:
    candidate = path.expanduser()
    if is_reparse_point(candidate) or not candidate.is_file():
        raise UsageError("deploy snapshot must be a real file outside the repository")
    if is_within(repo, candidate):
        raise UsageError("deploy snapshot must be a real file outside the repository")
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise UsageError("deploy snapshot must be a real file outside the repository") from exc
    if len(raw) > 64 * 1024 or b"\0" in raw:
        raise UsageError("deploy snapshot must be a real file outside the repository")
    try:
        return _Snapshot.model_validate(json.loads(raw.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        raise UsageError("deploy snapshot is not a deployment account file") from exc


def _declared_findings(repo: Path, deploy_dir: Path | None) -> list[Finding]:
    files = _collect(repo, deploy_dir)
    texts = [(label, text) for label, text in files]
    findings: list[Finding] = []
    edge_at: tuple[str, int] | None = None
    waf = False
    for label, text in texts:
        if _WAF.search(text):
            waf = True
        if edge_at is None and _EDGE.search(text):
            edge_at = (label, _line_of(text, _EDGE))
        findings.extend(_file_findings(label, text))
    if edge_at is None:
        anchor = texts[0][0] if texts else "deployment"
        findings.append(
            _gap(
                "deploy-origin-public",
                "medium",
                "No edge in front of the application",
                anchor,
                1,
                "Declared. No proxy, load balancer, or ingress file was in this review, so the origin is the public door.",
                "Put a proxy or load balancer on the public listener and keep the application off that listener.",
                "declared",
            )
        )
    elif not waf:
        findings.append(
            _gap(
                "deploy-waf-unattached",
                "medium",
                "No WAF on the public listener",
                edge_at[0],
                edge_at[1],
                "Declared. An edge is defined and no WAF is attached to it in these files. Attachment is not evidence the WAF stops an attack.",
                "Attach a WAF to the public listener and turn on its log.",
                "declared",
            )
        )
    return findings


def _file_findings(label: str, text: str) -> list[Finding]:
    found: list[Finding] = []
    lines = text.splitlines() or [text]
    if _HTTP_LISTENER.search(text) and not _HTTPS_LISTENER.search(text):
        found.append(
            _gap(
                "deploy-listener-cleartext",
                "high",
                "Public listener is clear text",
                label,
                _line_of(text, _HTTP_LISTENER),
                "Declared. The listener accepts HTTP and does not redirect to HTTPS in this file.",
                "Serve HTTPS on the public listener and redirect clear text to it.",
                "declared",
            )
        )
    match = _FORWARDED.search(text)
    if match:
        found.append(
            _gap(
                "deploy-forwarded-header",
                "medium",
                "Proxy trusts a client-supplied forwarded header",
                label,
                _line_of(text, _FORWARDED),
                "Declared. The proxy copies the inbound forwarded header instead of the address it observed.",
                "Set the forwarded header from the connection the proxy accepted.",
                "declared",
            )
        )
    for port, line in _admin_ports(lines):
        found.append(
            _gap(
                "deploy-admin-exposed",
                "high",
                f"Port {port} is open to the whole internet",
                label,
                line,
                f"Declared. Port {port} is published to 0.0.0.0/0 or ::/0, or on a public service.",
                "Keep admin and data ports on a private network.",
                "declared",
            )
        )
        break
    return found


def _admin_ports(lines: list[str]) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        window = "\n".join(lines[max(0, index - _WINDOW) : index + _WINDOW + 1])
        published = _PORT_PUBLISH.findall(line)
        for left, right in published:
            port = int(right)
            if port in _ADMIN_PORTS:
                hits.append((port, index + 1))
        if not any(token in window for token in _WORLD) and "LoadBalancer" not in window and "NodePort" not in window:
            continue
        for raw in _PORT_ASSIGN.findall(line):
            port = int(raw)
            if port in _ADMIN_PORTS:
                hits.append((port, index + 1))
                break
    return hits


def _snapshot_findings(snapshot: _Snapshot) -> list[Finding]:
    found: list[Finding] = []
    for rule in snapshot.rules:
        if rule.port in _ADMIN_PORTS and rule.cidr.strip() in _WORLD:
            found.append(
                _gap(
                    "deploy-admin-exposed",
                    "high",
                    f"Port {rule.port} is open to the whole internet",
                    "account",
                    1,
                    f"Observed. The account snapshot allows port {rule.port} from {rule.cidr}.",
                    "Keep admin and data ports on a private network.",
                    "observed",
                )
            )
            break
    https = [item for item in snapshot.listeners if item.protocol.lower() == "https" or item.redirect_to_https]
    clear = [item for item in snapshot.listeners if item.protocol.lower() == "http" and not item.redirect_to_https]
    if clear and not https:
        found.append(
            _gap(
                "deploy-listener-cleartext",
                "high",
                "Public listener is clear text",
                "account",
                1,
                "Observed. The account snapshot has an HTTP listener and no HTTPS listener.",
                "Serve HTTPS on the public listener and redirect clear text to it.",
                "observed",
            )
        )
    if snapshot.waf_attached is False:
        found.append(
            _gap(
                "deploy-waf-unattached",
                "medium",
                "No WAF on the public listener",
                "account",
                1,
                "Observed. The account snapshot says the WAF is not attached. Attachment is not evidence the WAF stops an attack.",
                "Attach a WAF to the public listener and turn on its log.",
                "observed",
            )
        )
    if snapshot.public_origin is True:
        found.append(
            _gap(
                "deploy-origin-public",
                "medium",
                "Origin is on the public listener",
                "account",
                1,
                "Observed. The account snapshot says the origin is reachable without the edge.",
                "Keep the application behind the proxy or load balancer.",
                "observed",
            )
        )
    return found


def _url_findings(
    url: str, observation: UrlObservation, existing: list[Finding]
) -> tuple[list[Finding], list[str]]:
    host = urlsplit(url).hostname or "url"
    if observation.error == "unreachable":
        return [
            _gap(
                "deploy-url-unreachable",
                "info",
                "Named URL could not be reached",
                "url",
                1,
                "Observed. The named URL was requested once and did not answer. The live headers were not observed.",
                "Confirm the host name and that this machine may open that one URL.",
                "observed",
            )
        ], []
    if observation.error == "untrusted":
        return [
            _gap(
                "deploy-certificate-untrusted",
                "high",
                "Certificate was not trusted",
                "url",
                1,
                f"Observed. The certificate presented by {host} did not verify. Verification was left on.",
                "Serve a certificate from a trusted issuer for this host name.",
                "observed",
            )
        ], []
    found: list[Finding] = []
    scheme = urlsplit(url).scheme
    location = observation.location
    if scheme == "http" and not _same_host_https(url, location):
        found.append(
            _gap(
                "deploy-listener-cleartext",
                "high",
                "Named URL did not redirect to HTTPS",
                "url",
                1,
                "Observed. One request to the named URL stayed on clear text.",
                "Redirect the public URL to HTTPS.",
                "observed",
            )
        )
    if location and not _same_host(url, location) and not _same_host_https(url, location):
        found.append(
            _gap(
                "deploy-redirect-elsewhere",
                "info",
                "Named URL redirects to another host",
                "url",
                1,
                "Observed. The named host redirected elsewhere. That host was not requested.",
                "Review the redirect target before treating it as this deployment.",
                "observed",
            )
        )
    cookie = _cookie_gap(observation.headers)
    if cookie:
        extra = ""
        if any(item.rule_id == "cookie-flag-disabled" for item in existing):
            extra = " The source report also records cookie-flag-disabled."
        found.append(
            _gap(
                "deploy-cookie-flags",
                "medium",
                "Live cookie is missing a flag",
                "url",
                1,
                f"Observed. A Set-Cookie from the named URL is missing {cookie}.{extra}",
                "Set Secure and HttpOnly on cookies the browser stores.",
                "observed",
            )
        )
    found.extend(_cert_findings(host, observation.cert))
    header_gaps, passed = _header_checks(url, observation.headers)
    found.extend(header_gaps)
    return found, passed


def _header_checks(url: str, headers: list[tuple[str, str]]) -> tuple[list[Finding], list[str]]:
    """Missing response headers are findings. Present headers are passed checks."""

    folded = {name.lower(): value.strip() for name, value in headers}
    found: list[Finding] = []
    passed: list[str] = []
    if urlsplit(url).scheme == "https":
        if folded.get("strict-transport-security", ""):
            passed.append("hsts")
        else:
            found.append(
                _gap(
                    "deploy-hsts-missing",
                    "medium",
                    "Live response has no HSTS header",
                    "url",
                    1,
                    "Observed. The HTTPS response did not send Strict-Transport-Security.",
                    "Send Strict-Transport-Security on the HTTPS response.",
                    "observed",
                )
            )
    content_type = folded.get("x-content-type-options", "")
    if content_type.lower() == "nosniff":
        passed.append("content-type-options")
    else:
        found.append(
            _gap(
                "deploy-content-type-options",
                "low",
                "Live response does not set nosniff",
                "url",
                1,
                "Observed. The response did not send X-Content-Type-Options: nosniff.",
                "Send X-Content-Type-Options: nosniff.",
                "observed",
            )
        )
    policy = folded.get("content-security-policy", "").lower()
    if folded.get("x-frame-options", "") or "frame-ancestors" in policy:
        passed.append("frame-options")
    else:
        found.append(
            _gap(
                "deploy-frame-options",
                "low",
                "Live response does not set a frame policy",
                "url",
                1,
                "Observed. The response did not send X-Frame-Options or a frame-ancestors policy.",
                "Send X-Frame-Options or a Content-Security-Policy frame-ancestors directive.",
                "observed",
            )
        )
    return found, passed


def _cert_findings(host: str, cert: dict | None) -> list[Finding]:
    if not cert:
        return []
    found: list[Finding] = []
    names = [value.lower() for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if names and not any(_name_matches(host.lower(), name) for name in names):
        found.append(
            _gap(
                "deploy-certificate-name",
                "high",
                "Certificate name does not match the host",
                "url",
                1,
                f"Observed. The certificate names do not include {host}.",
                "Serve a certificate whose name is this host.",
                "observed",
            )
        )
    not_after = cert.get("notAfter")
    if isinstance(not_after, str):
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
        except ValueError:
            expires = None
        if expires is not None and expires - datetime.now(timezone.utc) <= _CERT_SOON:
            found.append(
                _gap(
                    "deploy-certificate-expiring",
                    "medium",
                    "Certificate is expired or near expiry",
                    "url",
                    1,
                    f"Observed. The certificate for {host} expires at {expires.strftime('%Y-%m-%d')}.",
                    "Renew the certificate before it expires.",
                    "observed",
                )
            )
    return found


def _cookie_gap(headers: list[tuple[str, str]]) -> str:
    missing: list[str] = []
    saw = False
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        saw = True
        folded = value.lower()
        if "secure" not in folded:
            missing.append("Secure")
        if "httponly" not in folded:
            missing.append("HttpOnly")
    if not saw:
        return ""
    return " and ".join(dict.fromkeys(missing))


def _same_host(url: str, location: str) -> bool:
    if not location:
        return False
    left = urlsplit(url)
    right = urlsplit(location)
    if not right.hostname:
        return True
    return right.hostname.lower() == (left.hostname or "").lower()


def _same_host_https(url: str, location: str) -> bool:
    if not location:
        return False
    right = urlsplit(location)
    return right.scheme == "https" and _same_host(url, location)


def _name_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host.count(".") == pattern.count(".")
    return host == pattern


def _collect(repo: Path, deploy_dir: Path | None) -> list[tuple[str, str]]:
    roots: list[tuple[Path, Path]] = [(repo, repo)]
    if deploy_dir is not None:
        extra = deploy_dir.expanduser().resolve()
        if is_reparse_point(extra) or not extra.is_dir():
            raise UsageError("deploy directory must be a real directory")
        roots.append((extra, extra))
    seen: set[str] = set()
    found: list[tuple[str, str]] = []
    for root, label_root in roots:
        for path in _walk(root):
            key = os.path.normcase(str(path.resolve()))
            if key in seen:
                continue
            text = _read(root, path)
            if text is None or not _is_deploy_text(path, text):
                continue
            seen.add(key)
            if is_within(repo, path):
                label = path.resolve().relative_to(repo.resolve()).as_posix()
            else:
                label = "deploy/" + path.resolve().relative_to(label_root).as_posix()
            found.append((label, text))
            if len(found) >= _MAX_FILES:
                return found
    return found


def _walk(root: Path) -> list[Path]:
    paths: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if is_reparse_point(current) or not is_within(root, current):
            dirnames[:] = []
            continue
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")]
        for name in filenames:
            path = current / name
            if is_reparse_point(path) or not is_within(root, path):
                continue
            paths.append(path)
    return paths


def _is_deploy_text(path: Path, text: str) -> bool:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in {".tf", ".tf.json"} or name in _COMPOSE_NAMES:
        return True
    if name == "nginx.conf" or (suffix == ".conf" and "nginx" in str(path).lower()):
        return True
    parts = {part.lower() for part in path.parts}
    if suffix in {".yml", ".yaml"} and (parts & _EDGE_DIRS or "ingress" in name or "gateway" in name):
        return True
    if suffix in {".yml", ".yaml", ".conf"} and (_EDGE.search(text) or _WAF.search(text)):
        return True
    return False


def _read(root: Path, path: Path) -> str | None:
    if not is_within(root, path) or is_reparse_point(path) or not path.is_file():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192] or len(raw) > _MAX_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def _line_of(text: str, pattern: re.Pattern[str]) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return 1


def _gap(
    rule_id: str,
    severity: str,
    title: str,
    file: str,
    line: int,
    description: str,
    remediation: str,
    verdict: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        control_family="deployment",
        severity=severity,  # type: ignore[arg-type]
        title=title,
        file=file,
        line=max(line, 1),
        description=redact(description),
        remediation=remediation,
        confidence=0.8 if verdict == "observed" else 0.7,
        origin="deployment",
        verdict=verdict,  # type: ignore[arg-type]
    )


def _merge(
    report,
    declared: list[Finding],
    observed: list[Finding],
    account: bool,
    url: bool,
    edge_passed: list[str] | None = None,
):
    kept = [item for item in report.findings if item.control_family != "deployment"]
    fresh = [_with_case(item, {finding.case_id for finding in kept}) for item in declared + observed]
    used = {item.case_id for item in kept}
    unique: list[Finding] = []
    for item in fresh:
        current = item
        if current.case_id in used:
            current = current.model_copy(
                update={"case_id": case_id_for(current.file, current.line, current.rule_id, salt=str(current.line))}
            )
        used.add(current.case_id)
        unique.append(current)
    account_text = "The live account was compared." if account else "The live account was not observed."
    url_text = "The named URL was requested once." if url else "No URL was named."
    sentence = (
        f"Deployment review recorded {len(declared)} declared gaps and {len(observed)} observed gaps. "
        f"{account_text} {url_text}"
    )
    summary = report.summary
    if "Deployment review recorded" in summary:
        summary = summary.split("Deployment review recorded", 1)[0].rstrip()
    summary = f"{summary} {sentence}".strip()
    metrics = report.metrics.model_copy(update={"findings": len(kept) + len(unique)})
    return report.model_copy(
        update={
            "summary": redact(summary),
            "findings": kept + unique,
            "metrics": metrics,
            "edge_passed": list(edge_passed or []),
        }
    )


def _with_case(finding: Finding, used: set[str]) -> Finding:
    case_id = case_id_for(finding.file, finding.line, finding.rule_id)
    if case_id in used:
        case_id = case_id_for(finding.file, finding.line, finding.rule_id, salt="deploy")
    return finding.model_copy(update={"case_id": case_id})
