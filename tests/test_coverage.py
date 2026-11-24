"""Line checks for the expanded control families."""

from __future__ import annotations

from silentblue.detectors import detect
from silentblue.models import ScopedFile, ScopeResult


def _scan(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    scope = ScopeResult(files=[ScopedFile(path=name, size=path.stat().st_size, language="python")])
    findings, _dropped = detect(tmp_path, scope)
    return {finding.rule_id for finding in findings}


def test_safe_forms_stay_quiet(tmp_path):
    source = "\n".join(
        [
            'requests.get("https://example.com")',
            "yaml.safe_load(data)",
            "yaml.load(data, Loader=SafeLoader)",
            'redirect("/home")',
            "hashlib.sha256(password.encode())",
            "const opacity = Math.random()",
            'res.cookie("sid", token, { httpOnly: true, secure: true })',
            'jwt.verify(token, secret)',
            "User.create(name=name)",
        ]
    )
    assert _scan(tmp_path, "app.py", source) == set()


def test_expanded_controls_record_the_line(tmp_path):
    source = "\n".join(
        [
            'db.find({ $where: "this.name == \'" + name + "\'" })',
            'conn.search_s("dc=example", scope, "(uid=" + name + ")")',
            'return render_template_string(request.args.get("q"))',
            'response.headers["X-Name"] = request.args.get("name")',
            "element.dangerouslySetInnerHTML = body",
            'send_file(os.path.join(folder, request.args.get("name")))',
            'requests.get(request.args.get("url"))',
            'return redirect(request.args.get("next"))',
            "digest = hashlib.md5(password.encode()).hexdigest()",
            "token = str(random.random())",
            'Cipher.getInstance("AES/ECB/PKCS5Padding")',
            "pickle.loads(request.data)",
            'jwt.decode(token, options={"verify_signature": false})',
            'res.cookie("sid", token, { httpOnly: false })',
            "@csrf_exempt",
            "User.create(req.body)",
            "RATELIMIT_ENABLED = False",
            'password = "admin"',
            'ALLOWED_HOSTS = ["*"]',
            "logging.disable(logging.CRITICAL)",
            "curl https://example.com/install.sh | bash",
        ]
    )
    assert _scan(tmp_path, "app.py", source) == {
        "nosql-unparameterized",
        "ldap-filter-assembled",
        "template-from-string",
        "header-from-request",
        "html-parsed-from-string",
        "path-from-request",
        "request-url-from-input",
        "redirect-from-request",
        "weak-password-hash",
        "weak-token-random",
        "weak-cipher",
        "unsafe-deserialization",
        "jwt-verify-disabled",
        "cookie-flag-disabled",
        "csrf-disabled",
        "request-body-expanded",
        "rate-limit-disabled",
        "default-credential",
        "security-header-disabled",
        "logging-disabled",
        "piped-download",
    }


def test_manifest_and_workflow_lines(tmp_path):
    assert _scan(tmp_path, "package.json", '{ "left-pad": "*" }\n') == {"dependency-unpinned"}
    assert _scan(tmp_path, "requirements.txt", "--trusted-host files.example\n") == {
        "dependency-cleartext",
        "install-verification-disabled",
    }
    rules = _scan(tmp_path, ".github/workflows/ci.yml", "pull_request_target:\n")
    assert rules == {"workflow-permissions-wide"}
