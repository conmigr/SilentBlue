"""Detector behavior on small source samples."""

from __future__ import annotations

from silentblue.detectors import detect
from silentblue.models import ScopedFile, ScopeResult


def _scan(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    scope = ScopeResult(
        files=[ScopedFile(path=name, size=path.stat().st_size, language="python")]
    )
    findings, _dropped = detect(tmp_path, scope)
    return findings


def test_parameterized_sql_and_comments_are_quiet(tmp_path):
    findings = _scan(
        tmp_path,
        "app.py",
        "\n".join(
            [
                "def safe(conn, name):",
                '    conn.execute("SELECT * FROM users WHERE name = ?", (name,))',
                '    # conn.execute("SELECT " + name)',
                "    return name",
                "",
            ]
        ),
    )
    assert findings == []


def test_sql_closes_a_bound_value_a_fixed_clause_and_a_non_database_call(tmp_path):
    findings = _scan(
        tmp_path,
        "app.py",
        "\n".join(
            [
                'agent.query(f"SELECT {name}")',
                'print(f"Test 1: {query}")',
                'conn.execute("SELECT * FROM users WHERE company LIKE %s", (f"%{company}",))',
                'conn.execute("SELECT * FROM t WHERE id = %s " + "AND active = 1", {"id": user_id})',
                'conn.execute("INSERT INTO t " + clause)',
                'conn.execute("INSERT INTO t " + clause)',
                'conn.execute("SELECT " + name)',
                "",
            ]
        ),
    )
    sql = [item for item in findings if item.rule_id == "sql-unparameterized"]
    assert len(sql) == 2
    confirmed = [item for item in sql if item.verdict == "detector"]
    unsettled = [item for item in sql if item.verdict == "inconclusive"]
    assert len(confirmed) == 1
    assert confirmed[0].line == 7
    assert len(unsettled) == 1
    assert unsettled[0].also_at == [6]


def test_a_live_secret_stays_and_a_fixture_closes(tmp_path):
    findings = _scan(
        tmp_path,
        "test_smoke.py",
        "\n".join(
            [
                'password = "smoke-test"',
                'api_key = "AKIAIOSFODNN7EXAMPLE"',
                "",
            ]
        ),
    )
    assert [item.line for item in findings] == [2]
    assert findings[0].rule_id == "hardcoded-secret"


def test_identical_copies_are_one_finding(tmp_path):
    source = 'conn.execute("SELECT " + name)\n'
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / "backups").mkdir()
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / "app.py").write_text(source, encoding="utf-8")
    from silentblue.models import ScopedFile, ScopeResult
    from silentblue.detectors import detect

    scope = ScopeResult(
        files=[
            ScopedFile(path="pkg/app.py", size=len(source), language="python"),
            ScopedFile(path="app.py", size=len(source), language="python"),
        ]
    )
    findings, _dropped = detect(tmp_path, scope)
    sql = [item for item in findings if item.rule_id == "sql-unparameterized"]
    assert len(sql) == 1
    assert sql[0].file == "app.py"
    assert sql[0].also_in == ["pkg/app.py"]


def test_mirror_directories_are_not_scanned(tmp_path):
    from silentblue.scope import collect_scope
    from silentblue.models import ScopeConfig

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "requirements.txt").write_text("requests==1\n", encoding="utf-8")
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "requirements.txt").write_text("requests==1\n", encoding="utf-8")
    scope = collect_scope(tmp_path, ScopeConfig())
    assert [item.path for item in scope.files] == ["app.py"]
    assert ".claude" in scope.mirror_dirs
    assert "backups" in scope.mirror_dirs


def test_secret_placeholder_is_skipped(tmp_path):
    findings = _scan(
        tmp_path,
        "app.py",
        'password = "changeme"\npassword = "s3cret-value"\n',
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "hardcoded-secret"
    assert findings[0].line == 2
    assert "s3cret-value" not in findings[0].snippet
    assert findings[0].remediation
    assert findings[0].control_family == "secrets"


def test_shell_eval_tls_and_cors(tmp_path):
    source = "\n".join(
        [
            'os.system(f"rm {target}")',
            "subprocess.run(cmd, shell=True)",
            "eval(request.data)",
            "eval('1+1')",
            'client.get(url, verify=False)',
            'allow_origins = ["*"]',
        ]
    )
    findings = _scan(tmp_path, "app.py", source)
    rules = {finding.rule_id for finding in findings}
    assert rules == {
        "shell-command",
        "shell-enabled",
        "dynamic-eval",
        "tls-verify-disabled",
        "cors-wildcard",
    }
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["dynamic-eval"].line == 3
    assert all(finding.remediation for finding in findings)


def test_browser_token_log_and_html_sinks(tmp_path):
    source = "\n".join(
        [
            "localStorage.setItem('authToken', token);",
            "- Do not store tokens in localStorage if avoidable.",
            "console.log('No token found, skipping validation.');",
            "console.log('Token available:', !!token);",
            "console.log('main token from localStorage:', token);",
            "const page = document.getElementById('results').innerHTML;",
            "newWindow.document.write(`<h1>${title}</h1>`);",
            "element.innerHTML = '<p>Ready</p>';",
            "execSync(`tar ${name}`);",
            "agent = new https.Agent({ rejectUnauthorized: false });",
        ]
    )
    findings = _scan(tmp_path, "useAuth.js", source)
    rules = {finding.rule_id for finding in findings}
    assert rules == {
        "token-in-web-storage",
        "credential-logged",
        "html-parsed-from-string",
        "shell-command",
        "tls-verify-disabled",
    }
    logged = [finding for finding in findings if finding.rule_id == "credential-logged"]
    assert len(logged) == 1
    assert logged[0].line == 5
    assert all(finding.remediation for finding in findings)
