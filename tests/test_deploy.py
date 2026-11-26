"""Deployment review reads declared files and one named URL."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from silentblue.deploy import UrlObservation, _url_findings, run_deploy
from silentblue.runner import run_scan
from silentblue.session import run_session
from tests.conftest import link_directory


def _ready(workspace) -> None:
    (workspace["repo"] / "app.py").write_text(
        'def read_user(conn, name):\n    conn.execute("SELECT " + name)\n',
        encoding="utf-8",
    )
    run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )


def _rules(workspace) -> set[str]:
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    return {item["rule_id"] for item in report["findings"] if item["control_family"] == "deployment"}


def test_declared_edge_records_cleartext_admin_and_waf(workspace):
    _ready(workspace)
    infra = workspace["repo"] / "infra"
    infra.mkdir()
    (infra / "main.tf").write_text(
        "\n".join(
            [
                'resource "aws_security_group_rule" "ssh" {',
                "  from_port = 22",
                "  to_port = 22",
                '  cidr_blocks = ["0.0.0.0/0"]',
                "}",
                'resource "aws_lb_listener" "web" {',
                '  protocol = "HTTP"',
                "  port = 80",
                "  default_action { type = \"forward\" }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    result = run_deploy(repo=workspace["repo"], manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert _rules(workspace) == {
        "deploy-listener-cleartext",
        "deploy-admin-exposed",
        "deploy-waf-unattached",
    }


def test_https_listener_with_a_waf_stays_quiet(workspace):
    _ready(workspace)
    nginx = workspace["repo"] / "nginx"
    nginx.mkdir()
    (nginx / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  waf on;\n  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n}\n",
        encoding="utf-8",
    )
    result = run_deploy(repo=workspace["repo"], manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert result.declared_count == 0
    assert _rules(workspace) == set()


def test_forwarded_header_and_published_data_port(workspace):
    _ready(workspace)
    proxy = workspace["repo"] / "proxy"
    proxy.mkdir()
    (proxy / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  waf on;\n  proxy_set_header X-Forwarded-For $http_x_forwarded_for;\n}\n",
        encoding="utf-8",
    )
    (workspace["repo"] / "compose.yml").write_text('services:\n  db:\n    ports:\n      - "3306:3306"\n', encoding="utf-8")
    result = run_deploy(repo=workspace["repo"], manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert _rules(workspace) == {"deploy-forwarded-header", "deploy-admin-exposed"}


def test_snapshot_outside_the_repo_is_observed_and_inside_is_refused(workspace, tmp_path):
    _ready(workspace)
    (workspace["repo"] / "infra").mkdir()
    (workspace["repo"] / "infra" / "main.tf").write_text(
        'resource "aws_lb_listener" "web" {\n  protocol = "HTTPS"\n  port = 443\n}\nresource "aws_wafv2_web_acl_association" "edge" {}\n',
        encoding="utf-8",
    )
    snapshot = tmp_path / "account.json"
    snapshot.write_text(
        json.dumps({"rules": [{"port": 22, "cidr": "0.0.0.0/0"}], "waf_attached": True}),
        encoding="utf-8",
    )
    result = run_deploy(repo=workspace["repo"], snapshot=snapshot, manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert result.account_observed is True
    assert "deploy-admin-exposed" in _rules(workspace)
    report = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    observed = [item for item in report["findings"] if item["verdict"] == "observed"]
    assert observed and observed[0]["origin"] == "deployment"
    inside = workspace["repo"] / "account.json"
    inside.write_text(snapshot.read_text(encoding="utf-8"), encoding="utf-8")
    refused = run_deploy(repo=workspace["repo"], snapshot=inside, manifest_dir=workspace["manifests"])
    assert refused.exit_code == 2


def test_named_url_is_requested_once(workspace):
    _ready(workspace)
    hits = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits["count"] += 1
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=1")
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_deploy(
            repo=workspace["repo"],
            url=f"http://127.0.0.1:{port}/",
            manifest_dir=workspace["manifests"],
        )
    finally:
        server.shutdown()
    assert result.exit_code == 0
    assert hits["count"] == 1
    assert "deploy-listener-cleartext" in _rules(workspace)
    assert "deploy-cookie-flags" in _rules(workspace)


def test_missing_security_headers_are_observed_and_present_headers_pass():
    from silentblue.deploy import _header_checks

    missing, passed = _header_checks("https://app.example", [("Content-Type", "text/html")])
    assert {item.rule_id for item in missing} == {
        "deploy-hsts-missing",
        "deploy-content-type-options",
        "deploy-frame-options",
    }
    assert passed == []
    present, ok = _header_checks(
        "https://app.example",
        [
            ("Strict-Transport-Security", "max-age=60"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ],
    )
    assert present == []
    assert ok == ["hsts", "content-type-options", "frame-options"]


def test_a_closed_authorization_does_not_match():
    from datetime import datetime, timezone

    from silentblue.deploy import DeployAuthorization, authorization_allows

    record = DeployAuthorization(
        host="app.example",
        confirmed_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-01T00:10:00Z",
    )
    now = datetime(2026, 11, 25, tzinfo=timezone.utc)
    assert authorization_allows(record, "app.example", now) is False
    assert authorization_allows(record, "other.example", datetime(2020, 1, 1, tzinfo=timezone.utc)) is False


def test_untrusted_certificate_is_a_candidate():
    found, passed = _url_findings(
        "https://app.example",
        UrlObservation(error="untrusted", final_scheme="https"),
        [],
    )
    assert found[0].rule_id == "deploy-certificate-untrusted"
    assert passed == []


def test_a_linked_directory_does_not_contribute(workspace, tmp_path):
    _ready(workspace)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf").write_text(
        'resource "aws_security_group_rule" "ssh" {\n  from_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n',
        encoding="utf-8",
    )
    link_directory(workspace["repo"] / "infra", outside)
    result = run_deploy(repo=workspace["repo"], manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert "deploy-admin-exposed" not in _rules(workspace)
    assert "deploy-origin-public" in _rules(workspace)


def test_deploy_waits_for_yes(workspace):
    source = 'def lookup(conn, name):\n    conn.execute("SELECT " + name)\n'
    (workspace["repo"] / "app.py").write_text(source, encoding="utf-8")
    pending = iter(["/deploy", "no", "/deploy", "yes", "/findings", "/quit"])
    output: list[str] = []
    code = run_session(
        workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        reader=lambda: next(pending),
        writer=output.append,
    )
    text = "\n".join(output)
    assert code == 0
    assert "Cancelled." in text
    assert "deployment files  " in text
    assert "account  not observed" in text
    assert "deploy-origin-public" in text
