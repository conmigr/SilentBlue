"""End-to-end detect profile scans."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from silentblue.cli import app
from silentblue.runner import run_scan

runner = CliRunner()

APP = """\
def lookup(conn, name):
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")

def safe(conn, name):
    conn.execute("SELECT * FROM users WHERE name = ?", (name,))
"""

SECRETS = """\
API_KEY = "AKIA0123456789ABCD"

password = "changeme"

password = "s3cret-value"
"""

SETTINGS = "DEBUG = True\n"
CLIENT = 'import client\nclient.get(url, verify=False)\n'
AUTH = "def login():\n    return True\n"


def _seed(repo: Path) -> None:
    (repo / "app.py").write_text(APP, encoding="utf-8")
    (repo / "secrets.py").write_text(SECRETS, encoding="utf-8")
    (repo / "settings.py").write_text(SETTINGS, encoding="utf-8")
    (repo / "client.py").write_text(CLIENT, encoding="utf-8")
    (repo / "auth.py").write_text(AUTH, encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")


def _scan(workspace, **kwargs):
    return run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        **kwargs,
    )


def _artifacts(repo: Path):
    directory = repo / "security-scan"
    findings = json.loads((directory / "findings.json").read_text(encoding="utf-8"))
    markdown = next(directory.glob("*_report.md")).read_text(encoding="utf-8")
    sarif = json.loads(next(directory.glob("*.sarif")).read_text(encoding="utf-8"))
    return findings, markdown, sarif


def test_empty_scope_exits_2_without_a_report(workspace):
    node = workspace["repo"] / "node_modules"
    node.mkdir()
    (node / "lib.py").write_text("x = 1\n", encoding="utf-8")
    result = _scan(workspace)
    assert result.exit_code == 2
    assert "empty scope" in result.message
    assert not (workspace["repo"] / "security-scan").exists()
    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert manifest["exit_code"] == 2
    assert manifest["model_calls"] == 0


def test_stop_after_d0_writes_an_empty_report(workspace):
    _seed(workspace["repo"])
    result = _scan(workspace, stop_after="d0")
    assert result.exit_code == 0
    findings, _markdown, sarif = _artifacts(workspace["repo"])
    assert findings["findings"] == []
    assert findings["metrics"]["files"] == 6
    assert findings["stages"]["d0"] == "completed"
    assert findings["stages"]["d5"] == "not_run"
    assert findings["stages"]["d9"] == "completed"
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_full_scan_reports_agree_and_redact(workspace):
    _seed(workspace["repo"])
    result = _scan(workspace, stop_after="d9")
    assert result.exit_code == 0
    assert result.finding_count >= 4
    findings, markdown, sarif = _artifacts(workspace["repo"])
    assert findings["schema_version"] == "1.1"
    assert findings["tool"] == "silentblue"
    assert findings["profile"] == "detect"
    assert findings["hollow"] is False
    assert findings["stages"]["d2"] == "skipped"
    assert findings["stages"]["d6"] == "skipped"
    assert findings["metrics"]["model_calls"] == 0
    assert findings["metrics"]["primary_language"] == "python"
    assert "pyproject.toml" in findings["metrics"]["manifests"]
    assert "auth.py" in findings["metrics"]["control_hints"]

    reported = findings["findings"]
    for index, item in enumerate(reported, start=1):
        assert item["number"] == index
        assert item["cvss_vector"].startswith("CVSS:3.1/")
        assert item["cvss_score"] is not None
        assert item["component"]["name"] == item["file"]
    assert "\n## Finding 1:" in markdown
    assert "CVSS 3.1 " in markdown
    assert "CVSS:3.1/" in markdown
    assert "\nDescription:" in markdown
    assert "\nEvidence:" in markdown
    assert "\nRemediation:" in markdown
    assert "Apply this in " in markdown
    assert "Do not add a proof-of-concept" in markdown
    assert "**CVSS:**" not in markdown
    assert list((workspace["repo"] / "security-scan").glob("*_report.yaml")) == []
    ids = [item["case_id"] for item in reported]
    assert len(ids) == len(set(ids))
    for case_id in ids:
        assert case_id.startswith("sb1_") and len(case_id) == 36
        assert case_id in markdown
    sarif_ids = [
        item["partialFingerprints"]["sbFindingId/v1"] for item in sarif["runs"][0]["results"]
    ]
    assert sarif_ids == ids
    assert markdown.count("\n## Finding ") == len(reported)

    for item in reported:
        assert item["control_family"]
        assert item["remediation"]
        assert item["file"]
        assert item["line"] >= 1
        assert item["origin"] == "detector"

    blob = json.dumps(findings) + markdown + json.dumps(sarif)
    assert "AKIA0123456789ABCD" not in blob
    assert "s3cret-value" not in blob
    safe_lines = [
        item for item in reported if 'name = ?' in item.get("snippet", "")
    ]
    assert safe_lines == []
    families = {item["control_family"] for item in reported}
    assert {"secrets", "injection", "transport", "configuration"} <= families

    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert manifest["stages"]["d5"] == "completed"
    assert manifest["stages"]["d8"] == "completed"
    assert manifest["model_calls"] == 0
    assert manifest["findings"] == len(reported)


def test_resume_uses_checkpoints_until_one_is_corrupt(workspace):
    _seed(workspace["repo"])
    first = _scan(workspace)
    assert first.exit_code == 0
    first_report, _, _ = _artifacts(workspace["repo"])
    second = _scan(workspace, resume=True)
    assert second.exit_code == 0
    second_manifest = json.loads(Path(second.manifest_path).read_text(encoding="utf-8"))
    assert second_manifest["stages"]["d0"] == "cached"
    assert second_manifest["stages"]["d8"] == "cached"
    assert second_manifest["stages"]["d9"] == "completed"
    second_report, _, _ = _artifacts(workspace["repo"])
    assert [item["case_id"] for item in second_report["findings"]] == [
        item["case_id"] for item in first_report["findings"]
    ]

    checkpoints = list((workspace["state"] / "runs").glob("*/checkpoints/d0.json"))
    assert len(checkpoints) == 1
    checkpoints[0].write_text("{", encoding="utf-8")
    third = _scan(workspace, resume=True)
    assert third.exit_code == 0
    third_manifest = json.loads(Path(third.manifest_path).read_text(encoding="utf-8"))
    assert third_manifest["stages"]["d0"] == "completed"
    third_report, _, _ = _artifacts(workspace["repo"])
    assert [item["case_id"] for item in third_report["findings"]] == [
        item["case_id"] for item in first_report["findings"]
    ]


def test_config_inside_the_repository_is_refused(workspace):
    _seed(workspace["repo"])
    config = workspace["repo"] / "config.yaml"
    config.write_text("profile: detect\n", encoding="utf-8")
    result = _scan(workspace, config_path=config)
    assert result.exit_code == 2
    assert "config must live outside" in result.message


def test_cli_estimate_and_scan(workspace):
    _seed(workspace["repo"])
    repo = str(workspace["repo"])
    state = str(workspace["state"])
    manifests = str(workspace["manifests"])
    estimated = runner.invoke(
        app,
        ["estimate", "--repo", repo],
    )
    assert estimated.exit_code == 0
    assert "model_calls: 0" in estimated.stdout
    assert "files: 6" in estimated.stdout

    scanned = runner.invoke(
        app,
        [
            "scan",
            "--repo",
            repo,
            "--state-dir",
            state,
            "--manifest-dir",
            manifests,
            "--stop-after",
            "d9",
        ],
    )
    assert scanned.exit_code == 0
    assert "findings:" in scanned.stdout
    assert (workspace["repo"] / "security-scan" / "findings.json").is_file()

    doctor = runner.invoke(
        app,
        ["doctor", "--state-dir", str(workspace["root"] / "doctor-state")],
    )
    assert doctor.exit_code == 0
    assert "model_calls: 0" in doctor.stdout
    assert "config: ok (detect)" in doctor.stdout
    assert "Provider:" in doctor.stdout
    assert "Endpoint:" in doctor.stdout
    assert "This check does not call the model." in doctor.stdout
