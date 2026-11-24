"""SARIF ingest keeps case ids and refuses paths outside the repository."""

from __future__ import annotations

import json

from silentblue.ingest import run_ingest
from silentblue.remediate import run_remediate
from silentblue.runner import run_scan
from tests.conftest import link_directory
from tests.test_remediate import SOURCE

SECRET = 'password = "outside-secret-value"\n'


def _sarif(results: list[dict]) -> dict:
    return {"version": "2.1.0", "runs": [{"results": results}]}


def _result(uri: str, line: int, rule: str = "imported-rule", level: str = "warning") -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": "A control is missing."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def test_round_trip_keeps_case_ids_and_leaves_source(workspace):
    source = workspace["repo"] / "app.py"
    source.write_text(SOURCE, encoding="utf-8")
    before = source.read_bytes()
    scanned = run_scan(
        repo=workspace["repo"],
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert scanned.exit_code == 0
    original = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    sarif_path = next((workspace["repo"] / "security-scan").glob("*_report.sarif"))
    result = run_ingest(
        repo=workspace["repo"],
        sarif=sarif_path,
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 0
    assert result.model_calls == 0
    assert source.read_bytes() == before
    imported = json.loads((workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert [item["case_id"] for item in imported["findings"]] == [item["case_id"] for item in original["findings"]]
    assert imported["findings"][0]["origin"] == "imported"
    assert imported["findings"][0]["verdict"] == "imported"
    assert imported["findings"][0]["rule_id"] == "sql-unparameterized"
    assert imported["findings"][0]["file"] == "app.py"
    assert imported["findings"][0]["line"] == 2
    assert imported["metrics"]["model_calls"] == 0
    assert "makes no model calls" in imported["summary"]


def test_paths_outside_the_repository_are_not_opened(workspace):
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    outside = workspace["root"] / "outside.py"
    outside.write_text(SECRET, encoding="utf-8")
    sarif_path = workspace["root"] / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            _sarif(
                [
                    _result(outside.resolve().as_uri(), 1),
                    _result("../outside.py", 1),
                    _result("app.py", 1),
                ]
            )
        ),
        encoding="utf-8",
    )
    result = run_ingest(repo=workspace["repo"], sarif=sarif_path, manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    assert result.finding_count == 1
    assert result.dropped_count == 2
    report_text = (workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8")
    assert "outside-secret-value" not in report_text
    report = json.loads(report_text)
    assert report["findings"][0]["file"] == "app.py"
    assert report["findings"][0]["verdict"] == "imported"
    assert [item["reason"] for item in report["dropped"]] == ["outside_root", "outside_root"]


def test_junction_target_is_not_opened(workspace):
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    outside = workspace["root"] / "linked-src"
    outside.mkdir()
    (outside / "evil.py").write_text(SECRET, encoding="utf-8")
    link_directory(workspace["repo"] / "linked", outside)
    sarif_path = workspace["root"] / "results.sarif"
    sarif_path.write_text(
        json.dumps(_sarif([_result("linked/evil.py", 1), _result("app.py", 1)])),
        encoding="utf-8",
    )
    result = run_ingest(repo=workspace["repo"], sarif=sarif_path, manifest_dir=workspace["manifests"])
    assert result.exit_code == 0
    report_text = (workspace["repo"] / "security-scan" / "findings.json").read_text(encoding="utf-8")
    assert "outside-secret-value" not in report_text
    report = json.loads(report_text)
    assert [item["file"] for item in report["findings"]] == ["app.py"]
    assert any(item["reason"] == "outside_root" for item in report["dropped"])


def test_invalid_sarif_writes_no_report(workspace):
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    sarif_path = workspace["root"] / "results.sarif"
    sarif_path.write_text("not json", encoding="utf-8")
    result = run_ingest(repo=workspace["repo"], sarif=sarif_path, manifest_dir=workspace["manifests"])
    assert result.exit_code == 2
    assert not (workspace["repo"] / "security-scan").exists()


def test_imported_findings_are_not_remediated(workspace):
    (workspace["repo"] / "app.py").write_text("value = 1\n", encoding="utf-8")
    sarif_path = workspace["root"] / "results.sarif"
    sarif_path.write_text(json.dumps(_sarif([_result("app.py", 1)])), encoding="utf-8")
    ingested = run_ingest(repo=workspace["repo"], sarif=sarif_path, manifest_dir=workspace["manifests"])
    assert ingested.exit_code == 0

    class Boom:
        def complete(self, system: str, user: str) -> str:
            raise AssertionError("model was called")

    result = run_remediate(
        repo=workspace["repo"],
        manifest_dir=workspace["manifests"],
        client=Boom(),
    )
    assert result.exit_code == 0
    assert result.case_count == 0
    assert not (workspace["repo"] / "security-remediation").exists()


def test_sarif_directory_is_refused(workspace):
    result = run_ingest(
        repo=workspace["repo"],
        sarif=workspace["root"],
        manifest_dir=workspace["manifests"],
    )
    assert result.exit_code == 2
