"""Pin, install, CA bundle, and OSV advisory checks."""

from __future__ import annotations

import json

from silentblue.detectors import detect
from silentblue.models import ScopedFile, ScopeResult
from silentblue.runner import run_scan
from silentblue.supply import ca_bundle_label, cvss_v3_score

_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _rules(tmp_path, name: str, source: str, extra: dict[str, str] | None = None) -> set[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    files = [ScopedFile(path=name.replace("\\", "/"), size=path.stat().st_size, language="text")]
    for extra_name, extra_source in (extra or {}).items():
        extra_path = tmp_path / extra_name
        extra_path.parent.mkdir(parents=True, exist_ok=True)
        extra_path.write_text(extra_source, encoding="utf-8")
        files.append(
            ScopedFile(
                path=extra_name.replace("\\", "/"),
                size=extra_path.stat().st_size,
                language="text",
            )
        )
    findings, _dropped = detect(tmp_path, ScopeResult(files=files))
    return {finding.rule_id for finding in findings}


def test_cvss_v3_base_score_is_9_8():
    assert cvss_v3_score(_VECTOR) == 9.8


def test_every_rule_vector_matches_its_score():
    from silentblue.supply import _BY_RULE, _BY_SEVERITY, cvss_for

    for rule_id, (score, vector) in _BY_RULE.items():
        assert cvss_v3_score(vector) == score
        assert cvss_for(rule_id, "low") == (score, vector)
    for severity, (score, vector) in _BY_SEVERITY.items():
        assert cvss_v3_score(vector) == score
        assert cvss_for("unlisted-rule", severity) == (score, vector)


def test_exact_pins_stay_quiet_and_ranges_are_flagged(tmp_path):
    assert "dependency-unpinned" not in _rules(tmp_path, "requirements.txt", "requests==2.32.3\n")
    assert _rules(tmp_path, "requirements.txt", "requests>=2\n") == {"dependency-unpinned"}
    package = json.dumps({"dependencies": {"left-pad": "1.2.3"}})
    assert "dependency-unpinned" not in _rules(tmp_path, "package.json", package)
    ranged = json.dumps({"dependencies": {"left-pad": "^1.2.3"}})
    assert _rules(tmp_path, "package.json", ranged) == {"dependency-unpinned"}


def test_lockfile_suppresses_the_pin_finding(tmp_path):
    poetry = '[[package]]\nname = "requests"\nversion = "2.32.3"\n'
    assert "dependency-unpinned" not in _rules(
        tmp_path,
        "requirements.txt",
        "requests>=2\n",
        {"poetry.lock": poetry},
    )
    lock = json.dumps({"packages": {"node_modules/left-pad": {"version": "1.2.3"}}})
    ranged = json.dumps({"dependencies": {"left-pad": "^1.2.3"}})
    assert "dependency-unpinned" not in _rules(
        tmp_path,
        "package.json",
        ranged,
        {"package-lock.json": lock},
    )


def test_install_verification_and_ca_bundle(tmp_path):
    docker = "RUN curl https://example.com/install.sh -k\nENV SSL_CERT_FILE=certs/ca.pem\n"
    assert _rules(tmp_path, "Dockerfile", docker) == {
        "install-verification-disabled",
        "ca-bundle-missing",
    }
    present = tmp_path / "certs"
    present.mkdir()
    (present / "ca.pem").write_text("bundle", encoding="utf-8")
    docker_ok = "ENV SSL_CERT_FILE=certs/ca.pem\n"
    assert "ca-bundle-missing" not in _rules(tmp_path, "Dockerfile", docker_ok)
    assert "ca-bundle-missing" not in _rules(
        tmp_path,
        "Dockerfile",
        "ENV SSL_CERT_FILE=/etc/ssl/cert.pem\n",
    )


def test_missing_ca_override_is_reported(monkeypatch, tmp_path):
    monkeypatch.setenv("SILENTBLUE_CA_BUNDLE", str(tmp_path / "missing.pem"))
    assert ca_bundle_label(None) == "missing"


def test_osv_fills_cvss_and_a_failed_query_exits_1(workspace, monkeypatch):
    monkeypatch.setattr("silentblue.supply.load_ca", lambda repo: (True, "ok"))
    repo = workspace["repo"]
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")

    def fetch(payload, _context):
        assert payload["queries"][0]["package"] == {"name": "requests", "ecosystem": "PyPI"}
        assert payload["queries"][0]["version"] == "2.32.3"
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "summary": "Example advisory.",
                            "aliases": ["CVE-2024-0001"],
                            "severity": [{"type": "CVSS_V3", "score": _VECTOR}],
                            "affected": [
                                {
                                    "package": {"name": "requests", "ecosystem": "PyPI"},
                                    "ranges": [{"events": [{"fixed": "2.32.4"}]}],
                                }
                            ],
                        },
                        {
                            "id": "GHSA-dddd-eeee-ffff",
                            "summary": "Second advisory.",
                            "severity": [{"type": "CVSS_V3", "score": "4.0"}],
                        },
                    ]
                }
            ]
        }

    result = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=fetch,
    )
    assert result.exit_code == 0
    report = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.1"
    assert report["advisories"] == "queried"
    vulns = [item for item in report["findings"] if item["rule_id"] == "dependency-vulnerable"]
    assert len(vulns) == 2
    assert len({item["case_id"] for item in vulns}) == 2
    first = next(item for item in vulns if item["advisory_id"] == "GHSA-aaaa-bbbb-cccc")
    assert first["cvss_score"] == 9.8
    assert first["cvss_vector"] == _VECTOR
    assert first["cvss_version"] == "3.1"
    assert first["severity"] == "critical"
    assert first["component"]["purl"] == "pkg:pypi/requests@2.32.3"
    assert first["component"]["fixed_version"] == "2.32.4"
    assert first["component"]["relationship"] == "direct"
    markdown = next((repo / "security-scan").glob("*_report.md")).read_text(encoding="utf-8")
    assert "CVSS score: 9.8" in markdown
    assert "CVSS version: 3.1" in markdown
    assert f"CVSS vector: {_VECTOR}" in markdown
    assert "Component: PyPI requests 2.32.3" in markdown
    assert "Package URL: pkg:pypi/requests@2.32.3" in markdown
    assert "Fixed: 2.32.4" in markdown

    def fail(_payload, _context):
        raise OSError("down")

    failed = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=fail,
    )
    assert failed.exit_code == 1
    again = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert again["advisories"] == "degraded"


def test_unpinned_packages_are_not_sent(workspace, monkeypatch):
    monkeypatch.setattr("silentblue.supply.load_ca", lambda repo: (True, "ok"))
    repo = workspace["repo"]
    (repo / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")

    def fetch(_payload, _context):
        raise AssertionError("unpinned package was queried")

    result = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=fetch,
    )
    assert result.exit_code == 0
    report = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["advisories"] == "queried"
    assert any(item["rule_id"] == "dependency-unpinned" for item in report["findings"])
    assert not any(item["rule_id"] == "dependency-vulnerable" for item in report["findings"])


def _advisory_fetch(_payload, _context):
    return {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-aaaa-bbbb-cccc",
                        "summary": "Example advisory.",
                        "severity": [{"type": "CVSS_V3", "score": _VECTOR}],
                    }
                ]
            }
        ]
    }


def test_opening_scan_keeps_osv_rows_when_the_packages_match(workspace, monkeypatch):
    monkeypatch.setattr("silentblue.supply.load_ca", lambda repo: (True, "ok"))
    repo = workspace["repo"]
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    queried = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=_advisory_fetch,
    )
    assert queried.exit_code == 0
    stored = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert len(stored["advisory_fingerprint"]) == 64
    kept = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        retain_advisories=True,
    )
    assert kept.exit_code == 0
    assert "Kept from the last OSV query" in kept.message
    report = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["advisories"] == "queried"
    assert any(item["advisory_id"] == "GHSA-aaaa-bbbb-cccc" for item in report["findings"])
    replaced = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
    )
    assert replaced.exit_code == 0
    dropped = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert dropped["advisories"] == "off"
    assert not any(item["rule_id"] == "dependency-vulnerable" for item in dropped["findings"])


def test_opening_scan_drops_osv_rows_when_the_packages_change(workspace, monkeypatch):
    monkeypatch.setattr("silentblue.supply.load_ca", lambda repo: (True, "ok"))
    repo = workspace["repo"]
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=_advisory_fetch,
    )
    (repo / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
    kept = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        retain_advisories=True,
    )
    assert "resolved packages changed" in kept.message
    report = json.loads((repo / "security-scan" / "findings.json").read_text(encoding="utf-8"))
    assert report["advisories"] == "off"
    assert not any(item["rule_id"] == "dependency-vulnerable" for item in report["findings"])


def test_opening_scan_drops_osv_rows_when_the_package_set_was_not_recorded(workspace, monkeypatch):
    monkeypatch.setattr("silentblue.supply.load_ca", lambda repo: (True, "ok"))
    repo = workspace["repo"]
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        osv=True,
        advisory_fetch=_advisory_fetch,
    )
    path = repo / "security-scan" / "findings.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["advisory_fingerprint"] = ""
    path.write_text(json.dumps(stored), encoding="utf-8")
    kept = run_scan(
        repo=repo,
        state_dir=workspace["state"],
        manifest_dir=workspace["manifests"],
        retain_advisories=True,
    )
    assert "did not record the package set" in kept.message
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["advisories"] == "off"
