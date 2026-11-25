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


def test_certifi_fills_an_empty_system_store(monkeypatch, tmp_path):
    import ssl
    import sys
    import types

    bundle = tmp_path / "cacert.pem"
    bundle.write_text("placeholder\n", encoding="utf-8")
    module = types.ModuleType("certifi")
    module.where = lambda: str(bundle)
    monkeypatch.setitem(sys.modules, "certifi", module)

    class _Store:
        def __init__(self, count: int) -> None:
            self.verify_mode = ssl.CERT_REQUIRED
            self.check_hostname = True
            self._count = count

        def cert_store_stats(self) -> dict[str, int]:
            return {"x509_ca": self._count}

    def fake_context(cafile: str | None = None) -> _Store:
        return _Store(0 if cafile is None else 3)

    monkeypatch.setattr(ssl, "create_default_context", fake_context)
    from silentblue.supply import load_ca

    ready, note = load_ca(None)
    assert ready is True
    assert note == "ok"


def test_linux_with_no_store_names_the_system_certificates(monkeypatch):
    import sys

    from silentblue.supply import system_ca_note

    monkeypatch.setattr(sys, "platform", "linux")
    note = system_ca_note()
    assert "operating system's CA certificates" in note
    assert "certifi" in note
    assert "Leave SILENTBLUE_CA_BUNDLE unset" in note
    assert "Install Certificates.command" not in note


def test_a_mac_with_no_store_is_told_to_install_certificates(monkeypatch):
    import sys

    from silentblue.supply import system_ca_note

    monkeypatch.setattr(sys, "platform", "darwin")
    note = system_ca_note()
    assert "Install Certificates.command" in note
    assert "Leave SILENTBLUE_CA_BUNDLE unset" in note


def test_missing_ca_override_is_reported(monkeypatch, tmp_path):
    monkeypatch.setenv("SILENTBLUE_CA_BUNDLE", str(tmp_path / "missing.pem"))
    assert ca_bundle_label(None) == "missing"
    from silentblue.supply import load_ca

    ready, note = load_ca(None)
    assert ready is False
    assert "SILENTBLUE_CA_BUNDLE is not a readable CA file" in note


def test_osv_url_comes_from_the_environment(monkeypatch, tmp_path):
    from silentblue.supply import osv_endpoint, preview_advisories

    monkeypatch.setenv("SILENTBLUE_OSV_URL", "https://osv.example.test/v1/querybatch")
    monkeypatch.setenv("SILENTBLUE_CA_BUNDLE", str(tmp_path / "missing.pem"))
    url, host, source, note = osv_endpoint()
    assert url == "https://osv.example.test/v1/querybatch"
    assert host == "osv.example.test"
    assert source == "SILENTBLUE_OSV_URL"
    assert note == ""
    text = preview_advisories(tmp_path)
    assert "OSV URL: https://osv.example.test/v1/querybatch" in text
    assert "CA bundle: missing" in text
    assert "until the CA bundle loads" in text
    monkeypatch.setenv("SILENTBLUE_OSV_URL", "http://api.osv.dev/v1/querybatch")
    bad_url, _host, _source, bad_note = osv_endpoint()
    assert bad_url == ""
    assert "https://api.osv.dev/v1/querybatch" in bad_note


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
    assert f"CVSS 3.1 9.8 {_VECTOR}" in markdown
    assert "Component PyPI requests 2.32.3" in markdown
    assert "Fixed 2.32.4" in markdown
    assert "requests==2.32.4" in first["remediation"]
    assert "python -m pip install -r requirements.txt" in first["remediation"]
    assert "Do not add a proof-of-concept" in first["remediation"]
    assert "not 2.32.3" in first["remediation"]
    second = next(item for item in vulns if item["advisory_id"] == "GHSA-dddd-eeee-ffff")
    assert second["component"]["fixed_version"] == ""
    assert "does not name a fixed version" in second["remediation"]
    assert "Do not guess a version" in second["remediation"]

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


def test_fixed_version_is_the_lowest_newer_release():
    from silentblue.repair import choose_fixed, upgrade_remediation

    assert choose_fixed("2.32.3", ["1.2.0", "2.32.4", "2.33.0"]) == ("2.32.4", "")
    assert choose_fixed("2.32.3", ["1.2.0"]) == ("", "not-newer")
    assert choose_fixed("2.32.3", []) == ("", "none")
    chosen, reason = choose_fixed("1.0.0-debian", ["2.0.0"])
    assert chosen == "2.0.0"
    assert reason == "unordered"
    npm = upgrade_remediation(
        ecosystem="npm",
        name="left-pad",
        version="1.2.3",
        file="web/package-lock.json",
        line=40,
        advisory_id="GHSA-npm",
        fixed="1.3.0",
        reason="",
        fixes=["1.3.0"],
        direct=False,
    )
    assert "npm install left-pad@1.3.0 --save-exact" in npm
    assert "In web" in npm
    assert "left-pad is transitive" in npm
    assert "strict-ssl" in npm
    go = upgrade_remediation(
        ecosystem="Go",
        name="example.com/mod",
        version="v1.2.2",
        file="go.mod",
        line=4,
        advisory_id="GO-1",
        fixed="1.2.3",
        reason="",
        fixes=["1.2.3"],
        direct=True,
    )
    assert "go get example.com/mod@v1.2.3" in go
    assert "checksum database" in go
