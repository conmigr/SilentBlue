"""HTML, PDF, and YAML are projections of the same typed report."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import yaml

from silentblue.models import FinalReport, Finding, Metrics
from silentblue.report import render_html, render_markdown, render_pdf, write_report


def _report() -> FinalReport:
    return FinalReport(
        version="0.5.0",
        repo_name="sample",
        profile="detect",
        stop_after="d9",
        generated_at="2026-11-18T00:00:00Z",
        summary="Scanned sample.",
        stages={"d9": "completed"},
        metrics=Metrics(
            files=1,
            bytes=10,
            languages={"python": 1},
            primary_language="python",
            manifests=[],
            control_hints=[],
            findings=1,
            dropped=0,
            estimated_cost_usd=0.0,
            actual_cost_usd=0.0,
            price_date="2026-11-18",
        ),
        findings=[
            Finding(
                case_id="sb1_" + "ab" * 16,
                rule_id="sql-unparameterized",
                control_family="injection",
                severity="high",
                title="SQL <built>",
                file="app.py",
                line=2,
                description="The query is assembled.",
                remediation="Use a bound parameter.",
                snippet='conn.execute("SELECT " + name)',
                confidence=0.7,
            )
        ],
        dropped=[],
    )


def test_html_escapes_text_and_states_the_cost():
    html = render_html(_report())
    assert "SQL &lt;built&gt;" in html
    assert "<script" not in html
    assert "<dt>Estimated cost USD:</dt><dd>0.0000</dd>" in html
    assert "<dt>Severity:</dt><dd>high</dd>" in html
    assert "<dt>File:</dt><dd>app.py</dd>" in html
    assert "<dt>Line:</dt><dd>2</dd>" in html
    assert "<h3>Description:</h3>" in html
    assert "<h3>Evidence:</h3>" in html
    assert "<h3>Remediation:</h3>" in html
    assert "CVSS." not in html
    assert "http://" not in html
    assert "https://" not in html


def test_markdown_uses_labeled_findings():
    markdown = render_markdown(_report())
    assert "## Finding 1: SQL <built>" in markdown
    assert "Severity: high" in markdown
    assert "File: app.py" in markdown
    assert "Line: 2" in markdown
    assert "Description:\nThe query is assembled." in markdown
    assert "Evidence:\n    conn.execute" in markdown
    assert "Remediation:\nUse a bound parameter." in markdown
    assert "Component:" not in markdown


def test_pdf_is_a_real_document():
    payload = render_pdf(_report())
    assert payload.startswith(b"%PDF-1.4")
    assert b"%%EOF" in payload
    assert b"sql-unparameterized" in payload


def test_format_selection_writes_only_the_requested_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    when = datetime(2026, 11, 18, tzinfo=timezone.utc)
    write_report(_report(), repo, "security-scan", when, formats={"html", "pdf"})
    directory = repo / "security-scan"
    assert list(directory.glob("*_report.html"))
    assert list(directory.glob("*_report.pdf"))
    assert not (directory / "findings.json").exists()
    assert list(directory.glob("*_report.md")) == []
    assert list(directory.glob("*_report.yaml")) == []


def test_yaml_matches_findings_json(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    when = datetime(2026, 11, 18, tzinfo=timezone.utc)
    write_report(_report(), repo, "security-scan", when, formats={"json", "yaml"})
    directory = repo / "security-scan"
    loaded = yaml.safe_load(next(directory.glob("*_report.yaml")).read_text(encoding="utf-8"))
    raw = json.loads((directory / "findings.json").read_text(encoding="utf-8"))
    assert loaded == raw


def test_default_formats_omit_yaml(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    when = datetime(2026, 11, 18, tzinfo=timezone.utc)
    write_report(_report(), repo, "security-scan", when)
    directory = repo / "security-scan"
    assert (directory / "findings.json").is_file()
    assert list(directory.glob("*_report.yaml")) == []
    assert list(directory.glob("*_report.md"))
