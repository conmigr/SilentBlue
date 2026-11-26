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
    assert "The estimated cost is 0.0000 USD." in html
    assert "SilentBlue sample Assessment" in html
    assert "sam-1" in html
    assert "rule sql-unparameterized, at app.py:2" in html
    assert "<strong>Description:</strong>" in html
    assert "<strong>Why it matters:</strong>" in html
    assert "<strong>Impact:</strong>" in html
    assert "<strong>Evidence:</strong>" in html
    assert "<strong>Remediation:</strong>" in html
    assert "#4f7db0" in html
    assert "#e8f0f7" in html
    assert "SilentBlue version 0.5.0 Assessment 2026-11-18" in html
    assert "http://" not in html
    assert "https://" not in html


def test_markdown_uses_labeled_findings():
    markdown = render_markdown(_report())
    assert "# SilentBlue sample Assessment" in markdown
    assert "## sam-1" in markdown
    assert "SQL <built>" in markdown
    assert "## Summary" in markdown
    assert "## Index" in markdown
    assert "| **#** | **Severity** | **CVSS** | **Rule** | **Title** |" in markdown
    assert "## Record" in markdown
    assert "**Description:** The query is assembled." in markdown
    assert "**Why it matters:**" in markdown
    assert "**Impact:**" in markdown
    assert "```app.py\nconn.execute" in markdown
    assert "**Remediation:** Use a bound parameter." in markdown
    assert "SilentBlue version 0.5.0 Assessment 2026-11-18" in markdown
    assert "Findings are candidates" not in markdown


def test_pdf_is_a_real_document():
    payload = render_pdf(_report())
    assert payload.startswith(b"%PDF-1.4")
    assert b"%%EOF" in payload
    assert b"sql-unparameterized" in payload
    assert b"Helvetica-Bold" in payload
    assert b"Courier" in payload
    assert b"SilentBlue sample Assessment" in payload
    assert b"SilentBlue version 0.5.0 Assessment 2026-11-18" in payload


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
