"""The assessment reading copy shared by Markdown, HTML, PDF, and /finding.

JSON and YAML keep their field names. This module only builds the reading copy.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape

from silentblue.cost import format_usd
from silentblue.models import FinalReport, Finding
from silentblue.playbooks import why_it_matters

_BLUE = "0.310 0.490 0.690"
_LIGHT = "0.910 0.941 0.969"
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STAGE_TITLES = {
    "d0": "Scope",
    "d1": "Context",
    "d2": "Review list",
    "d3": "Units",
    "d4": "Model review",
    "d5": "Detectors",
    "d6": "Review stamp",
    "d7": "Dedup",
    "d8": "Rank",
    "d9": "Report",
}
_DROP_SENTENCE = {
    "not_a_sink": "The line is not the call the rule is about.",
    "bound_parameter": "The assembled text is a bound value.",
    "fixed_clause": "The inserted text is a fixed clause.",
    "fixture": "The value is a fixture, not a live credential.",
    "duplicate": "The same rule already covers a nearby line.",
}
_STAGE_SENTENCE = {
    "completed": "finished",
    "cached": "used a cached result",
    "not_run": "did not run",
    "skipped": "was skipped",
    "degraded": "finished with a degraded result",
}


@dataclass(frozen=True)
class _Block:
    kind: str
    text: str = ""
    body: str = ""
    rows: tuple[tuple[str, ...], ...] = ()
    code: tuple[str, ...] = ()


def display_prefix(repo_name: str) -> str:
    """The first three letters of the repository name, lowercased."""

    letters = "".join(ch for ch in repo_name if ch.isascii() and ch.isalpha()).lower()
    if not letters:
        return "rep"
    return letters[:3]


def display_id(repo_name: str, number: int) -> str:
    """The reading-copy id, such as rho-1. The case id stays the record."""

    return f"{display_prefix(repo_name)}-{number}"


def assessment_title(repo_name: str, *, partial: bool = False) -> str:
    """One line. A finished review says Assessment. An unfinished review says Partial."""

    name = " ".join(repo_name.split()) or "repository"
    prefix = "SilentBlue "
    suffix = " Partial" if partial else " Assessment"
    if len(prefix) + len(name) + len(suffix) <= 60:
        return prefix + name + suffix
    room = 60 - len(prefix) - len(suffix) - 3
    if room < 1:
        room = 1
    return prefix + name[:room].rstrip() + "..." + suffix


def assessment_date(generated_at: str) -> str:
    text = generated_at.strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10]
    return text or "undated"


def footer_line(report: FinalReport) -> str:
    return f"SilentBlue version {report.version} Assessment {assessment_date(report.generated_at)}"


def render_markdown(report: FinalReport) -> str:
    """The assessment as Markdown. Color is left to HTML and PDF."""

    lines = _markdown_blocks(_document(report))
    foot = footer_line(report)
    return "\n".join([lines[0], "", foot, "", *lines[1:], "", foot, ""])


def finding_markdown(finding: Finding, index: int, repo_name: str) -> list[str]:
    """One finding, in the same labels the report uses."""

    number = finding.number or index
    return _markdown_blocks(_finding_blocks(repo_name, number, finding))


def render_html(report: FinalReport) -> str:
    """One self-contained HTML file. It loads nothing from the network."""

    body = "\n".join(_html_block(block) for block in _document(report))
    title = assessment_title(report.repo_name, partial=_partial(report))
    foot = escape(footer_line(report))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto 4rem; max-width: 72rem; color: #1c1917; background: #fff; font-variant-numeric: tabular-nums; }}
h1, h2, h3 {{ color: #4f7db0; font-weight: 700; }}
h1 {{ font-size: 1.6rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.6rem 0 1.2rem; }}
th, td {{ text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #e7e5e4; vertical-align: top; }}
th {{ font-weight: 700; color: #4f7db0; }}
.finding {{ border: 1px solid #e7e5e4; border-left: 4px solid #4f7db0; padding: 1rem 1.2rem; margin: 1rem 0; }}
.critical {{ border-left-color: #7f1d1d; }}
.high {{ border-left-color: #9a3412; }}
.medium {{ border-left-color: #a16207; }}
.low, .info {{ border-left-color: #57534e; }}
strong {{ font-weight: 700; }}
pre {{ white-space: pre-wrap; background: #e8f0f7; border-left: 3px solid #4f7db0; padding: 0.7rem 0.8rem; font-family: ui-monospace, Consolas, monospace; }}
.footer {{ position: fixed; bottom: 0; left: 0; right: 0; padding: 0.4rem 2rem; background: #fff; color: #4f7db0; border-top: 1px solid #e8f0f7; font-size: 12px; }}
@media print {{
  body {{ margin: 0.6in; margin-bottom: 0.8in; }}
  .finding {{ break-inside: avoid; }}
  a {{ color: inherit; text-decoration: none; }}
  .footer {{ position: fixed; bottom: 0; }}
}}
</style>
</head>
<body>
{body}
<p class="footer">{foot}</p>
</body>
</html>
"""


def render_pdf(report: FinalReport) -> bytes:
    """Pages drawn from the same blocks as HTML, with the blue and the footer."""

    drawn = _Pdf(footer_line(report), report.repo_name)
    for block in _document(report):
        drawn.block(block)
    return _pdf_document(drawn.finish())


def _document(report: FinalReport) -> list[_Block]:
    count = len(report.findings)
    noun = "finding" if count == 1 else "findings"
    blocks: list[_Block] = [
        _Block("title", assessment_title(report.repo_name, partial=_partial(report))),
        _Block("p", _opening(report)),
    ]
    if _partial(report):
        blocks.append(_Block("h2", "Review"))
        blocks.append(_Block("p", _review_lead(report)))
    product, other = _by_role(report.findings)
    product_noun = "product gap" if len(product) == 1 else "product gaps"
    blocks.extend(
        [
        _Block("h2", "Summary"),
        _Block("p", f"This assessment reported {len(product)} {product_noun}."),
        ]
    )
    if other:
        blocks.append(
            _Block(
                "p",
                f"{len(other)} other open rows stay on the record and are not in that count.",
            )
        )
    blocks.append(_Block("table", rows=_summary_rows(report.findings)))
    blocks.append(_Block("h2", "Categories"))
    blocks.append(_Block("p", "The findings are grouped by control category in the table below."))
    blocks.append(_Block("table", rows=_category_rows(report.findings)))
    blocks.append(_Block("h2", "Scope"))
    blocks.extend(_Block("p", sentence) for sentence in _scope_sentences(report))
    if other:
        blocks.append(_Block("h2", "Other open rows"))
        blocks.append(
            _Block(
                "p",
                "Test secrets, specimens, and docs stay visible. A test secret leaves the release gate after the owner confirm matches the line.",
            )
        )
        blocks.append(_Block("table", rows=_role_rows(report)))
    blocks.append(_Block("h2", "Index"))
    blocks.append(_Block("p", f"The index lists {count} {noun}."))
    if report.findings:
        blocks.append(_Block("table", rows=_index_rows(report)))
    blocks.append(_Block("h2", "Findings"))
    if report.findings:
        blocks.append(
            _Block(
                "p",
                "Each finding states the control, why it matters, the impact, the evidence, and the repair.",
            )
        )
    else:
        blocks.append(_Block("p", "This assessment reported no findings."))
    for index, finding in enumerate(report.findings, start=1):
        number = finding.number or index
        blocks.extend(_finding_blocks(report.repo_name, number, finding))
    blocks.extend(_dropped_blocks(report.dropped))
    blocks.append(_Block("h2", "Appendix"))
    blocks.append(_Block("p", "The appendix records how each stage finished."))
    for name, outcome in report.stages.items():
        title = _STAGE_TITLES.get(name, name)
        verb = _STAGE_SENTENCE.get(outcome, outcome)
        blocks.append(_Block("p", f"{title} {verb}."))
    blocks.append(_Block("h2", "Record"))
    blocks.append(_Block("p", "The record below is the summary stored with the findings."))
    blocks.append(_Block("p", report.summary))
    return blocks


def _finding_blocks(repo_name: str, number: int, finding: Finding) -> list[_Block]:
    why, impact = why_it_matters(finding.control_family)
    shown = display_id(repo_name, number)
    blocks = [
        _Block("id", shown, body=finding.severity),
        _Block("p", _facts(finding)),
        _Block("field", "Title", body=_sentence(finding.title)),
        _Block("field", "CVSS", body=_cvss_body(finding)),
        _Block("field", "Description", body=_sentence(finding.description)),
        _Block("field", "Why it matters", body=why),
        _Block("field", "Impact", body=impact),
    ]
    snippet = finding.snippet.strip()
    if snippet:
        blocks.append(_Block("evidence", finding.file, code=tuple(snippet.splitlines())))
    else:
        blocks.append(_Block("field", "Evidence", body="This finding has no source excerpt."))
    if finding.threat_note.strip():
        blocks.append(_Block("field", "Threat model", body=_sentence(finding.threat_note)))
    blocks.append(_Block("field", "Remediation", body=finding.remediation.strip() or "This finding has no repair text."))
    return blocks


def _partial(report: FinalReport) -> bool:
    return report.metrics.model_review == "incomplete"


def _by_role(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    product = [finding for finding in findings if finding.role in {"", "product"}]
    other = [finding for finding in findings if finding.role not in {"", "product"}]
    return product, other


def _review_lead(report: FinalReport) -> str:
    sentences = ["This is a partial assessment. Resume with /scan resume."]
    coverage = report.coverage
    if coverage is not None and coverage.unread:
        sentences.append("Unread paths: " + ", ".join(coverage.unread) + ".")
    if coverage is not None:
        skipped = [row for row in coverage.rows if row.model_state.startswith("skipped:")]
        if skipped:
            shown = ", ".join(f"{row.path} ({row.model_state})" for row in skipped)
            sentences.append(f"Skipped paths: {shown}.")
        if coverage.stop == "budget":
            sentences.append("The call budget stopped the review.")
        elif coverage.stop == "owner":
            sentences.append("The owner stopped the review.")
        if coverage.refute == "not_started":
            sentences.append("Refute did not start.")
        if coverage.miss == "not_started":
            sentences.append("Miss did not start.")
    return " ".join(sentences)


def _role_rows(report: FinalReport) -> tuple[tuple[str, ...], ...]:
    rows = [("Role", "Id", "Rule", "Location", "Owner")]
    for index, finding in enumerate(report.findings, start=1):
        if finding.role in {"", "product"}:
            continue
        number = finding.number or index
        rows.append(
            (
                finding.role,
                display_id(report.repo_name, number),
                finding.rule_id,
                f"{finding.file}:{finding.line}",
                _owner_action(finding),
            )
        )
    return tuple(rows)


def _owner_action(finding: Finding) -> str:
    if finding.role == "specimen":
        return "Specimen"
    if finding.role == "docs":
        return "Docs"
    if finding.rule_id == "hardcoded-secret" and finding.owner_confirm == "recorded":
        return "Owner confirmed"
    if finding.rule_id == "hardcoded-secret" and finding.owner_confirm == "stale":
        return "Line changed"
    if finding.role == "test" and finding.rule_id == "hardcoded-secret":
        return "Confirm the value cannot authenticate"
    return "Test"


def _opening(report: FinalReport) -> str:
    date = assessment_date(report.generated_at)
    kind = "partial assessment" if _partial(report) else f"{report.profile} assessment"
    sentences = [
        (
            f"This Silent Blue {kind} of {report.repo_name} "
            f"was recorded on {date} with version {report.version}."
        ),
        "It reviews the source controls and the coverage ledger.",
    ]
    if report.profile == "assess":
        sentences.append("The model review is included.")
    if report.advisories == "queried":
        sentences.append("Dependency advisories were queried and are included.")
    elif report.advisories == "degraded":
        sentences.append("The dependency advisory query did not finish.")
    else:
        sentences.append("Dependency advisories were not queried.")
    if report.threat_model == "accepted":
        sentences.append("An accepted threat model orders the findings.")
    elif report.threat_model == "draft":
        sentences.append("A draft threat model is present and does not order the findings.")
    elif report.threat_model == "stale":
        sentences.append("The accepted threat model no longer matches this repository.")
    else:
        sentences.append("No threat model was accepted for this run.")
    observed = report.edge_passed or any(item.origin == "deployment" for item in report.findings)
    if observed:
        sentences.append("Deployment observations are included.")
    else:
        sentences.append("No deployment check is included.")
    if report.hollow:
        sentences.append("This empty result is untrusted because no source was sent for review.")
    return " ".join(sentences)


def _scope_sentences(report: FinalReport) -> list[str]:
    metrics = report.metrics
    language = metrics.primary_language or "unknown"
    sentences = [
        (
            f"The walk read {metrics.files} files and {metrics.bytes} bytes. "
            f"The primary language is {language}."
        )
    ]
    coverage = report.coverage
    if coverage is not None and coverage.rows:
        if coverage.saturated:
            sentences.append("Coverage is saturated. Every applicable file was checked or skipped with a reason.")
        else:
            sentences.append("Coverage is not saturated. At least one applicable file was not checked.")
        if any(row.model_state for row in coverage.rows):
            if coverage.model_saturated:
                sentences.append("Model coverage is saturated. Every review path was read.")
            else:
                sentences.append("Model coverage is not saturated. At least one review path was not read.")
        if coverage.unread:
            sentences.append(
                f"{len(coverage.unread)} review paths were not read: {', '.join(coverage.unread)}."
            )
    if report.edge_passed:
        sentences.append(
            "The deployment check passed these header controls: " + ", ".join(report.edge_passed) + "."
        )
    estimated = format_usd(metrics.estimated_cost_usd, metrics.rate_known)
    if metrics.model_calls:
        actual = format_usd(metrics.actual_cost_usd, metrics.usage_known and metrics.rate_known)
        sentences.append(
            f"The estimated cost is {estimated} USD, and the actual cost is {actual} USD, "
            f"across {metrics.model_calls} model calls."
        )
    else:
        sentences.append(
            f"The estimated cost is {estimated} USD. This profile made no model calls."
        )
    return sentences


def _summary_rows(findings: list[Finding]) -> tuple[tuple[str, ...], ...]:
    counts = {name: 0 for name in _SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    rows = [("Severity", "Count")]
    rows.extend((name.capitalize(), str(counts[name])) for name in _SEVERITIES)
    return tuple(rows)


def _category_rows(findings: list[Finding]) -> tuple[tuple[str, ...], ...]:
    header = ("Control category", *(name.capitalize() for name in _SEVERITIES), "Confirmed", "Unsettled")
    buckets: dict[str, dict[str, int]] = {}
    for finding in findings:
        key = finding.control_family or "unspecified"
        bucket = buckets.setdefault(key, {name: 0 for name in (*_SEVERITIES, "confirmed", "unsettled")})
        bucket[finding.severity] = bucket.get(finding.severity, 0) + 1
        if finding.verdict == "inconclusive":
            bucket["unsettled"] += 1
        else:
            bucket["confirmed"] += 1
    if not buckets:
        return (header, ("None", *(["0"] * (len(header) - 1))))
    rows = [header]
    ordered = sorted(buckets, key=lambda item: (-sum(buckets[item][name] for name in _SEVERITIES), item))
    for key in ordered:
        bucket = buckets[key]
        rows.append(
            (
                _category_label(key),
                *(str(bucket[name]) for name in _SEVERITIES),
                str(bucket["confirmed"]),
                str(bucket["unsettled"]),
            )
        )
    return tuple(rows)


def _index_rows(report: FinalReport) -> tuple[tuple[str, ...], ...]:
    rows = [("#", "Severity", "CVSS", "Rule", "Title")]
    for index, finding in enumerate(report.findings, start=1):
        number = finding.number or index
        score = "-" if finding.cvss_score is None else format(finding.cvss_score, ".1f")
        rule = finding.advisory_id or finding.rule_id
        rows.append((display_id(report.repo_name, number), finding.severity, score, rule, finding.title))
    return tuple(rows)


def _dropped_blocks(dropped: list) -> list[_Block]:
    blocks = [_Block("h2", "Dropped"), _Block("p", f"This assessment closed {len(dropped)} candidates before they became findings.")]
    if not dropped:
        return blocks
    grouped: dict[str, list] = {}
    for item in dropped:
        grouped.setdefault(item.reason, []).append(item)
    for reason in sorted(grouped):
        gloss = _DROP_SENTENCE.get(reason, "The candidate was closed for this reason.")
        blocks.append(_Block("p", f"Closed as {reason}. {gloss}"))
        lines = [f"{item.file}:{item.line} {item.rule_id}." for item in grouped[reason]]
        blocks.append(_Block("p", " ".join(lines)))
    return blocks


def _facts(finding: Finding) -> str:
    case = finding.case_id or "unassigned"
    parts = [
        (
            f"This finding is {finding.severity}, rule {finding.rule_id}, "
            f"at {finding.file}:{finding.line}, case {case}."
        )
    ]
    if finding.role:
        parts.append(f"The path role is {finding.role}.")
    if finding.owner_confirm == "recorded":
        parts.append("The owner confirmed this test secret. The line hash still matches.")
    elif finding.owner_confirm == "stale":
        parts.append("The owner confirm no longer matches this line.")
    if finding.verdict:
        parts.append(f"The verdict is {finding.verdict}.")
    if finding.playbook:
        parts.append(f"The playbook is {finding.playbook}.")
    if finding.category:
        parts.append(f"The category is {finding.category}.")
    if finding.advisory_id:
        parts.append(f"The advisory is {finding.advisory_id}.")
    component = finding.component
    if component is not None and component.purl.startswith("pkg:"):
        parts.append(f"The component is {component.ecosystem} {component.name} {component.version}.")
        if component.fixed_version:
            parts.append(f"The fixed version is {component.fixed_version}.")
        if component.relationship:
            parts.append(f"The dependency is {component.relationship}.")
    if finding.also_at:
        listed = ", ".join(str(line) for line in finding.also_at)
        parts.append(f"The same pattern also appears at lines {listed}.")
    if finding.also_in:
        parts.append("The same bytes also appear in " + ", ".join(finding.also_in) + ".")
    return " ".join(parts)


def _cvss_body(finding: Finding) -> str:
    if finding.cvss_score is None:
        return "This finding has no CVSS score."
    version = finding.cvss_version or "3.1"
    score = format(finding.cvss_score, ".1f")
    vector = f" {finding.cvss_vector}" if finding.cvss_vector else ""
    return f"{version} {score}{vector}."


def _sentence(text: str) -> str:
    body = " ".join(text.split())
    if not body:
        return "This section has no text."
    if body[-1] not in ".!?":
        body += "."
    return body


def _category_label(family: str) -> str:
    return " ".join(part.capitalize() for part in family.replace("_", "-").split("-"))


def _markdown_blocks(blocks: list[_Block]) -> list[str]:
    lines: list[str] = []
    for block in blocks:
        if block.kind == "title":
            lines.extend([f"# {block.text}", ""])
        elif block.kind == "h2":
            lines.extend([f"## {block.text}", ""])
        elif block.kind == "id":
            lines.extend([f"## {block.text}", ""])
        elif block.kind == "p":
            lines.extend([block.text, ""])
        elif block.kind == "field":
            lines.extend([f"**{block.text}:** {block.body}", ""])
        elif block.kind == "evidence":
            lines.extend([f"**Evidence:** {block.text}", ""])
            lines.extend(_fence(block.text, block.code))
            lines.append("")
        elif block.kind == "table":
            lines.extend(_markdown_table(block.rows))
            lines.append("")
    return lines


def _markdown_table(rows: tuple[tuple[str, ...], ...]) -> list[str]:
    if not rows:
        return []
    header = "| " + " | ".join(f"**{_md_cell(cell)}**" for cell in rows[0]) + " |"
    rule = "| " + " | ".join("---" for _ in rows[0]) + " |"
    body = [
        "| " + " | ".join(_md_cell(cell) for cell in row) + " |"
        for row in rows[1:]
    ]
    return [header, rule, *body]


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _fence(path: str, code: tuple[str, ...]) -> list[str]:
    snippet = "\n".join(code)
    marker = "```"
    while marker in snippet:
        marker += "`"
    return [f"{marker}{path}", *code, marker]


def _html_block(block: _Block) -> str:
    if block.kind == "title":
        return f"<h1>{escape(block.text)}</h1>"
    if block.kind == "h2":
        return f"<h2>{escape(block.text)}</h2>"
    if block.kind == "id":
        severity = escape(block.body or "info")
        return (
            f"<article class='finding {severity}' id='{escape(block.text)}'>"
            f"<h3>{escape(block.text)}</h3>"
        )
    if block.kind == "p":
        return f"<p>{escape(block.text)}</p>"
    if block.kind == "field":
        closer = "</article>" if block.text == "Remediation" else ""
        body = escape(block.body).replace("\n", "<br>\n")
        return f"<p><strong>{escape(block.text)}:</strong> {body}</p>{closer}"
    if block.kind == "evidence":
        code = escape("\n".join(block.code))
        return f"<p><strong>Evidence:</strong> {escape(block.text)}</p><pre><code>{code}</code></pre>"
    if block.kind == "table":
        return _html_table(block.rows)
    return ""


def _html_table(rows: tuple[tuple[str, ...], ...]) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{escape(cell)}</th>" for cell in rows[0])
    body: list[str] = []
    link_ids = rows[0] and rows[0][0] in {"#", "\\#"}
    for row in rows[1:]:
        cells = []
        for index, cell in enumerate(row):
            shown = escape(cell)
            if index == 0 and link_ids and cell not in {"None", "-"}:
                shown = f"<a href='#{escape(cell)}'>{shown}</a>"
            cells.append(f"<td>{shown}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


class _Pdf:
    """One content stream per page. The footer is drawn when the pages are finished."""

    def __init__(self, footer: str, repo_name: str) -> None:
        self.footer = footer
        self.repo_name = repo_name
        self.pages: list[list[str]] = [[]]
        self.y = 740.0

    def page(self) -> list[str]:
        return self.pages[-1]

    def break_page(self) -> None:
        self.pages.append([])
        self.y = 740.0

    def room(self, height: float) -> None:
        if self.y - height < 58:
            self.break_page()

    def text(self, font: str, size: float, x: float, y: float, value: str, color: str = "0 0 0") -> None:
        self.page().extend(
            [
                f"{color} rg",
                "BT",
                f"/{font} {size:.1f} Tf",
                f"1 0 0 1 {x:.1f} {y:.1f} Tm",
                f"({_pdf_escape(value)}) Tj",
                "ET",
            ]
        )

    def fill(self, x: float, y: float, width: float, height: float, color: str) -> None:
        self.page().extend(
            [
                f"{color} rg",
                f"{x:.1f} {y:.1f} {width:.1f} {height:.1f} re",
                "f",
            ]
        )

    def block(self, block: _Block) -> None:
        if block.kind == "title":
            self.room(24)
            self.text("F2", 16, 50, self.y, block.text, _BLUE)
            self.y -= 24
        elif block.kind == "h2":
            self.room(22)
            self.y -= 8
            self.text("F2", 13, 50, self.y, block.text, _BLUE)
            self.y -= 18
        elif block.kind == "id":
            self.room(22)
            self.y -= 8
            self.text("F2", 13, 50, self.y, block.text, _BLUE)
            self.y -= 18
        elif block.kind == "p":
            self._paragraph(block.text, "F1", 11, "0 0 0")
        elif block.kind == "field":
            self.room(16)
            self.text("F2", 11, 50, self.y, f"{block.text}:", "0 0 0")
            self.y -= 14
            self._paragraph(block.body, "F1", 11, "0 0 0")
        elif block.kind == "evidence":
            self.room(16)
            self.text("F2", 11, 50, self.y, f"Evidence: {block.text}", "0 0 0")
            self.y -= 14
            for raw in block.code or ("",):
                for piece in _hard(raw, 84):
                    self.room(13)
                    self.fill(48, self.y - 3, 516, 13, _LIGHT)
                    self.text("F3", 9, 54, self.y, piece)
                    self.y -= 13
        elif block.kind == "table":
            self._table(block.rows)

    def _paragraph(self, text: str, font: str, size: float, color: str) -> None:
        width = 92 if size >= 11 else 100
        for line in _wrap_words(text, width) or [""]:
            self.room(size + 4)
            self.text(font, size, 50, self.y, line, color)
            self.y -= size + 4

    def _table(self, rows: tuple[tuple[str, ...], ...]) -> None:
        if not rows:
            return
        cols = max(len(row) for row in rows)
        size = 8.0 if cols > 5 else 9.0
        width = 512 / cols
        capacity = max(4, int(width / (size * 0.5)) - 1)
        line_h = size + 6

        def emit(row: tuple[str, ...], bold: bool, y: float) -> None:
            font = "F2" if bold else "F1"
            color = _BLUE if bold else "0 0 0"
            for index in range(cols):
                cell = row[index] if index < len(row) else ""
                if len(cell) > capacity:
                    cell = cell[: capacity - 3] + "..."
                self.text(font, size, 50 + index * width, y, cell, color)

        header = rows[0]
        self.room(line_h)
        emit(header, True, self.y)
        self.y -= line_h
        for row in rows[1:]:
            if self.y - line_h < 58:
                self.break_page()
                emit(header, True, self.y)
                self.y -= line_h
            emit(row, False, self.y)
            self.y -= line_h

    def finish(self) -> list[tuple[list[str], str]]:
        total = len(self.pages)
        finished: list[tuple[list[str], str]] = []
        for number, commands in enumerate(self.pages, start=1):
            header = f"{self.repo_name}  {number} / {total}"
            chrome = []
            chrome.extend(_placed("F1", 9, 50, 770, header, "0 0 0"))
            chrome.extend(_placed("F1", 9, 50, 36, self.footer, _BLUE))
            finished.append((chrome + commands, ""))
        return finished


def _placed(font: str, size: float, x: float, y: float, value: str, color: str) -> list[str]:
    return [
        f"{color} rg",
        "BT",
        f"/{font} {size:.1f} Tf",
        f"1 0 0 1 {x:.1f} {y:.1f} Tm",
        f"({_pdf_escape(value)}) Tj",
        "ET",
    ]


def _wrap_words(text: str, width: int) -> list[str]:
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = ""
    for word in words:
        piece = word if len(word) <= width else word[:width]
        if not current:
            current = piece
            continue
        if len(current) + 1 + len(piece) <= width:
            current = f"{current} {piece}"
        else:
            lines.append(current)
            current = piece
    if current:
        lines.append(current)
    return lines


def _hard(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    return [text[index : index + width] for index in range(0, len(text), width)]


def _pdf_escape(text: str) -> str:
    encoded = text.encode("latin-1", errors="replace").decode("latin-1")
    return encoded.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_document(pages: list[tuple[list[str], str]]) -> bytes:
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    courier = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    content_ids: list[int] = []
    for commands, _note in pages:
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        content_ids.append(
            add(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        )
    page_ids: list[int] = []
    resources = (
        f"/Resources << /Font << /F1 {font} 0 R /F2 {bold} 0 R /F3 {courier} 0 R >> >>"
    )
    for content_id in content_ids:
        page_ids.append(
            add(
                (
                    "<< /Type /Page /Parent 0 0 R /MediaBox [0 0 612 792] "
                    f"/Contents {content_id} 0 R {resources} >>"
                ).encode()
            )
        )
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    pages_id = add(f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode())
    for page_id in page_ids:
        objects[page_id - 1] = objects[page_id - 1].replace(b"/Parent 0 0 R", f"/Parent {pages_id} 0 R".encode())
    catalog = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
    return _serialize(objects, catalog)


def _serialize(objects: list[bytes], root: int) -> bytes:
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    chunks = [header]
    offsets = [0]
    cursor = len(header)
    for number, body in enumerate(objects, start=1):
        offsets.append(cursor)
        piece = f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
        chunks.append(piece)
        cursor += len(piece)
    xref_at = cursor
    xref = [f"xref\n0 {len(objects) + 1}\n".encode(), b"0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n".encode())
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {root} 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return b"".join([*chunks, *xref, trailer])
