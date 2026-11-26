"""Terminal layout for the session and the one-shot commands.

A pipe keeps one record per line. A terminal gets a title, aligned content,
and a working, done, or waiting line so a turn is visible.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

from silentblue.models import Finding
from silentblue.playbooks import why_it_matters
from silentblue.reading import display_id
_ROW = re.compile(r"^([A-Za-z][A-Za-z0-9 _./-]{0,40}): (.+)$")
_SEVERITY = {
    "critical": "\033[38;2;127;29;29m",
    "high": "\033[38;2;154;52;18m",
    "medium": "\033[38;2;161;98;7m",
    "low": "\033[38;2;87;83;78m",
    "info": "\033[38;2;87;83;78m",
}
_RESET = "\033[0m"
_BLUE = "\033[38;2;79;125;176m"

HELP_SHORT = """\
/status     Where this session is
/findings   The gaps, or /finding rho-1 for one
/scan       Detect. /scan osv and /scan assess ask first
/model      Draft or accept the threat model
/report     The HTML, PDF, and JSON that were written
/quit       Leave

/help scan, /help findings, or /help model shows that group.
A sentence works in place of a command.
"""

HELP_SCAN = """\
Scan

  /scan                 Run a detect scan
  /scan osv             Detect, then query OSV. Asks first
  /scan assess          Assess. Prints the estimate and asks first
  /scan assess osv      Assess, then query OSV. Asks first
  /scan resume          Continue an assess scan from the last finished unit
  /deploy               Review deployment files. Asks first
"""

HELP_FINDINGS = """\
Findings

  /findings             Gaps from the latest report
  /findings osv         Only the OSV rows
  /findings counts      Count by control category and severity
  /findings categories  Gaps grouped by control category
  /finding <number>     One gap. A case id or rho-1 also works
  /report               Paths of the written reports
  /exclusions           Directories left out of the scan
  /skills               Harness skills. /skill <name> shows one
  /triage               Dispositions stored outside the repository
"""

HELP_MODEL = """\
Model

  /model                Show the threat model
  /model draft          Draft from the current findings
  /model draft assess   Draft after reading source. Asks first
  /model assume <text>  Add an assumption. Asks first
  /model accept         Record acceptance. The sentence form asks first
  /cost                 Cost since this session started

A request to drop a finding or change the mission is refused.
"""

_TOPICS = {
    "": HELP_SHORT,
    "scan": HELP_SCAN,
    "findings": HELP_FINDINGS,
    "model": HELP_MODEL,
}


def help_text(topic: str = "") -> str:
    return _TOPICS.get(topic.strip().lower(), "").rstrip()


def width() -> int:
    columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    return max(40, min(columns, 120))


def working(detail: str) -> str:
    return f"working  {detail}"


def done(detail: str) -> str:
    return f"done  {detail}"


def waiting(detail: str) -> str:
    return f"waiting  {detail}"


def prompt_for(pending: bool) -> str:
    return "yes/no> " if pending else "silentblue> "


def severity(name: str) -> str:
    """Color the severity word when the terminal has color."""

    if not name or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return name
    color = _SEVERITY.get(name)
    if color is None:
        return name
    return f"{color}{name}{_RESET}"


def accent(text: str) -> str:
    if not text or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"{_BLUE}{text}{_RESET}"


def card(title: str, rows: list[tuple[str, str]], notes: list[str] | None = None) -> list[str]:
    """A title, a label column, and the notes under it."""

    lines = [title, ""]
    label = max((len(key) for key, _value in rows), default=0)
    for key, value in rows:
        lines.append(f"  {key.ljust(label)}  {value}")
    if rows and notes:
        lines.append("")
    lines.extend(notes or [])
    return lines


def table(headers: list[str], rows: list[list[str]], *, wide: bool = True) -> list[str]:
    """Aligned columns. A narrow terminal drops the third column."""

    if not wide or width() < 72:
        if len(headers) >= 4:
            headers = [headers[0], headers[1], headers[3]]
            rows = [[row[0], row[1], row[3] if len(row) > 3 else ""] for row in rows]
    widths = [len(cell) for cell in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(_plain(cell)))
    cap = width() - 2

    def fit(cells: list[str]) -> str:
        shown = []
        for index, cell in enumerate(cells):
            pad = widths[index] if index < len(widths) else len(_plain(cell))
            shown.append(_pad(cell, pad))
        line = "  " + "  ".join(shown).rstrip()
        if len(_plain(line)) <= cap:
            return line
        return line[:cap]
    return [fit(headers), *([fit(row) for row in rows])]


def labeled(label: str, body: str, *, indent: int = 2) -> list[str]:
    """A label on its own line and the body indented under it."""

    lines = [label]
    prefix = " " * indent
    room = max(20, width() - indent)
    for paragraph in (body or "").splitlines() or [""]:
        lines.extend(prefix + piece for piece in _wrap(paragraph, room))
    return lines


def finding_view(repo_name: str, number: int, finding: Finding) -> list[str]:
    """One finding for the terminal. The report labels, without Markdown marks."""

    shown = display_id(repo_name, number)
    why, impact = why_it_matters(finding.control_family)
    case = finding.case_id or "unassigned"
    lines = [
        f"{accent(shown)}  {severity(finding.severity)}",
        "",
        (
            f"This finding is {finding.severity}, rule {finding.rule_id}, "
            f"at {finding.file}:{finding.line}, case {case}."
        ),
        "",
    ]
    lines.extend(labeled("Title", _sentence(finding.title)))
    lines.append("")
    score = "This finding has no CVSS score."
    if finding.cvss_score is not None:
        version = finding.cvss_version or "3.1"
        vector = f"  {finding.cvss_vector}" if finding.cvss_vector else ""
        score = f"{version}  {finding.cvss_score:.1f}{vector}"
    lines.extend(labeled("CVSS", score))
    lines.append("")
    lines.extend(labeled("Description", _sentence(finding.description)))
    lines.append("")
    lines.extend(labeled("Why it matters", why))
    lines.append("")
    lines.extend(labeled("Impact", impact))
    lines.append("")
    lines.extend(labeled("Evidence", finding.file + ":" + str(finding.line)))
    snippet = finding.snippet.strip()
    if snippet:
        for raw in snippet.splitlines():
            lines.append("    " + raw)
    else:
        lines.append("  This finding has no source excerpt.")
    if finding.threat_note.strip():
        lines.append("")
        lines.extend(labeled("Threat model", _sentence(finding.threat_note)))
    lines.append("")
    lines.extend(labeled("Remediation", finding.remediation.strip() or "This finding has no repair text."))
    lines.append("")
    lines.append("/findings returns to the list.")
    return lines


def command_text(lines: list[str]) -> str:
    """The one-shot commands. A terminal gets a card. A pipe keeps the lines."""

    if not lines:
        return ""
    if not _terminal():
        return "\n".join(lines)
    title = lines[0]
    rows: list[tuple[str, str]] = []
    notes: list[str] = []
    for line in lines[1:]:
        match = _ROW.match(line)
        if match is not None:
            rows.append((match.group(1), match.group(2)))
        elif line.strip():
            notes.append(line)
    viewed = card(title, rows, notes)
    if notes:
        viewed.append("")
        viewed.append(done(notes[0]))
    return "\n".join(viewed)


def _terminal() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _sentence(text: str) -> str:
    body = " ".join(text.split())
    if not body:
        return "This section has no text."
    if body[-1] not in ".!?":
        body += "."
    return body


def _wrap(text: str, room: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines: list[str] = []
    current = ""
    for word in words:
        piece = word if len(word) <= room else word[:room]
        if not current:
            current = piece
            continue
        if len(current) + 1 + len(piece) <= room:
            current = f"{current} {piece}"
        else:
            lines.append(current)
            current = piece
    if current:
        lines.append(current)
    return lines


def _plain(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _pad(text: str, width_cells: int) -> str:
    gap = width_cells - len(_plain(text))
    if gap <= 0:
        return text
    return text + (" " * gap)
