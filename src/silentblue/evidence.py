"""Evidence bar for line rules. A closed row never becomes a finding."""

from __future__ import annotations

import re
from dataclasses import dataclass

_DB_CALL = re.compile(
    r"(?i)(?P<recv>\b[\w.]*)\.(?P<method>execute|executemany|executescript|query)\s*\("
)
_BARE_EXEC = re.compile(r"(?i)(?<!\.)\b(?:execute|executemany|executescript)\s*\(")
_DB_RECEIVER = re.compile(
    r"(?i)(?:^|\.)(?:conn|connection|cursor|db|pool|client|database|sql|tx|txn|knex)$"
)
_ASSEMBLY = re.compile(r"""(?s)f['\"]|\$\{|\.format\s*\(|%\s*[\(\w]|\+\s*""")
_PRINT = re.compile(r"(?i)^\s*(?:print|logger|logging)\b")
_STRING = re.compile(r"""(?s)(?:[rubfRUBF]{0,2})('''|\"\"\"|'|\")(?:\\.|(?!\1).)*\1""")
_NAMES = re.compile(
    r"\{([A-Za-z_][\w.]*)|\+\s*([A-Za-z_][\w]*)|%\(([A-Za-z_]\w*)\)"
)
_USER_NAMES = {
    "request",
    "req",
    "input",
    "argv",
    "form",
    "body",
    "user",
    "args",
    "payload",
    "search",
    "params",
    "param",
    "data",
    "name",
    "company",
    "email",
    "query",
    "value",
    "text",
    "term",
    "filter",
    "raw",
}
_LIVE_SECRET = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
)
_FIXTURE = re.compile(
    r"(?i)(?:^|[-_\s])(?:test|fake|dummy|example|smoke|placeholder|sample|not-?a-?real)(?:[-_\s]|$)"
    r"|smoke[-_\s]?test"
    r"|^(?:test|fake|dummy|example|smoke|password|secret|changeme)$"
)
_DOC_EXT = {".md", ".markdown", ".rst", ".txt", ".adoc"}


@dataclass(frozen=True)
class SqlCluster:
    """One SQL control gap, or one closed candidate."""

    line: int
    status: str
    reason: str
    also_at: tuple[int, ...] = ()


def sql_clusters(path: str, text: str) -> list[SqlCluster]:
    """Classify assembled SQL in one file. Closed clusters are not findings."""

    suffix = _suffix(path)
    if suffix in _DOC_EXT:
        return _doc_clusters(text)
    lines = text.splitlines()
    in_doc = _doc_lines(lines)
    grouped: dict[tuple[str, str, str], list[int]] = {}
    order: list[tuple[str, str, str]] = []
    for number, line in enumerate(lines, start=1):
        if _is_comment(line):
            continue
        status, reason, template = _sql_line(line, in_doc=in_doc[number - 1])
        if status is None:
            continue
        key = (status, reason, template)
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(number)
    clusters: list[SqlCluster] = []
    for key in order:
        numbers = grouped[key]
        status, reason, _template = key
        clusters.append(
            SqlCluster(line=numbers[0], status=status, reason=reason, also_at=tuple(numbers[1:]))
        )
    return clusters


def assembled_sql_verdict(line: str) -> str | None:
    """Verdict for a language rule that already matched assembled SQL. None closes it."""

    names = _interpolated_names(line)
    added = re.search(r"""\+\s*(['\"]|[A-Za-z_])""", line)
    if not names and "{" not in line and (added is None or added.group(1) in {"'", '"'}):
        if not re.search(r"\+\s*[A-Za-z_]", line):
            return None
    if any(_is_user(name) for name in names):
        return "detector"
    if names or re.search(r"\+\s*[A-Za-z_]", line):
        return "inconclusive"
    return None


def fixture_secret(value: str) -> bool:
    """True when an assigned secret is a fixture rather than a live credential."""

    text = value.strip()
    if _LIVE_SECRET.search(text):
        return False
    if _FIXTURE.search(text):
        return True
    if len(text) >= 8 and len(set(text.lower())) <= 2:
        return True
    return False


def live_secret(line: str) -> bool:
    """True when the line contains a credential a real service would accept."""

    return _LIVE_SECRET.search(line) is not None


def caller_controlled(line: str) -> bool:
    """True when the line names a value that arrives from outside the file."""

    for name in _interpolated_names(line):
        if _is_user(name):
            return True
    return False


def _sql_line(line: str, *, in_doc: bool) -> tuple[str | None, str, str]:
    if not _ASSEMBLY.search(line):
        return None, "", ""
    code = _STRING.sub("''", line)
    if in_doc:
        if _looks_like_query(line):
            return "closed", "mentioned", ""
        return None, "", ""
    if _PRINT.search(code) and _BARE_EXEC.search(code) is None and ".execute" not in code.lower():
        if _looks_like_query(line):
            return "closed", "not_a_sink", ""
        return None, "", ""
    sink = _sink_at(line)
    if sink is None:
        if _looks_like_query(line):
            return "closed", "not_a_sink", ""
        return None, "", ""
    first = _first_argument(line, sink)
    names = _interpolated_names(first)
    template = _template(first)
    if not names and "{" not in first:
        if re.search(r"""\+\s*['\"]""", first):
            return "closed", "fixed_clause", template
        if _ASSEMBLY.search(line[sink:]):
            return "closed", "bound_parameter", template
        return "closed", "fixed_clause", template
    if any(_is_user(name) for name in names):
        return "detector", "caller", template
    return "inconclusive", "unsettled", template


def _doc_clusters(text: str) -> list[SqlCluster]:
    for number, line in enumerate(text.splitlines(), start=1):
        if _looks_like_query(line) and _ASSEMBLY.search(line):
            return [SqlCluster(line=number, status="closed", reason="not_a_sink")]
    return []


def _sink_at(line: str) -> int | None:
    for match in _DB_CALL.finditer(line):
        method = match.group("method").lower()
        if method != "query" or _DB_RECEIVER.search(match.group("recv")):
            return match.end() - 1
    bare = _BARE_EXEC.search(line)
    if bare is not None:
        return bare.end() - 1
    return None


def _looks_like_query(line: str) -> bool:
    return bool(re.search(r"(?i)\b(?:execute|query)\s*\(|\.query\s*\(", line))


def _first_argument(line: str, open_paren: int) -> str:
    chars: list[str] = []
    depth = 1
    index = open_paren + 1
    while index < len(line) and depth:
        char = line[index]
        if char in {"'", '"'}:
            quote = char
            chars.append(char)
            index += 1
            while index < len(line):
                chars.append(line[index])
                if line[index] == "\\" and index + 1 < len(line):
                    index += 1
                    chars.append(line[index])
                elif line[index] == quote:
                    break
                index += 1
        elif char == "(":
            depth += 1
            chars.append(char)
        elif char == ")":
            depth -= 1
            if depth == 0:
                break
            chars.append(char)
        elif char == "," and depth == 1:
            break
        else:
            chars.append(char)
        index += 1
    return "".join(chars)


def _interpolated_names(fragment: str) -> list[str]:
    names: list[str] = []
    for match in _NAMES.finditer(fragment):
        raw = next(group for group in match.groups() if group)
        names.append(raw.split(".")[0])
    return names


def _is_user(name: str) -> bool:
    leaf = name.split(".")[-1].lower()
    return leaf in _USER_NAMES or any(part in _USER_NAMES for part in leaf.split("_"))


def _template(first: str) -> str:
    text = re.sub(r"\s+", " ", first).strip()
    text = re.sub(r"\{[^}]*\}", "?", text)
    text = re.sub(r"\+\s*[A-Za-z_][\w.]*", "+ ?", text)
    return text[:180]


def _doc_lines(lines: list[str]) -> list[bool]:
    """True when the line is inside a quote, so a sample statement is not a call."""

    text = "\n".join(lines)
    if lines and lines[-1] == "":
        text += "\n"
    masks = literal_masks(text)
    marked: list[bool] = []
    for line, mask in zip(lines, masks):
        exposed = [char for char, hidden in zip(line, mask) if not hidden and char.strip()]
        marked.append(bool(line.strip()) and not exposed and any(mask))
    return marked


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith("//")


def is_document(path: str) -> bool:
    """True for prose the execution rules should not score."""

    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.startswith("requirements") or name in {"constraints.txt", "pipfile"}:
        return False
    return _suffix(path) in _DOC_EXT


def literal_masks(text: str) -> list[list[bool]]:
    """Mark quotes, comments, and docstrings. True means the character is not code."""

    masks: list[list[bool]] = []
    triple: str | None = None
    block = False
    for line in text.splitlines():
        mask = [False] * len(line)
        index = 0
        length = len(line)
        while index < length:
            if triple is not None:
                end = line.find(triple, index)
                stop = length if end < 0 else end + len(triple)
                for cursor in range(index, stop):
                    mask[cursor] = True
                index = stop
                if end < 0:
                    break
                triple = None
                continue
            if block:
                end = line.find("*/", index)
                stop = length if end < 0 else end + 2
                for cursor in range(index, stop):
                    mask[cursor] = True
                index = stop
                block = end < 0
                continue
            if _opens_comment(line, index):
                for cursor in range(index, length):
                    mask[cursor] = True
                break
            if line.startswith("/*", index):
                block = True
                mask[index] = True
                if index + 1 < length:
                    mask[index + 1] = True
                index += 2
                continue
            if line[index] in {"'", '"', "`"}:
                index, opened = _mask_string(line, mask, index)
                if opened is not None:
                    triple = opened
                    break
                continue
            index += 1
        masks.append(mask)
    return masks


def quote_only(line: str, mask: list[bool], patterns: tuple[re.Pattern[str], ...]) -> bool:
    """True when every match is inside a quote or comment and is not a call argument."""

    saw = False
    for pattern in patterns:
        for match in pattern.finditer(line):
            saw = True
            if _match_in_code(mask, match.start(), match.end()):
                return False
            if _call_keeps(line, mask, match.start()):
                return False
    return saw


def _opens_comment(line: str, index: int) -> bool:
    if line.startswith("#", index):
        return True
    if not line.startswith("//", index):
        return False
    return index == 0 or line[index - 1] != ":"


def _mask_string(line: str, mask: list[bool], index: int) -> tuple[int, str | None]:
    """Mask one literal. The marker is set when a triple quote stays open."""

    quote = line[index]
    triple = quote != "`" and line.startswith(quote * 3, index)
    marker = quote * 3 if triple else quote
    cursor = index + len(marker)
    while cursor < len(line):
        if line[cursor] == "\\":
            cursor += 2
            continue
        if line.startswith(marker, cursor):
            for spot in range(index, cursor + len(marker)):
                mask[spot] = True
            return cursor + len(marker), None
        cursor += 1
    for spot in range(index, len(line)):
        mask[spot] = True
    if triple:
        return len(line), marker
    return len(line), None


def _match_in_code(mask: list[bool], start: int, end: int) -> bool:
    return any(not mask[index] for index in range(start, min(end, len(mask))))


def _call_keeps(line: str, mask: list[bool], index: int) -> bool:
    """A quoted token still counts when a real call receives it as an argument."""

    depth = 0
    cursor = index - 1
    while cursor >= 0:
        if cursor < len(mask) and mask[cursor]:
            cursor -= 1
            continue
        char = line[cursor]
        if char == ")":
            depth += 1
        elif char == "(":
            if depth == 0:
                name = re.search(r"([A-Za-z_][\w.]*)\s*$", line[:cursor])
                if name is None:
                    return False
                return _regex_compiler(name.group(1)) is False
            depth -= 1
        cursor -= 1
    return False


def _regex_compiler(name: str) -> bool:
    return (
        re.search(
            r"(?i)(?:^re\.(?:compile|search|match|findall|fullmatch|sub)$)|(?:^Pattern\.compile$)|(?:^RegExp$)",
            name,
        )
        is not None
    )


def _suffix(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if "." not in name:
        return ""
    return f".{name.rsplit('.', 1)[-1]}"
