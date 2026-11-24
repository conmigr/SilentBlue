"""Policy gate for a proposed repair. A refusal is stored on the case."""

from __future__ import annotations

import re
from dataclasses import dataclass

_MAX_REPLACEMENT = 8000
_TEST_DEF = re.compile(r"(?m)^[ \t]*def[ \t]+test_\w+[ \t]*\(")
_CONTROL_OFF: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bverify\s*=\s*False\b"),
    re.compile(r"(?i)\bshell\s*=\s*True\b"),
    re.compile(r"(?i)\bos\.system\s*\("),
    re.compile(r"(?i)\beval\s*\("),
    re.compile(r"(?i)\bexec\s*\("),
    re.compile(r"(?i)\bdebug\s*[:=]\s*(?:true|1|'1'|\"1\")\b"),
    re.compile(r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]"),
    re.compile(r"(?i)access-control-allow-origin['\"]?\s*[:=]\s*['\"]\*['\"]"),
    re.compile(r"(?i)\bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)


@dataclass(frozen=True)
class PatchReview:
    """Gate result. ``refusal`` is empty when the patch may be recorded."""

    ok: bool
    refusal: str
    start_line: int
    end_line: int
    replacement: str


def review_patch(
    *,
    finding_file: str,
    proposed_file: str,
    start_line: int,
    end_line: int,
    replacement: str,
    line_count: int,
    original_span: str,
) -> PatchReview:
    """Accept a same-file repair that keeps controls on and keeps tests."""

    review = PatchReview(False, "", start_line, end_line, replacement)
    if _normalize(proposed_file) != _normalize(finding_file):
        return _refused(review, "outside_path")
    if start_line < 1 or end_line < start_line or end_line > line_count:
        return _refused(review, "line_out_of_range")
    if len(replacement) > _MAX_REPLACEMENT:
        return _refused(review, "too_large")
    if "\0" in replacement:
        return _refused(review, "unsafe")
    if any(pattern.search(replacement) for pattern in _CONTROL_OFF):
        return _refused(review, "control_disabled")
    if _drops_test(finding_file, original_span, replacement):
        return _refused(review, "deletes_test")
    return PatchReview(True, "", start_line, end_line, replacement)


def _refused(review: PatchReview, reason: str) -> PatchReview:
    return PatchReview(False, reason, review.start_line, review.end_line, review.replacement)


def _normalize(value: str) -> str | None:
    text = value.replace("\\", "/").strip()
    if not text:
        return ""
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
        return None
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _drops_test(relative: str, original: str, replacement: str) -> bool:
    removed = _TEST_DEF.findall(original)
    kept = _TEST_DEF.findall(replacement)
    if removed and len(kept) < len(removed):
        return True
    if _is_test_path(relative) and original.strip() and not replacement.strip():
        return True
    return False


def _is_test_path(relative: str) -> bool:
    parts = relative.replace("\\", "/").split("/")
    name = parts[-1].lower()
    folders = [part.lower() for part in parts[:-1]]
    if any(part in {"test", "tests", "__tests__", "spec"} for part in folders):
        return True
    return name.startswith("test_") or name.endswith("_test.py") or ".test." in name or ".spec." in name
