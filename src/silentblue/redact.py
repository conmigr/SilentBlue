"""Redaction of secret-shaped text in logs and reports."""

from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

_ASSIGNMENT = re.compile(
    r"(?ix)"
    r"(\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|"
    r"auth[_-]?token|password|passwd|token)\b\s*[:=]\s*)"
    r"(['\"])"
    r"([^'\"]{8,})"
    r"\2"
)

_OPAQUE: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),
)


def redact(value: str) -> str:
    """Replace secret-shaped substrings with a fixed marker."""

    text = _ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(2)}",
        value,
    )
    for pattern in _OPAQUE:
        text = pattern.sub(REDACTED, text)
    return text


class RedactFilter(logging.Filter):
    """Apply :func:`redact` to log messages before they are emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact(item) if isinstance(item, str) else item for item in record.args
            )
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Attach redaction to the root logger once."""

    root = logging.getLogger()
    if not any(isinstance(item, RedactFilter) for item in root.filters):
        root.addFilter(RedactFilter())
    root.setLevel(level)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)
