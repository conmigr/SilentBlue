"""Redaction of secret-shaped text."""

from __future__ import annotations

import logging

from silentblue.redact import REDACTED, RedactFilter, redact


def test_redact_assignment_and_tokens():
    text = (
        'API_KEY = "AKIA0123456789ABCD"\n'
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        "model sk-abcdefghijklmnopqrstuvwxyz\n"
    )
    cleaned = redact(text)
    assert "AKIA0123456789ABCD" not in cleaned
    assert "abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert REDACTED in cleaned
    assert redact(cleaned) == cleaned


def test_log_filter_redacts_message_and_args():
    formatted = logging.LogRecord(
        name="silentblue",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="saw sk-abcdefghijklmnopqrstuvwxyz",
        args=(),
        exc_info=None,
    )
    assert RedactFilter().filter(formatted)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in formatted.getMessage()

    deferred = logging.LogRecord(
        name="silentblue",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="saw %s",
        args=("sk-abcdefghijklmnopqrstuvwxyz",),
        exc_info=None,
    )
    assert RedactFilter().filter(deferred)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in deferred.getMessage()
    assert REDACTED in deferred.getMessage()
