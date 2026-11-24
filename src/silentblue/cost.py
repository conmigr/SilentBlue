"""List-price cost for an assess run.

Rates are short-context public list prices, in USD per one million tokens.
They are not an invoice. A provider can bill cached tokens, long context, or
regional traffic at a different rate. Set both price variables to replace the
table for the model you are calling.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from silentblue.errors import UsageError

PRICE_DATE = "2026-11-18"
_ASSUMED_OUTPUT_TOKENS = 400
_CHARS_PER_TOKEN = 4
_D2_SAMPLE_BYTES = 1500 * 3
_REVIEW_PROMPT_TOKENS = 200

# (provider, model) -> (input USD per 1M, output USD per 1M)
_RATES: dict[tuple[str, str], tuple[float, float]] = {
    ("openai", "gpt-6.1-terra"): (1.0, 5.0),
    ("anthropic", "claude-sonnet-5-5"): (2.0, 10.0),
    ("grok", "grok-4.7"): (2.0, 6.0),
    ("gemini", "gemini-4-hydrogen"): (1.5, 7.5),
}


@dataclass(frozen=True)
class SpendEstimate:
    """A pre-run allowance. Output tokens are assumed until usage is reported."""

    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    rate_known: bool
    model_provider: str
    model_name: str
    price_date: str
    source_files: int = 0
    units: int = 0
    files_covered: int = 0


def rate_for(provider: str, model: str) -> tuple[float, float] | None:
    """Return USD per million input and output tokens, or None when unpublished."""

    override_in = os.environ.get("SILENTBLUE_PRICE_INPUT_PER_MILLION", "").strip()
    override_out = os.environ.get("SILENTBLUE_PRICE_OUTPUT_PER_MILLION", "").strip()
    if override_in or override_out:
        if not override_in or not override_out:
            raise UsageError(
                "set both SILENTBLUE_PRICE_INPUT_PER_MILLION and "
                "SILENTBLUE_PRICE_OUTPUT_PER_MILLION"
            )
        try:
            parsed = (float(override_in), float(override_out))
        except ValueError as exc:
            raise UsageError("price overrides must be numbers") from exc
        if parsed[0] < 0 or parsed[1] < 0:
            raise UsageError("price overrides must be zero or positive")
        return parsed
    return _RATES.get((provider, model))


def dollars(input_tokens: int, output_tokens: int, rate: tuple[float, float]) -> float:
    """Price one token pair at a per-million rate."""

    return (input_tokens * rate[0] + output_tokens * rate[1]) / 1_000_000


def format_usd(value: float | None, known: bool) -> str:
    """Render a cost for the command output and the report."""

    if not known or value is None:
        return "unknown"
    return f"{value:.4f}"


def estimate_spend(
    *,
    profile: str,
    source_files: int,
    max_calls: int,
    max_units: int,
    max_files_per_unit: int,
    max_excerpt_bytes: int,
    provider: str,
    model_name: str,
) -> SpendEstimate:
    """Bound an assess run by the call and excerpt budgets. Detect stays at zero."""

    if profile != "assess" or source_files <= 0:
        return SpendEstimate(0, 0, 0, 0.0, True, "", "", PRICE_DATE, source_files, 0, 0)
    per_unit = max(1, max_files_per_unit)
    chunks = min(max_units, math.ceil(source_files / per_unit))
    files_covered = min(source_files, chunks * per_unit)
    named = 1 + chunks
    reviews = min(chunks, max(0, max_calls - named))
    calls = min(max_calls, named + reviews)
    files_in_unit = min(per_unit, source_files)
    unit_tokens = (max_excerpt_bytes * files_in_unit) // _CHARS_PER_TOKEN
    input_tokens = (_D2_SAMPLE_BYTES // _CHARS_PER_TOKEN) + (unit_tokens * chunks)
    input_tokens += _REVIEW_PROMPT_TOKENS * reviews
    output_tokens = _ASSUMED_OUTPUT_TOKENS * calls
    rate = rate_for(provider, model_name)
    cost = dollars(input_tokens, output_tokens, rate) if rate is not None else None
    return SpendEstimate(
        calls=calls,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost,
        rate_known=rate is not None,
        model_provider=provider,
        model_name=model_name,
        price_date=PRICE_DATE,
        source_files=source_files,
        units=chunks,
        files_covered=files_covered,
    )


def actual_cost(
    input_tokens: int,
    output_tokens: int,
    *,
    provider: str,
    model_name: str,
    usage_known: bool,
    made_calls: bool,
) -> tuple[float | None, bool]:
    """Price reported usage. A detect run is zero. Missing usage stays unknown."""

    if not made_calls:
        return 0.0, True
    if not usage_known:
        return None, True
    rate = rate_for(provider, model_name)
    if rate is None:
        return None, False
    return dollars(input_tokens, output_tokens, rate), True
