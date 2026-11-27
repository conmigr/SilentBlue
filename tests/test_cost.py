"""Cost estimates use the dated list-price table and reported token counts."""

from __future__ import annotations

import json

import pytest

from silentblue.cost import dollars, estimate_spend, format_usd, rate_for
from silentblue.errors import UsageError
from silentblue.model import parse_thinking, parse_usage


def test_default_models_have_list_prices():
    assert rate_for("openai", "gpt-6.1-terra") == (1.0, 5.0)
    assert rate_for("anthropic", "claude-sonnet-5-5") == (2.0, 10.0)
    assert rate_for("grok", "grok-4.7") == (2.0, 6.0)
    assert rate_for("gemini", "gemini-4-hydrogen") == (1.5, 7.5)
    assert rate_for("openai", "custom-model") is None


def test_detect_estimate_is_zero():
    estimate = estimate_spend(
        profile="detect",
        source_files=10,
        max_calls=40,
        max_units=20,
        max_files_per_unit=4,
        max_excerpt_bytes=8000,
        provider="openai",
        model_name="gpt-6.1-terra",
    )
    assert estimate.calls == 0
    assert estimate.cost_usd == 0.0
    assert format_usd(estimate.cost_usd, estimate.rate_known) == "0.0000"


def test_assess_estimate_is_bounded_by_the_call_budget():
    estimate = estimate_spend(
        profile="assess",
        source_files=3,
        max_calls=40,
        max_units=20,
        max_files_per_unit=4,
        max_excerpt_bytes=8000,
        provider="openai",
        model_name="gpt-6.1-terra",
    )
    assert estimate.calls == 4
    assert estimate.follow_up_calls == 3
    assert estimate.units == 1
    assert estimate.cost_usd is not None
    assert estimate.cost_usd > 0
    capped = estimate_spend(
        profile="assess",
        source_files=8,
        max_calls=1,
        max_units=20,
        max_files_per_unit=4,
        max_excerpt_bytes=8000,
        provider="openai",
        model_name="gpt-6.1-terra",
    )
    assert capped.calls == 1
    assert capped.follow_up_calls == 0
    assert dollars(1_000_000, 0, (1.0, 5.0)) == 1.0


def test_price_override_replaces_the_table(monkeypatch):
    monkeypatch.setenv("SILENTBLUE_PRICE_INPUT_PER_MILLION", "3")
    monkeypatch.setenv("SILENTBLUE_PRICE_OUTPUT_PER_MILLION", "9")
    assert rate_for("openai", "custom-model") == (3.0, 9.0)


def test_a_partial_price_override_is_refused(monkeypatch):
    monkeypatch.setenv("SILENTBLUE_PRICE_INPUT_PER_MILLION", "3")
    monkeypatch.delenv("SILENTBLUE_PRICE_OUTPUT_PER_MILLION", raising=False)
    with pytest.raises(UsageError):
        rate_for("openai", "gpt-6.1-terra")


def test_usage_is_read_from_each_provider_shape():
    chat = json.dumps(
        {"usage": {"prompt_tokens": 11, "completion_tokens": 7}, "choices": []}
    ).encode()
    assert parse_usage("openai", chat) == (11, 7)
    assert parse_usage("grok", chat) == (11, 7)
    messages = json.dumps({"usage": {"input_tokens": 5, "output_tokens": 2}}).encode()
    assert parse_usage("anthropic", messages) == (5, 2)
    assert parse_usage("openai", b"{}") == (None, None)


def test_thinking_tokens_are_read_when_the_provider_sends_them():
    chat = json.dumps(
        {
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "completion_tokens_details": {"reasoning_tokens": 3},
            }
        }
    ).encode()
    assert parse_thinking("openai", chat) == 3
    assert parse_thinking("grok", chat) == 3
    gemini = json.dumps({"usage": {"prompt_tokens": 4, "completion_tokens": 2, "thoughts_token_count": 6}}).encode()
    assert parse_thinking("gemini", gemini) == 6
    anthropic = json.dumps({"usage": {"input_tokens": 5, "output_tokens": 2}}).encode()
    assert parse_thinking("anthropic", anthropic) is None
    assert parse_thinking("openai", b"{}") is None
