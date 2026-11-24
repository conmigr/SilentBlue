"""Provider routes. These tests do not call a network endpoint."""

from __future__ import annotations

import json

import pytest

from silentblue.errors import UsageError
from silentblue.model import PROVIDERS, build_request, parse_reply, resolve_model
from silentblue.models import AppConfig, ModelConfig
from silentblue.runner import _prepare_model


def test_each_provider_has_a_default_endpoint_and_model():
    expected = {
        "openai": ("https://api.openai.com/v1", "gpt-6.1-terra"),
        "anthropic": ("https://api.anthropic.com/v1", "claude-sonnet-5-5"),
        "grok": ("https://api.x.ai/v1", "grok-4.7"),
        "gemini": (
            "https://generativelanguage.googleapis.com/v1beta/openai",
            "gemini-4-hydrogen",
        ),
    }
    for provider, (url, name) in expected.items():
        resolved = resolve_model(ModelConfig(provider=provider))
        assert resolved.base_url == url
        assert resolved.name == name
        assert PROVIDERS[provider].default_model == name


def test_aliases_select_the_same_provider():
    assert resolve_model(ModelConfig(provider="gpt")).provider == "openai"
    assert resolve_model(ModelConfig(provider="claude")).provider == "anthropic"
    assert resolve_model(ModelConfig(provider="xai")).provider == "grok"
    assert resolve_model(ModelConfig(provider="google")).provider == "gemini"


def test_unknown_provider_is_refused():
    with pytest.raises(UsageError):
        resolve_model(ModelConfig(provider="local-model"))


def test_explicit_endpoint_and_model_are_kept():
    resolved = resolve_model(
        ModelConfig(provider="grok", base_url="https://example.invalid/v1", name="grok-custom")
    )
    assert resolved.base_url == "https://example.invalid/v1"
    assert resolved.name == "grok-custom"


def test_chat_providers_share_one_request_shape():
    for provider in ("openai", "grok", "gemini"):
        url, headers, body = build_request(
            ModelConfig(provider=provider, api_key="test-key"),
            "system text",
            "user text",
        )
        assert url.endswith("/chat/completions")
        assert headers["Authorization"] == "Bearer test-key"
        assert body["messages"][0] == {"role": "system", "content": "system text"}
        assert body["messages"][1] == {"role": "user", "content": "user text"}
        assert body["response_format"] == {"type": "json_object"}
        assert "temperature" not in body


def test_anthropic_uses_the_messages_shape():
    url, headers, body = build_request(
        ModelConfig(provider="anthropic", api_key="test-key"),
        "system text",
        "user text",
    )
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "test-key"
    assert "Authorization" not in headers
    assert body["system"] == "system text"
    assert body["messages"] == [{"role": "user", "content": "user text"}]
    assert body["model"] == "claude-sonnet-5-5"
    assert body["max_tokens"] == 4096


def test_a_full_endpoint_is_not_doubled():
    url, _headers, _body = build_request(
        ModelConfig(
            provider="openai",
            base_url="https://example.invalid/v1/chat/completions",
            api_key="test-key",
        ),
        "system",
        "user",
    )
    assert url == "https://example.invalid/v1/chat/completions"


def test_file_url_is_refused():
    with pytest.raises(UsageError):
        build_request(ModelConfig(base_url="file:///tmp/model", api_key="local"), "system", "user")


def test_replies_are_read_from_each_shape():
    chat = json.dumps({"choices": [{"message": {"content": "{\"ok\": true}"}}]}).encode()
    assert parse_reply("openai", chat) == "{\"ok\": true}"
    messages = json.dumps(
        {"content": [{"type": "text", "text": "{\"vote\": \"fixed\"}"}]}
    ).encode()
    assert parse_reply("anthropic", messages) == "{\"vote\": \"fixed\"}"


def test_prepare_model_uses_the_provider_from_the_environment(monkeypatch):
    monkeypatch.setenv("SILENTBLUE_PROVIDER", "claude")
    monkeypatch.setenv("SILENTBLUE_API_KEY", "test-key")
    monkeypatch.delenv("SILENTBLUE_BASE_URL", raising=False)
    monkeypatch.delenv("SILENTBLUE_MODEL", raising=False)
    prepared = _prepare_model(AppConfig(profile="assess"))
    assert prepared.model.provider == "anthropic"
    assert prepared.model.base_url == "https://api.anthropic.com/v1"
    assert prepared.model.name == "claude-sonnet-5-5"
    assert prepared.model.api_key == "test-key"
