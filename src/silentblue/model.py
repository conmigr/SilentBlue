"""One completion route for GPT, Anthropic, Grok, and Gemini.

Detect scans never construct a client. GPT, Grok, and Gemini use the chat
completions shape. Anthropic uses the messages shape.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urlparse

from silentblue.errors import RunError, UsageError
from silentblue.models import ModelConfig

Wire = Literal["chat", "messages"]


@dataclass(frozen=True)
class ProviderSpec:
    """Default endpoint and model for one provider."""

    provider_id: str
    base_url: str
    default_model: str
    wire: Wire


PROVIDERS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        "openai",
        "https://api.openai.com/v1",
        "gpt-6.1-terra",
        "chat",
    ),
    "anthropic": ProviderSpec(
        "anthropic",
        "https://api.anthropic.com/v1",
        "claude-sonnet-5-5",
        "messages",
    ),
    "grok": ProviderSpec(
        "grok",
        "https://api.x.ai/v1",
        "grok-4.7",
        "chat",
    ),
    "gemini": ProviderSpec(
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-4-hydrogen",
        "chat",
    ),
}

_ALIASES = {
    "openai": "openai",
    "gpt": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "grok": "grok",
    "xai": "grok",
    "gemini": "gemini",
    "google": "gemini",
}

_ANTHROPIC_VERSION = "2026-10-21"
_ANTHROPIC_MAX_TOKENS = 4096


@dataclass(frozen=True)
class ModelReply:
    """Assistant text plus provider usage, when the response includes it."""

    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    thinking_tokens: int | None = None


class ModelClient(Protocol):
    """A single completion. Implementations must not log the credential."""

    def complete(self, system: str, user: str) -> str | ModelReply:
        """Return the assistant message text, with usage when the provider sends it."""


class HttpModelClient:
    """POST one chat request and return the assistant text."""

    def __init__(self, settings: ModelConfig) -> None:
        self.settings = resolve_model(settings)
        self.endpoint = _endpoint(self.settings)

    def complete(self, system: str, user: str) -> ModelReply:
        url, headers, payload = build_request(self.settings, system, user)
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.settings.timeout_s) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise UsageError("model endpoint rejected the credential") from exc
            raise RunError("model endpoint returned an error") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RunError("model endpoint was unreachable") from exc
        text = parse_reply(self.settings.provider, raw)
        prompt_tokens, completion_tokens = parse_usage(self.settings.provider, raw)
        return ModelReply(text, prompt_tokens, completion_tokens, parse_thinking(self.settings.provider, raw))


def canonical_provider(name: str) -> str:
    """Return the provider id. Aliases such as ``gpt`` and ``claude`` are accepted."""

    key = name.strip().lower()
    if key not in _ALIASES:
        raise UsageError("provider must be openai, anthropic, grok, or gemini")
    return _ALIASES[key]


def resolve_model(settings: ModelConfig) -> ModelConfig:
    """Fill an empty endpoint or model name from the provider."""

    provider = canonical_provider(settings.provider or "openai")
    spec = PROVIDERS[provider]
    return settings.model_copy(
        update={
            "provider": provider,
            "base_url": settings.base_url.strip() or spec.base_url,
            "name": settings.name.strip() or spec.default_model,
        }
    )


def configured_model(settings: ModelConfig) -> ModelConfig:
    """Apply the operator environment, then the provider default. No network call."""

    updates: dict[str, str] = {}
    if os.environ.get("SILENTBLUE_PROVIDER"):
        updates["provider"] = os.environ["SILENTBLUE_PROVIDER"]
    if not settings.api_key and os.environ.get("SILENTBLUE_API_KEY"):
        updates["api_key"] = os.environ["SILENTBLUE_API_KEY"]
    if os.environ.get("SILENTBLUE_BASE_URL"):
        updates["base_url"] = os.environ["SILENTBLUE_BASE_URL"]
    if os.environ.get("SILENTBLUE_MODEL"):
        updates["name"] = os.environ["SILENTBLUE_MODEL"]
    if updates:
        settings = settings.model_copy(update=updates)
    return resolve_model(settings)


def route_status(settings: ModelConfig) -> list[str]:
    """Describe the model the next assess call will use. No network call."""

    resolved = resolve_model(settings)
    endpoint = _endpoint(resolved)
    key = "present" if resolved.api_key.strip() else "absent"
    lines = [
        f"Provider: {resolved.provider}",
        f"Model: {resolved.name}",
        f"Endpoint: {endpoint}",
        f"Assess key: {key}",
    ]
    try:
        from silentblue.cost import rate_for

        rate = rate_for(resolved.provider, resolved.name)
    except UsageError as exc:
        lines.append(str(exc))
        return lines
    if rate is None:
        lines.append(
            "Price: unknown. Set SILENTBLUE_PRICE_INPUT_PER_MILLION and "
            "SILENTBLUE_PRICE_OUTPUT_PER_MILLION in .env."
        )
    else:
        lines.append(
            f"Price: {rate[0]} USD per million input tokens, "
            f"{rate[1]} USD per million output tokens."
        )
    if resolved.provider == "gemini" and "/openai" in endpoint:
        lines.append(
            "Gemini uses this OpenAI-compatible endpoint. "
            "Set SILENTBLUE_MODEL to choose Flash. Leave SILENTBLUE_BASE_URL unset."
        )
    return lines


def failure_label(exc: BaseException) -> str:
    """A short reason for a model call that did not return text."""

    text = str(exc)
    if "rejected the credential" in text:
        return "credential"
    if "unreachable" in text:
        return "unreachable"
    if "returned an error" in text:
        return "endpoint error"
    if "reply was empty" in text:
        return "empty reply"
    return "call failed"


def build_request(settings: ModelConfig, system: str, user: str) -> tuple[str, dict[str, str], dict]:
    """Return the URL, headers, and JSON body for one completion."""

    resolved = resolve_model(settings)
    spec = PROVIDERS[resolved.provider]
    if spec.wire == "messages":
        headers = {
            "content-type": "application/json",
            "x-api-key": resolved.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
        }
        body = {
            "model": resolved.name,
            "max_tokens": _ANTHROPIC_MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {resolved.api_key}",
        }
        body = {
            "model": resolved.name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
    return _endpoint(resolved), headers, body


def parse_reply(provider: str, raw: bytes) -> str:
    """Read the assistant text. The response body is not included in errors."""

    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RunError("model reply was empty") from exc
    spec = PROVIDERS[canonical_provider(provider)]
    if spec.wire == "messages":
        text = _anthropic_text(body)
    else:
        text = _chat_text(body)
    if not text.strip():
        raise RunError("model reply was empty")
    return text


def parse_usage(provider: str, raw: bytes) -> tuple[int | None, int | None]:
    """Read token counts. Missing usage is unknown, not zero."""

    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError):
        return None, None
    if not isinstance(body, dict) or not isinstance(body.get("usage"), dict):
        return None, None
    usage = body["usage"]
    spec = PROVIDERS[canonical_provider(provider)]
    if spec.wire == "messages":
        return _count(usage.get("input_tokens")), _count(usage.get("output_tokens"))
    return _count(usage.get("prompt_tokens")), _count(usage.get("completion_tokens"))


def parse_thinking(provider: str, raw: bytes) -> int | None:
    """Read a reasoning count when the provider sends one. Missing stays unknown."""

    canonical_provider(provider)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(body, dict) or not isinstance(body.get("usage"), dict):
        return None
    usage = body["usage"]
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        counted = _count(details.get("reasoning_tokens"))
        if counted is not None:
            return counted
    for key in ("reasoning_tokens", "thinking_tokens", "thoughts_token_count"):
        counted = _count(usage.get(key))
        if counted is not None:
            return counted
    output_details = usage.get("output_tokens_details")
    if isinstance(output_details, dict):
        return _count(output_details.get("thinking_tokens"))
    return None


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _endpoint(settings: ModelConfig) -> str:
    spec = PROVIDERS[settings.provider]
    parsed = urlparse(settings.base_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UsageError("model base_url must be an http(s) endpoint")
    root = settings.base_url.rstrip("/")
    suffix = "/messages" if spec.wire == "messages" else "/chat/completions"
    if root.endswith(suffix):
        return root
    return root + suffix


def _chat_text(body: object) -> str:
    if not isinstance(body, dict):
        return ""
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""
    return _flatten(content)


def _anthropic_text(body: object) -> str:
    if not isinstance(body, dict):
        return ""
    return _flatten(body.get("content"))


def _flatten(content: object) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict) and isinstance(item.get("text"), str):
            if item.get("type") in {None, "text", "output_text"}:
                parts.append(item["text"])
    return "".join(parts)
