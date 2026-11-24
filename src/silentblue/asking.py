"""One JSON completion, with a single retry when the reply is not the requested object."""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ValidationError

from silentblue.redact import redact
from silentblue.runtime import StageContext


def ask_json(ctx: StageContext, system: str, user: str, shape: type[BaseModel]) -> BaseModel | None:
    """Return a validated object, or None when the budget or the route fails."""

    prompt = redact(user)
    raw = ctx.complete(system, prompt)
    parsed = _fit(raw, shape)
    if parsed is not None or raw is None:
        return parsed
    retry = ctx.complete(
        system,
        prompt + "\n\nThe previous reply was not a valid JSON object. Return one JSON object.",
    )
    parsed = _fit(retry, shape)
    if parsed is None and retry is not None:
        ctx.degraded = True
    return parsed


def _fit(raw: str | None, shape: type[BaseModel]) -> BaseModel | None:
    if raw is None:
        return None
    try:
        return shape.model_validate(_parse_object(raw))
    except (ValueError, ValidationError, json.JSONDecodeError):
        return None


def _parse_object(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no json object")
    data = json.loads(cleaned[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data
