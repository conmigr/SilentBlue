"""Session cost ledger. Prices are the same list rates as the report."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from silentblue.cost import actual_cost, format_usd
from silentblue.model import ModelReply

_WORKS = ("scan", "assess", "threat-model", "nlp")
_NOTE = (
    "USD prices input and output tokens. "
    "Thinking tokens are reported separately and are not priced again."
)


@dataclass(frozen=True)
class _Call:
    work: str
    provider: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    thinking_tokens: int | None
    failure: str = ""


class SessionLedger:
    """Model calls made since this session started."""

    def __init__(self) -> None:
        self._calls: list[_Call] = []
        self._noted: set[str] = set()
        self._lock = threading.Lock()

    def add(self, work: str, reply: object, provider: str, model: str, failure: str = "") -> None:
        """Record one completion. A reply without usage stays unknown."""

        if isinstance(reply, ModelReply):
            item = _Call(
                work,
                provider or "unknown",
                model or "unknown",
                reply.input_tokens,
                reply.output_tokens,
                reply.thinking_tokens,
                failure,
            )
        else:
            item = _Call(work, provider or "unknown", model or "unknown", None, None, None, failure)
        with self._lock:
            self._calls.append(item)
            self._noted.add(work)

    def note_scan(self, work: str) -> None:
        """Remember a scan that made no model call, so its cost stays visible at zero."""

        with self._lock:
            self._noted.add(work)

    def render(self) -> list[str]:
        """Labeled totals, one line per work, one line per model, then the matrix."""

        with self._lock:
            calls = list(self._calls)
            noted = set(self._noted)
        works = [name for name in _WORKS if name in noted or any(item.work == name for item in calls)]
        for item in calls:
            if item.work not in works:
                works.append(item.work)
        total_calls = len(calls)
        total_usd, _total_known = _price(calls)
        lines = [
            f"Total USD: {total_usd}",
            f"Model calls: {total_calls}",
            *_cost_notes(calls),
            "",
            "Work",
        ]
        if not works:
            lines.append("No work yet.")
        for work in works:
            rows = [item for item in calls if item.work == work]
            usd, calls_n, incoming, outgoing, thinking = _cells(rows)
            lines.append(
                f"{work}: {usd} USD, calls {calls_n}, in {incoming}, out {outgoing}, thinking {thinking}"
            )
        lines.extend(["", "Models"])
        models = _model_keys(calls)
        if not models:
            lines.append("No model calls.")
        for provider, model in models:
            rows = [item for item in calls if item.provider == provider and item.model == model]
            usd, calls_n, incoming, outgoing, thinking = _cells(rows)
            lines.append(
                f"{provider} {model}: {usd} USD, calls {calls_n}, "
                f"in {incoming}, out {outgoing}, thinking {thinking}"
            )
        lines.extend(["", "Matrix"])
        emitted = False
        for work in works:
            keys = _model_keys([item for item in calls if item.work == work])
            if not keys:
                lines.extend(_block(work, "none", _cells([])))
                emitted = True
                continue
            for provider, model in keys:
                rows = [
                    item
                    for item in calls
                    if item.work == work and item.provider == provider and item.model == model
                ]
                lines.extend(_block(work, f"{provider} {model}", _cells(rows)))
                emitted = True
        if not emitted:
            lines.append("None.")
        return lines

    def activity(self) -> str:
        """Say whether this session has called the model."""

        with self._lock:
            calls = list(self._calls)
        if not calls:
            return "This session has not called the model."
        answered = sum(
            1
            for call in calls
            if call.input_tokens is not None and call.output_tokens is not None
        )
        failures = [call.failure for call in calls if call.failure]
        parts: list[str] = []
        if answered:
            parts.append(f"{_counted(answered)} returned tokens")
        if failures:
            parts.append(f"{_counted(len(failures))} failed: {_unique(failures)}")
        if not parts:
            return "This session called the model and received no token counts."
        return "This session: " + "; ".join(parts) + "."


def _cost_notes(calls: list[_Call]) -> list[str]:
    notes = [_NOTE]
    unpriced: list[str] = []
    thinking_missing = False
    for call in calls:
        if call.input_tokens is None or call.output_tokens is None:
            continue
        if call.thinking_tokens is None:
            thinking_missing = True
        label = f"{call.provider} {call.model}"
        _spent, known = actual_cost(
            call.input_tokens,
            call.output_tokens,
            provider=call.provider,
            model_name=call.model,
            usage_known=True,
            made_calls=True,
        )
        if not known and label not in unpriced:
            unpriced.append(label)
    for label in unpriced:
        notes.append(
            f"USD is unknown for {label}. Set SILENTBLUE_PRICE_INPUT_PER_MILLION and "
            "SILENTBLUE_PRICE_OUTPUT_PER_MILLION in .env, then quit and start the session again."
        )
    if thinking_missing:
        notes.append("Thinking is unknown. This model sent no reasoning count.")
    return notes


def _counted(count: int) -> str:
    noun = "call" if count == 1 else "calls"
    return f"{count} {noun}"


def _unique(reasons: list[str]) -> str:
    ordered: list[str] = []
    for reason in reasons:
        if reason not in ordered:
            ordered.append(reason)
    return ", ".join(ordered)


def _model_keys(calls: list[_Call]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for item in calls:
        key = (item.provider, item.model)
        if key not in keys:
            keys.append(key)
    return keys


def _block(work: str, model: str, cells: tuple[str, str, str, str, str]) -> list[str]:
    usd, calls_n, incoming, outgoing, thinking = cells
    return [
        f"Work: {work}",
        f"Model: {model}",
        f"Calls: {calls_n}",
        f"In: {incoming}",
        f"Out: {outgoing}",
        f"Thinking: {thinking}",
        f"USD: {usd}",
        "",
    ]


def _cells(calls: list[_Call]) -> tuple[str, str, str, str, str]:
    if not calls:
        return "0.0000", "0", "0", "0", "0"
    usd, _known = _price(calls)
    return (
        usd,
        str(len(calls)),
        _sum(call.input_tokens for call in calls),
        _sum(call.output_tokens for call in calls),
        _sum(call.thinking_tokens for call in calls),
    )


def _price(calls: list[_Call]) -> tuple[str, bool]:
    if not calls:
        return "0.0000", True
    total = 0.0
    for call in calls:
        if call.input_tokens is None or call.output_tokens is None:
            return "unknown", False
        spent, rate_known = actual_cost(
            call.input_tokens,
            call.output_tokens,
            provider=call.provider,
            model_name=call.model,
            usage_known=True,
            made_calls=True,
        )
        if spent is None or not rate_known:
            return "unknown", False
        total += spent
    return format_usd(total, True), True


def _sum(values) -> str:
    total = 0
    for value in values:
        if value is None:
            return "unknown"
        total += value
    return str(total)
