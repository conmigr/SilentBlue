"""Per-run services that stay out of the checkpoint."""

from __future__ import annotations

import threading
from collections.abc import Callable

from silentblue.cost import dollars, rate_for
from silentblue.errors import UsageError
from silentblue.graph import CodeGraph
from silentblue.model import ModelClient, ModelReply, failure_label
from silentblue.models import AppConfig, RunState


class StageContext:
    """Config, model budget, and the in-memory symbol graph for one scan."""

    def __init__(self, config: AppConfig, client: ModelClient | None) -> None:
        self.config = config
        self.client = client
        self.model_calls = 0
        self.resumed_calls = 0
        self.answered_calls = 0
        self.call_failures: list[str] = []
        self.input_tokens = 0
        self.output_tokens = 0
        self.usage_known = True
        self.degraded = False
        self.budget_exhausted = False
        self.graph = CodeGraph()
        self.graph_ready = False
        self._lock = threading.Lock()
        self._local = threading.local()
        self.stop_event: threading.Event | None = None
        self.on_progress: Callable[[dict], None] | None = None
        self.on_usage: Callable[[ModelReply | None, str, str, str], None] | None = None
        self.store = None

    def should_stop(self) -> bool:
        """True when a new model call or unit must not start."""

        with self._lock:
            return self._blocked()

    def note_progress(self, **update: object) -> None:
        if self.on_progress is not None:
            self.on_progress(update)

    def complete(self, system: str, user: str) -> str | None:
        """Call the model once, or return None when the budget or the route fails."""

        if self.client is None:
            self.degraded = True
            self._local.failure = "call failed"
            return None
        self._local.refused = False
        self._local.failure = ""
        with self._lock:
            if self._blocked():
                self.budget_exhausted = True
                self._local.refused = True
                return None
            self.model_calls += 1
        try:
            reply = self.client.complete(system, user)
        except UsageError as exc:
            self._local.failure = failure_label(exc)
            self._fail(self._local.failure)
            raise
        except Exception as exc:
            self.degraded = True
            self._local.failure = failure_label(exc)
            self._fail(self._local.failure)
            return None
        return self._record(reply)

    def _blocked(self) -> bool:
        if self.stop_event is not None and self.stop_event.is_set():
            return True
        if self.model_calls >= self.config.model.max_calls:
            return True
        cap = self.config.budgets.max_cost_usd
        if cap is None or not self.usage_known:
            return False
        rate = rate_for(self.config.model.provider, self.config.model.name)
        if rate is None:
            return False
        return dollars(self.input_tokens, self.output_tokens, rate) >= cap

    def stamp(self, state: RunState) -> RunState:
        return state.model_copy(
            update={
                "model_calls": self.model_calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "usage_known": self.usage_known,
                "degraded": state.degraded or self.degraded,
            }
        )

    def note_loaded(self, state: RunState) -> None:
        self.model_calls = max(self.model_calls, state.model_calls)
        self.resumed_calls = self.model_calls
        self.input_tokens = max(self.input_tokens, state.input_tokens)
        self.output_tokens = max(self.output_tokens, state.output_tokens)
        self.usage_known = self.usage_known and state.usage_known
        self.degraded = self.degraded or state.degraded

    def _record(self, reply: str | ModelReply) -> str:
        with self._lock:
            if not isinstance(reply, ModelReply):
                self.usage_known = False
                recorded: ModelReply | None = None
                text = reply
            else:
                if reply.input_tokens is None or reply.output_tokens is None:
                    self.usage_known = False
                else:
                    self.input_tokens += reply.input_tokens
                    self.output_tokens += reply.output_tokens
                    self.answered_calls += 1
                if self._blocked():
                    self.budget_exhausted = True
                recorded = reply
                text = reply.text
        self._notify(recorded)
        return text

    def _fail(self, reason: str) -> None:
        with self._lock:
            self.call_failures.append(reason)
        self._notify(None, reason)

    def _notify(self, reply: ModelReply | None, failure: str = "") -> None:
        if self.on_usage is None:
            return
        self.on_usage(reply, self.config.model.provider, self.config.model.name, failure)
