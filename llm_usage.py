"""A record of every AI call a run makes: which model, what for, how many
tokens, how long.

Every call goes through one place (ollama_client.py for the LLM, laya_client.py
for Laya), so this is complete by construction: a call that isn't in the
ledger didn't happen. The ledger goes into the run report, from there into the
dashboard, and (optionally) to Langfuse.

What a call is FOR is not known to the client, so the code around a call says
so with `tag(purpose=..., ref=...)`; the client reads the tags. That keeps
every call site's signature unchanged.
"""

import contextlib
import contextvars
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

_tags: contextvars.ContextVar[dict] = contextvars.ContextVar("llm_tags", default={})

# A run makes dozens of calls, not millions. The cap only stops a runaway loop
# from growing the report without bound.
MAX_CALLS = 5000


@contextlib.contextmanager
def tag(**values):
    """Label every AI call made inside the block, e.g. tag(purpose="fix", ref="app.py:98")."""
    token = _tags.set({**_tags.get(), **{k: v for k, v in values.items() if v is not None}})
    try:
        yield
    finally:
        _tags.reset(token)


def current_tags() -> dict:
    return dict(_tags.get())


@dataclass
class Call:
    at: str                      # when it started, ISO UTC
    purpose: str                 # triage | triage_followup | fix | review | proof | laya_triage ...
    model: str
    provider: str                # ollama | openai_compatible | laya
    prompt_tokens: int | None    # None when the provider doesn't count (Laya)
    completion_tokens: int | None
    duration_ms: int
    ok: bool
    error: str | None = None
    truncated: bool = False      # the reply hit the output limit
    ref: str | None = None       # what it was about, e.g. "app.py:98"
    # Where Langfuse shows this call, when tracing was on: the dashboard uses
    # them to fetch the prompt and reply and to link to the trace.
    trace_id: str | None = None
    span_id: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _blank() -> dict:
    return {"calls": 0, "errors": 0, "truncated": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "total_tokens": 0, "duration_ms": 0}


def _add(bucket: dict, call: Call) -> None:
    bucket["calls"] += 1
    bucket["errors"] += 0 if call.ok else 1
    bucket["truncated"] += 1 if call.truncated else 0
    bucket["prompt_tokens"] += call.prompt_tokens or 0
    bucket["completion_tokens"] += call.completion_tokens or 0
    bucket["total_tokens"] += (call.prompt_tokens or 0) + (call.completion_tokens or 0)
    bucket["duration_ms"] += call.duration_ms


class UsageLedger:
    def __init__(self):
        self._calls: list[Call] = []
        self._lock = threading.Lock()
        self.dropped = 0

    def record(self, call: Call) -> None:
        with self._lock:
            if len(self._calls) >= MAX_CALLS:
                self.dropped += 1
                return
            self._calls.append(call)

    def calls(self) -> list[Call]:
        with self._lock:
            return list(self._calls)

    def summary(self) -> dict:
        totals, by_purpose, by_model = _blank(), {}, {}
        counted = 0
        for call in self.calls():
            _add(totals, call)
            _add(by_purpose.setdefault(call.purpose, _blank()), call)
            _add(by_model.setdefault(call.model, _blank()), call)
            counted += 1 if call.prompt_tokens is not None else 0
        return {**totals, "calls_with_token_counts": counted, "dropped": self.dropped,
                "by_purpose": by_purpose, "by_model": by_model}

    def report(self) -> dict:
        """The shape stored in the run report (schema documented in report.py)."""
        return {"summary": self.summary(), "calls": [asdict(c) for c in self.calls()]}
