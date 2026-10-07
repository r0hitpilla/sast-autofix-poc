"""The pipeline's LLM client: LangChain's ChatOllama behind a one-method API.

Every AI call in the pipeline goes through `OllamaClient.generate`, so this is
the one place that counts tokens and time (llm_usage.py) and traces to
Langfuse (observability.py). LangChain does the model call and reports usage
through its callback system; swapping the model server later (another Ollama
box, vLLM) means changing how the chat model is built in `_chat`, not the
callers.
"""

import os
import time

import httpx
from langchain_core.callbacks import BaseCallbackHandler
from langchain_ollama import ChatOllama

from llm_usage import Call, UsageLedger, current_tags, now_iso
from observability import NullTracer

# LangChain can ship traces to LangSmith, a hosted service. Prompts here contain
# the client's source code, so that is switched off, whatever the environment says.
for _name in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING"):
    os.environ[_name] = "false"

# Reproducible but not greedy. Greedy decoding (temperature 0) let the model's
# hidden "thinking" fall into a repetition loop that never ended, stalling a
# run for 19+ minutes. A low temperature with a fixed seed still gives the same
# answer for the same prompt on every run; the cap and penalty bound a loop.
GENERATION_OPTIONS = {
    "temperature": 0.2,
    "seed": 42,
    "num_predict": 8192,      # thinking + answer tokens per reply
    "repeat_penalty": 1.1,
}
REQUEST_TIMEOUT_SECONDS = 600
# Only "could not connect" is retried (Ollama restarting). A read timeout means
# the model is busy for ten minutes; waiting again would just triple the stall.
CONNECT_RETRIES = 2
CONNECT_BACKOFF_SECONDS = (2, 6)
RETRYABLE = (ConnectionError, httpx.ConnectError)


class LLMOutputLimitError(RuntimeError):
    """The reply was cut off at num_predict — almost always a runaway loop."""


class UsageCallback(BaseCallbackHandler):
    """Turns each LangChain model call into a ledger entry and a Langfuse generation."""

    def __init__(self, ledger: UsageLedger, tracer, provider: str = "ollama"):
        self.ledger, self.tracer, self.provider = ledger, tracer, provider
        self._open: dict = {}

    def on_chat_model_start(self, serialized, messages, *, run_id, metadata=None, **kwargs):
        prompt = "\n".join(str(m.content) for m in (messages[0] if messages else []))
        self._open[run_id] = {
            "at": now_iso(), "ns": time.time_ns(), "clock": time.perf_counter(),
            "prompt": prompt, "meta": metadata or {},
        }

    def _finish(self, run_id, *, ok, error=None, message=None):
        start = self._open.pop(run_id, None)
        if start is None:
            return
        meta = start["meta"]
        usage = getattr(message, "usage_metadata", None) or {}
        info = getattr(message, "response_metadata", None) or {}
        truncated = info.get("done_reason") == "length"
        prompt_tokens = usage.get("input_tokens", info.get("prompt_eval_count"))
        completion_tokens = usage.get("output_tokens", info.get("eval_count"))
        duration_ms = int((time.perf_counter() - start["clock"]) * 1000)
        ok = ok and not truncated
        if truncated and not error:
            error = "reply hit the output-token limit"
        call = Call(
            at=start["at"], purpose=meta.get("purpose", "other"), model=meta.get("model", "?"),
            provider=self.provider, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            duration_ms=duration_ms, ok=ok, error=error, truncated=truncated, ref=meta.get("ref"),
        )
        self.ledger.record(call)
        self.tracer.generation(
            name=call.purpose, model=call.model, start_ns=start["ns"], end_ns=time.time_ns(),
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            input=start["prompt"], output=str(getattr(message, "content", "")) if message else None,
            ok=ok, error=error, parameters=GENERATION_OPTIONS,
            metadata={"purpose": call.purpose, "ref": call.ref, "provider": self.provider,
                      "think": meta.get("think"), "truncated": truncated},
        )

    def on_llm_end(self, response, *, run_id, **kwargs):
        message = None
        try:
            message = response.generations[0][0].message
        except (AttributeError, IndexError):
            pass
        self._finish(run_id, ok=True, message=message)

    def on_llm_error(self, error, *, run_id, **kwargs):
        self._finish(run_id, ok=False, error=f"{type(error).__name__}: {error}"[:300])


class OllamaClient:
    def __init__(self, host: str, model: str, usage: UsageLedger | None = None, tracer=None):
        self.host, self.model = host, model
        self.usage = usage if usage is not None else UsageLedger()
        self.tracer = tracer if tracer is not None else NullTracer()
        self._callback = UsageCallback(self.usage, self.tracer)
        self._chats: dict = {}

    def _chat(self, model: str, think: bool | None) -> ChatOllama:
        key = (model, think)
        if key not in self._chats:
            extra = {} if think is None else {"reasoning": think}
            self._chats[key] = ChatOllama(
                model=model, base_url=self.host, client_kwargs={"timeout": REQUEST_TIMEOUT_SECONDS},
                **GENERATION_OPTIONS, **extra,
            )
        return self._chats[key]

    def generate(self, prompt: str, think: bool | None = None, model: str | None = None) -> str:
        """`think=False` skips the model's hidden reasoning. Fix generation
        uses it: with reasoning on, qwen3.5 regularly ran into the output cap
        on edit prompts; without it, a correct edit takes ~2 s. `None` keeps
        the model's default (used for triage, where the reasoning helps)."""
        name = model or self.model
        tags = current_tags()
        config = {
            "callbacks": [self._callback], "run_name": tags.get("purpose", "llm"),
            "metadata": {"purpose": tags.get("purpose", "other"), "ref": tags.get("ref"),
                         "model": name, "think": think},
        }
        chat = self._chat(name, think)
        attempt = 0
        while True:
            try:
                message = chat.invoke(prompt, config=config)
                break
            except RETRYABLE:
                if attempt >= CONNECT_RETRIES:
                    raise
                time.sleep(CONNECT_BACKOFF_SECONDS[min(attempt, len(CONNECT_BACKOFF_SECONDS) - 1)])
                attempt += 1
        if (message.response_metadata or {}).get("done_reason") == "length":
            # A truncated reply is unusable (no VERDICT line, half an edit
            # block). Raising routes it through the callers' existing failure
            # handling: triage -> review, fix -> failed attempt, retried.
            raise LLMOutputLimitError(
                f"LLM reply hit the {GENERATION_OPTIONS['num_predict']}-token output "
                "limit (likely a repetition loop)"
            )
        return message.content
