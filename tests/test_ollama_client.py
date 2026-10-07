import os
from unittest.mock import patch

import httpx
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

import ollama_client
from llm_usage import tag
from ollama_client import GENERATION_OPTIONS, LLMOutputLimitError, OllamaClient


class FakeChat(BaseChatModel):
    """A chat model that returns canned replies the way ChatOllama reports them."""
    replies: list = []
    seen: list = []

    @property
    def _llm_type(self) -> str:
        return "fake"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(messages[0].content)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        message = AIMessage(
            content=reply.get("content", "hello from model"),
            usage_metadata={"input_tokens": reply.get("in", 30), "output_tokens": reply.get("out", 12),
                            "total_tokens": reply.get("in", 30) + reply.get("out", 12)},
            response_metadata={"done_reason": reply.get("done", "stop"), "model": "test-model"},
        )
        return ChatResult(generations=[ChatGeneration(message=message)])


class RecordingTracer:
    enabled = True

    def __init__(self):
        self.generations = []

    def generation(self, **kw):
        self.generations.append(kw)

    def span(self, **kw):
        pass


def client_with(replies, tracer=None):
    built = []

    def make(**kwargs):
        built.append(kwargs)
        return FakeChat(replies=replies, seen=[])

    with patch.object(ollama_client, "ChatOllama", side_effect=make):
        c = OllamaClient(host="http://localhost:11434", model="test-model", tracer=tracer)
        c._built = built
        return c


def test_generate_returns_the_reply_and_builds_the_model_with_our_options():
    c = client_with([{"content": "hello from model"}])
    with patch.object(ollama_client, "ChatOllama", side_effect=lambda **kw: (c._built.append(kw), FakeChat(replies=[{"content": "hello from model"}], seen=[]))[1]):
        assert c.generate("say hi") == "hello from model"
    kwargs = c._built[-1]
    assert kwargs["model"] == "test-model" and kwargs["base_url"] == "http://localhost:11434"
    assert kwargs["client_kwargs"]["timeout"] > 0
    for key, value in GENERATION_OPTIONS.items():
        assert kwargs[key] == value
    assert "reasoning" not in kwargs  # default: leave the model's own thinking behaviour alone


def test_options_are_seeded_capped_and_not_greedy():
    # temperature 0 caused an endless repetition loop in a real run
    assert GENERATION_OPTIONS["temperature"] > 0
    assert GENERATION_OPTIONS["seed"] == 42
    assert GENERATION_OPTIONS["num_predict"] > 0


def test_think_false_is_passed_as_reasoning_off_and_a_model_override_is_honoured():
    c = OllamaClient("h", "main-model")
    built = []
    with patch.object(ollama_client, "ChatOllama",
                      side_effect=lambda **kw: (built.append(kw), FakeChat(replies=[{}], seen=[]))[1]):
        c.generate("x", think=False, model="coder-model")
    assert built[0]["reasoning"] is False and built[0]["model"] == "coder-model"


def test_every_call_is_recorded_with_tokens_purpose_and_what_it_was_about():
    c = OllamaClient("h", "test-model")
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=[{"in": 120, "out": 45}], seen=[])):
        with tag(purpose="fix", ref="app.py:98"):
            c.generate("fix this")
    [call] = c.usage.calls()
    assert (call.purpose, call.ref, call.model, call.provider) == ("fix", "app.py:98", "test-model", "ollama")
    assert (call.prompt_tokens, call.completion_tokens, call.ok) == (120, 45, True)
    assert call.duration_ms >= 0
    s = c.usage.summary()
    assert s["total_tokens"] == 165 and s["by_purpose"]["fix"]["calls"] == 1
    assert s["by_model"]["test-model"]["prompt_tokens"] == 120


def test_untagged_calls_are_still_counted():
    c = OllamaClient("h", "m")
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=[{}], seen=[])):
        c.generate("x")
    assert c.usage.calls()[0].purpose == "other"


def test_reply_cut_off_at_the_output_limit_raises_and_is_marked_in_the_ledger():
    c = OllamaClient("h", "m")
    with patch.object(ollama_client, "ChatOllama",
                      return_value=FakeChat(replies=[{"content": "loop loop", "done": "length"}], seen=[])):
        with pytest.raises(LLMOutputLimitError):
            c.generate("x")
    [call] = c.usage.calls()
    assert call.truncated and not call.ok and "limit" in call.error


def test_a_failed_call_is_recorded_and_the_error_still_reaches_the_caller():
    c = OllamaClient("h", "m")
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=[RuntimeError("model crashed")], seen=[])):
        with pytest.raises(RuntimeError, match="model crashed"):
            c.generate("x")
    [call] = c.usage.calls()
    assert not call.ok and "model crashed" in call.error


def test_only_connection_failures_are_retried():
    c = OllamaClient("h", "m")
    replies = [httpx.ConnectError("down"), ConnectionError("still down"), {"content": "back"}]
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=replies, seen=[])), \
         patch.object(ollama_client.time, "sleep") as sleep:
        assert c.generate("x") == "back"
    assert sleep.call_count == 2

    c2 = OllamaClient("h", "m")
    with patch.object(ollama_client, "ChatOllama",
                      return_value=FakeChat(replies=[httpx.ReadTimeout("slow")], seen=[])), \
         patch.object(ollama_client.time, "sleep") as sleep:
        with pytest.raises(httpx.ReadTimeout):
            c2.generate("x")
    assert sleep.call_count == 0  # a read timeout is not retried


def test_gives_up_after_the_retry_budget():
    c = OllamaClient("h", "m")
    replies = [ConnectionError("down")] * 5
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=replies, seen=[])), \
         patch.object(ollama_client.time, "sleep"):
        with pytest.raises(ConnectionError):
            c.generate("x")
    assert len(c.usage.calls()) == ollama_client.CONNECT_RETRIES + 1


def test_the_tracer_gets_each_call_with_its_token_usage_and_prompt():
    tracer = RecordingTracer()
    c = OllamaClient("h", "m", tracer=tracer)
    with patch.object(ollama_client, "ChatOllama", return_value=FakeChat(replies=[{"in": 10, "out": 3, "content": "ans"}], seen=[])):
        with tag(purpose="review", ref="a.py:1"):
            c.generate("the prompt text")
    [g] = tracer.generations
    assert g["name"] == "review" and g["model"] == "m"
    assert (g["prompt_tokens"], g["completion_tokens"]) == (10, 3)
    assert g["input"] == "the prompt text" and g["output"] == "ans" and g["ok"] is True
    assert g["metadata"]["ref"] == "a.py:1"


def test_langsmith_cloud_tracing_is_always_off():
    # Prompts contain source code; LangChain's hosted tracing must never be enabled.
    for name in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2"):
        assert os.environ[name] == "false"
