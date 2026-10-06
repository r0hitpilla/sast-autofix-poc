from unittest.mock import patch

import pytest

from ollama_client import GENERATION_OPTIONS, LLMOutputLimitError, OllamaClient


def test_generate_returns_message_content():
    with patch("ollama_client.ollama.Client") as MockClient:
        instance = MockClient.return_value
        instance.chat.return_value = {"message": {"content": "hello from model"}, "done_reason": "stop"}

        client = OllamaClient(host="http://localhost:11434", model="test-model")
        result = client.generate("say hi")

        assert result == "hello from model"
        instance.chat.assert_called_once_with(
            model="test-model",
            messages=[{"role": "user", "content": "say hi"}],
            options=GENERATION_OPTIONS,
        )
        assert MockClient.call_args.kwargs["timeout"] > 0


def test_options_are_seeded_capped_and_not_greedy():
    # temperature 0 caused an endless repetition loop in a real run
    assert GENERATION_OPTIONS["temperature"] > 0
    assert GENERATION_OPTIONS["seed"] == 42
    assert GENERATION_OPTIONS["num_predict"] > 0


def test_reply_cut_off_at_the_output_limit_raises():
    with patch("ollama_client.ollama.Client") as MockClient:
        MockClient.return_value.chat.return_value = {
            "message": {"content": "loop loop loop"}, "done_reason": "length",
        }
        with pytest.raises(LLMOutputLimitError):
            OllamaClient(host="h", model="m").generate("x")
