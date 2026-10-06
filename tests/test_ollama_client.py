from unittest.mock import MagicMock, patch

from ollama_client import OllamaClient


def test_generate_returns_message_content():
    with patch("ollama_client.ollama.Client") as MockClient:
        instance = MockClient.return_value
        instance.chat.return_value = {"message": {"content": "hello from model"}}

        client = OllamaClient(host="http://localhost:11434", model="test-model")
        result = client.generate("say hi")

        assert result == "hello from model"
        instance.chat.assert_called_once_with(
            model="test-model",
            messages=[{"role": "user", "content": "say hi"}],
            # Deterministic: the same code must get the same triage answers.
            options={"temperature": 0, "seed": 42},
        )
