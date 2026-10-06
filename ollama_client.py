import ollama

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


class LLMOutputLimitError(RuntimeError):
    """The reply was cut off at num_predict — almost always a runaway loop."""


class OllamaClient:
    def __init__(self, host: str, model: str):
        self.client = ollama.Client(host=host, timeout=REQUEST_TIMEOUT_SECONDS)
        self.model = model

    def generate(self, prompt: str, think: bool | None = None, model: str | None = None) -> str:
        """`think=False` skips the model's hidden reasoning. Fix generation
        uses it: with reasoning on, qwen3.5 regularly ran into the output cap
        on edit prompts; without it, a correct edit takes ~2 s. `None` keeps
        the model's default (used for triage, where the reasoning helps)."""
        kwargs = {} if think is None else {"think": think}
        response = self.client.chat(
            model=model or self.model,
            messages=[{"role": "user", "content": prompt}],
            options=GENERATION_OPTIONS,
            **kwargs,
        )
        if response.get("done_reason") == "length":
            # A truncated reply is unusable (no VERDICT line, half an edit
            # block). Raising routes it through the callers' existing failure
            # handling: triage -> review, fix -> failed attempt, retried.
            raise LLMOutputLimitError(
                f"LLM reply hit the {GENERATION_OPTIONS['num_predict']}-token output "
                "limit (likely a repetition loop)"
            )
        return response["message"]["content"]
