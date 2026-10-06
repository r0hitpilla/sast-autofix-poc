import ollama


# Greedy decoding with a fixed seed: the same code should get the same
# triage answers on every run. With sampling, one SQL injection scored 0.85
# ("fix") on one run and 0.37 ("reject") on the next.
DETERMINISTIC = {"temperature": 0, "seed": 42}


class OllamaClient:
    def __init__(self, host: str, model: str):
        self.client = ollama.Client(host=host)
        self.model = model

    def generate(self, prompt: str) -> str:
        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            options=DETERMINISTIC,
        )
        return response["message"]["content"]
