import ollama


class OllamaClient:
    def __init__(self, host: str, model: str):
        self.client = ollama.Client(host=host)
        self.model = model

    def generate(self, prompt: str) -> str:
        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response["message"]["content"]
