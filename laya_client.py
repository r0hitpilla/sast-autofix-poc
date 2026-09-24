import laya


class LayaClient:
    def __init__(self, model: str):
        self.agent = laya.load(model)

    def true_positive_score(self, state: str, question: str) -> float:
        questions = [{
            "key": "true_positive",
            "type": "noul",
            "instructions": question,
        }]
        result = self.agent.predict(state, questions)
        return result["true_positive"]["noul"]
