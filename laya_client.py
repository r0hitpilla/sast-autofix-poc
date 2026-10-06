import laya


class LayaClient:
    def __init__(self, model: str):
        self.agent = laya.load(model)

    def true_positive_score(self, state: str, question: str) -> float:
        questions = {
            "true_positive": {
                "type": "noul",
                "instructions": question,
            }
        }
        result = self.agent.predict(state, questions)
        return result["answers"]["true_positive"]["noul"]

    def assess(self, state: str, question: str, next_options: dict[str, str]) -> tuple[float, str | None]:
        """Score the finding AND pick which piece of evidence to ask the LLM for next.

        Both questions go in one forward pass. `next_options` maps an option id
        to a description of the evidence it would gather; Laya's choice is
        returned as that id (or None when there is nothing left to ask).
        """
        questions = {
            "true_positive": {
                "type": "noul",
                "instructions": question,
            }
        }
        if next_options:
            questions["next_question"] = {
                "type": "choice",
                "instructions": (
                    "Which missing piece of evidence would most change the "
                    "verdict on whether this finding is a true positive?"
                ),
                "criteria": next_options,
            }
        result = self.agent.predict(state, questions)
        answers = result["answers"]
        score = answers["true_positive"]["noul"]
        choice = answers.get("next_question", {}).get("choice") if next_options else None
        return score, choice
