import time

import laya

from llm_usage import Call, UsageLedger, current_tags, now_iso
from observability import NullTracer


class LayaClient:
    def __init__(self, model: str, usage: UsageLedger | None = None, tracer=None):
        self.model = model
        self.agent = laya.load(model)
        self.usage = usage if usage is not None else UsageLedger()
        self.tracer = tracer if tracer is not None else NullTracer()

    def _observed(self, call):
        """Run `call()` and record it. Laya reports no token counts, so only
        the call, its purpose and its time are known."""
        tags = current_tags()
        at, start_ns, clock = now_iso(), time.time_ns(), time.perf_counter()
        error = None
        try:
            return call()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:300]
            raise
        finally:
            ledger_call = Call(
                at=at, purpose=tags.get("purpose", "laya"), model=self.model, provider="laya",
                prompt_tokens=None, completion_tokens=None,
                duration_ms=int((time.perf_counter() - clock) * 1000),
                ok=error is None, error=error, ref=tags.get("ref"),
            )
            self.usage.record(ledger_call)
            self.tracer.span(
                name=ledger_call.purpose, start_ns=start_ns, end_ns=time.time_ns(),
                ok=ledger_call.ok, error=error,
                metadata={"model": self.model, "provider": "laya", "ref": ledger_call.ref},
            )

    def true_positive_score(self, state: str, question: str) -> float:
        questions = {
            "true_positive": {
                "type": "noul",
                "instructions": question,
            }
        }
        result = self._observed(lambda: self.agent.predict(state, questions))
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
        result = self._observed(lambda: self.agent.predict(state, questions))
        answers = result["answers"]
        score = answers["true_positive"]["noul"]
        choice = answers.get("next_question", {}).get("choice") if next_options else None
        return score, choice
