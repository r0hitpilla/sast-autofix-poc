import re
import sys

from models import Finding, TriageResult

TRIAGE_QUESTION = "is this a true positive security vulnerability"

VERDICT_INSTRUCTION = (
    "\n\nEnd your answer with exactly one final line of the form:\n"
    "VERDICT: <one-sentence conclusion>"
)
VERDICT_RE = re.compile(r"^[\s*_`#>-]*VERDICT[\s*_`]*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# Laya reads at most ~512 tokens and drops everything past that. The evidence
# lines go BEFORE the code in its input, so if anything gets cut it's the tail of
# the code, never the LLM's conclusions; each line is capped so a verbose
# answer can't crowd out the others.
EVIDENCE_LINE_CHARS = 240
SNIPPET_CHARS = 400

# The evidence Laya can ask the LLM for. Keys are the option ids Laya chooses
# between; each value is (what Laya sees as the option, what the LLM is asked).
INVESTIGATION_QUESTIONS = {
    "input_source": (
        "whether attacker-controlled input actually reaches the flagged code",
        "Trace the data flowing into the flagged line. Is any of it "
        "attacker-controlled (request parameters, headers, body, files, "
        "environment an attacker can influence)? Name the exact source.",
    ),
    "sanitization": (
        "whether the input is validated, escaped or parameterized before the sink",
        "Between the input source and the flagged line, is the data validated, "
        "escaped, parameterized, allow-listed or otherwise made safe? Quote the "
        "code that does it, or state plainly that nothing does.",
    ),
    "reachability": (
        "whether the flagged code is reachable by an attacker in practice",
        "Is the flagged code reachable by an attacker — e.g. exposed through a "
        "route or public entry point without authentication — or is it dead, "
        "test-only, or admin-only code?",
    ),
    "sink_safety": (
        "whether the sink is dangerous in this specific usage",
        "Is the sink on the flagged line actually dangerous as used here, or "
        "does the API/framework make this particular call safe?",
    ),
    "exploit": (
        "a concrete exploit payload and its impact",
        "Give a concrete example request or input that would exploit this, and "
        "what an attacker gains. If you cannot construct one, say so and why.",
    ),
}


def build_reasoning_prompt(finding: Finding, context: str = "") -> str:
    return (
        "You are a security engineer triaging a static analysis finding.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"Rule: {finding.rule_id}\n"
        f"CWE: {finding.cwe}\n"
        f"Semgrep message: {finding.message}\n\n"
        f"Code context:\n{context or finding.snippet}\n\n"
        "In plain text, reason about whether this is a real, exploitable "
        "vulnerability or a false positive. Note anything Semgrep's static "
        "view might miss, such as input being sanitized earlier in the call "
        "chain, the route being unreachable, or the sink being safe in this "
        "context."
        + VERDICT_INSTRUCTION
    )


def build_followup_prompt(
    finding: Finding, context: str, evidence: list[tuple[str, str]], question: str
) -> str:
    transcript = "\n\n".join(f"Q: {q}\nA: {a}" for q, a in evidence)
    return (
        "You are a security engineer helping triage a static analysis finding.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"CWE: {finding.cwe}\n"
        f"Semgrep message: {finding.message}\n\n"
        f"Code context:\n{context or finding.snippet}\n\n"
        f"Evidence gathered so far:\n{transcript}\n\n"
        f"Answer this specific question concisely, citing line numbers:\n{question}"
        + VERDICT_INSTRUCTION
    )


def summarize_answer(answer: str, limit: int = EVIDENCE_LINE_CHARS) -> str:
    """The LLM's VERDICT line if it gave one, else the start of its answer."""
    verdicts = VERDICT_RE.findall(answer)
    text = verdicts[-1] if verdicts else answer
    text = " ".join(text.replace("*", "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def question_label(question: str) -> str:
    for key, (_, text) in INVESTIGATION_QUESTIONS.items():
        if text == question:
            return key
    return question


def build_laya_state(finding: Finding, evidence: list[tuple[str, str]]) -> str:
    lines = "\n".join(
        f"- {question_label(q)}: {summarize_answer(a)}" for q, a in evidence
    )
    return (
        f"Static analysis finding: {finding.message} (CWE {finding.cwe}) at "
        f"{finding.file}:{finding.line}.\n"
        f"Security analyst conclusions:\n{lines}\n"
        f"Flagged code:\n{finding.snippet[:SNIPPET_CHARS]}"
    )


def format_evidence(evidence: list[tuple[str, str]]) -> str:
    return "\n\n".join(f"**{q}**\n{a}" for q, a in evidence)


def route(score: float, threshold_fix: float, threshold_review: float) -> str:
    if score > threshold_fix:
        return "fix"
    if score >= threshold_review:
        return "review"
    return "reject"


def triage_finding(
    finding: Finding,
    ollama,
    laya,
    threshold_fix: float,
    threshold_review: float,
    max_rounds: int = 3,
    context: str = "",
) -> TriageResult:
    """Laya-driven triage: Laya decides, the LLM investigates.

    The LLM writes an initial analysis. Then, each round, Laya scores the
    evidence so far and picks which open question it wants answered next;
    the LLM answers it and the answer joins the evidence. This stops as soon
    as Laya's score leaves the uncertain review band, when Laya has nothing
    left to ask, or after `max_rounds` follow-up questions. Laya's last score
    is the verdict.
    """
    try:
        initial = ollama.generate(build_reasoning_prompt(finding, context))
    except Exception as exc:
        print(
            f"[triage error: ollama call failed for {finding.file}:{finding.line}: {exc}]",
            file=sys.stderr,
        )
        return TriageResult(
            finding=finding,
            llm_reasoning=f"[triage error: ollama call failed: {exc}]",
            laya_score=0.0,
            route="review",
        )

    evidence = [("Initial analysis", initial)]
    remaining = dict(INVESTIGATION_QUESTIONS)
    rounds = 0

    while True:
        options = (
            {key: desc for key, (desc, _) in remaining.items()}
            if rounds < max_rounds else {}
        )
        try:
            score, choice = laya.assess(
                build_laya_state(finding, evidence), TRIAGE_QUESTION, options
            )
        except Exception as exc:
            # Annotate rather than silently returning 0.0: a reader (and the
            # PR body) must be able to tell a Laya failure apart from a
            # genuine calibrated score of 0.0.
            print(
                f"[triage error: laya call failed for {finding.file}:{finding.line}: {exc}]",
                file=sys.stderr,
            )
            return TriageResult(
                finding=finding,
                llm_reasoning=(
                    f"{format_evidence(evidence)}\n\n[triage error: laya call "
                    f"failed: {exc} — laya_score=0.0 is a placeholder, not a "
                    "calibrated score; routed to review]"
                ),
                laya_score=0.0,
                route="review",
                evidence=evidence,
            )

        confident = score > threshold_fix or score < threshold_review
        if confident or not options or choice not in options:
            break

        _, question = remaining.pop(choice)
        rounds += 1
        try:
            answer = ollama.generate(
                build_followup_prompt(finding, context, evidence, question)
            )
        except Exception as exc:
            print(
                f"[triage warning: follow-up '{choice}' failed for "
                f"{finding.file}:{finding.line}: {exc}]",
                file=sys.stderr,
            )
            # No new evidence, so another Laya pass would return the same
            # score — the last one stands.
            break
        evidence.append((question, answer))

    return TriageResult(
        finding=finding,
        llm_reasoning=format_evidence(evidence),
        laya_score=score,
        route=route(score, threshold_fix, threshold_review),
        evidence=evidence,
    )
