import sys

from models import Finding, TriageResult

TRIAGE_QUESTION = "is this a true positive security vulnerability"


def build_reasoning_prompt(finding: Finding) -> str:
    return (
        "You are a security engineer triaging a static analysis finding.\n\n"
        f"File: {finding.file}\n"
        f"Line: {finding.line}\n"
        f"Rule: {finding.rule_id}\n"
        f"CWE: {finding.cwe}\n"
        f"Semgrep message: {finding.message}\n\n"
        f"Code context:\n{finding.snippet}\n\n"
        "In plain text, reason about whether this is a real, exploitable "
        "vulnerability or a false positive. Note anything Semgrep's static "
        "view might miss, such as input being sanitized earlier in the call "
        "chain, the route being unreachable, or the sink being safe in this "
        "context."
    )


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
) -> TriageResult:
    try:
        reasoning = ollama.generate(build_reasoning_prompt(finding))
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

    state = (
        f"Finding: {finding.message} (CWE {finding.cwe}) at "
        f"{finding.file}:{finding.line}.\n"
        f"Code:\n{finding.snippet}\n\n"
        f"Analyst reasoning:\n{reasoning}"
    )

    try:
        score = laya.true_positive_score(state, TRIAGE_QUESTION)
    except Exception as exc:
        # Annotate rather than silently returning 0.0 with untouched
        # reasoning: a reader (and the PR body) must be able to tell a Laya
        # failure apart from a genuine calibrated score of 0.0.
        print(
            f"[triage error: laya call failed for {finding.file}:{finding.line}: {exc}]",
            file=sys.stderr,
        )
        return TriageResult(
            finding=finding,
            llm_reasoning=(
                f"{reasoning}\n\n[triage error: laya call failed: {exc} — "
                "laya_score=0.0 is a placeholder, not a calibrated score; "
                "routed to review]"
            ),
            laya_score=0.0,
            route="review",
        )

    return TriageResult(
        finding=finding,
        llm_reasoning=reasoning,
        laya_score=score,
        route=route(score, threshold_fix, threshold_review),
    )
