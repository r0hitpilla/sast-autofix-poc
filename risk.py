"""Order findings so the most dangerous are fixed first.

Severity alone ties too many findings together. Code that takes input from a
request or the environment is reachable by an attacker, so the same rule
matters more there. Secrets and known-vulnerable dependencies are fixed early
because they are the costliest to leave in place.
"""

import re

SEVERITY_WEIGHT = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0}

# Source of untrusted input: a request parameter, form field, header, or
# environment/command-line value.
UNTRUSTED_INPUT = re.compile(
    r"request\.|\bargs\.get\(|\bform\[|\bparams\b|\bheaders\b|\bcookies\b|"
    r"os\.environ|\bsys\.argv\b|\binput\(",
)


def risk_score(finding) -> float:
    score = SEVERITY_WEIGHT.get(finding.severity, 2.0)
    if UNTRUSTED_INPUT.search(finding.snippet or ""):
        score *= 1.5
    if finding.rule_id.startswith(("gitleaks.", "osv.")):
        score += 0.5
    return score


def by_risk(triage_results) -> list:
    """Triage results, highest risk first; ties keep the scanner's order."""
    return sorted(triage_results, key=lambda t: -risk_score(t.finding))
