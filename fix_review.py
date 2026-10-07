"""Second opinion on a fix before it is accepted.

A clean rescan only proves the rule stopped matching, not that the weakness
is gone: MD5 -> unsalted SHA-256 clears the MD5 rule but is still unfit for
passwords. The reviewer prompt judges the actual diff against current best
practice. It is the same local model that wrote the fix, so it is a filter,
not a guarantee: every accepted fix still lands in a human-reviewed PR.
"""

import difflib
import re
import sys

from injection import FENCE_RULE, fence
from models import Finding

REVIEW_RE = re.compile(r"^[\s*_`#>-]*REVIEW[\s*_`]*:[\s*_`]*(APPROVE|REJECT)\b[\s*_`:—–-]*(.*)$",
                       re.IGNORECASE | re.MULTILINE)


def file_diff(file: str, before: str | None, after: str | None) -> str:
    if before is None or after is None:
        return ""
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{file}", tofile=f"b/{file}", n=3,
    ))


def build_review_prompt(finding: Finding, diff: str, dependencies: str = "") -> str:
    deps = (
        "\nThe project's declared dependencies (plus the Python standard "
        "library). When you REJECT, recommend a remedy available within "
        f"these — the fixer cannot add packages:\n{dependencies}\n"
        if dependencies else ""
    )
    return (
        "You are a senior application-security reviewer. A developer tool "
        "proposed this change to fix a static analysis finding.\n\n"
        f"File: {finding.file}\n"
        f"CWE: {finding.cwe}\n"
        f"Finding: {finding.message}\n\n"
        f"{FENCE_RULE}\n\n"
        f"Proposed change (a diff):\n{fence(diff)}\n"
        f"{deps}\n"
        "Judge ONE thing: after this change, is the weakness actually "
        "remediated, the way current best practice (e.g. the OWASP Cheat "
        "Sheets) would accept?\n"
        "REJECT only if: the vulnerability is still exploitable, the change "
        "only silences the scanner, or it swaps one weak primitive for another "
        "(for example a fast unsalted hash for passwords).\n"
        "Do NOT reject for style, minor behaviour differences, missing "
        "features or hardening that would be nice to have — the project's "
        "tests already cover behaviour, and a human reviews the PR. Mention "
        "such points in your reason but still APPROVE.\n\n"
        "End your answer with exactly one final line, either\n"
        "REVIEW: APPROVE — <one-sentence reason>\n"
        "or\n"
        "REVIEW: REJECT — <what must change>"
    )


def review_fix(ollama, finding: Finding, diff: str, dependencies: str = "") -> tuple[bool, str]:
    """(approved, reason). An unreachable or unparseable reviewer approves
    with a note: failing closed would burn every retry on a format slip, and
    the fix is still human-reviewed in the PR."""
    if not diff:
        return True, "no diff to review"
    try:
        answer = ollama.generate(build_review_prompt(finding, diff, dependencies))
    except Exception as exc:
        print(f"[fix review warning: reviewer call failed: {exc}]", file=sys.stderr)
        return True, "automated review unavailable"
    matches = REVIEW_RE.findall(answer)
    if not matches:
        return True, "automated review inconclusive"
    decision, reason = matches[-1]
    reason = " ".join(reason.replace("*", "").split()) or decision.lower()
    return decision.upper() == "APPROVE", reason
