"""Laya's trust score for a fix: how complete and safe is this change?

Triage asks Laya "is this finding a real vulnerability?". This asks a second
question about the CHANGE: given the finding, what the fix does, and the facts
already verified about it (rescan, tests, AI review), does it fully and safely
remediate the problem without breaking the code?

Advisory only. The score is shown to the reviewer next to the fix; it never
accepts, rejects or gates anything, because Laya's checkpoint warns that its
outputs are uncalibrated. The verified checks decide; this helps a human
decide where to look first.

Laya reads about 512 tokens, so the facts go first and the change is
condensed to its removed and added lines.
"""

import sys

from injection import suspicious
from models import Finding, ValidationResult

FIX_QUESTION = (
    "does this change fully and safely remediate the vulnerability without "
    "breaking the code"
)
CHANGE_CHARS = 700
MESSAGE_CHARS = 200


def condensed_change(diff: str, limit: int = CHANGE_CHARS) -> str:
    """Just the removed and added lines of a unified diff, capped."""
    removed, added = [], []
    for line in (diff or "").splitlines():
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-") and line[1:].strip():
            removed.append(line[1:].strip())
        elif line.startswith("+") and line[1:].strip():
            added.append(line[1:].strip())
    text = ""
    if removed:
        text += "Removed: " + " | ".join(removed) + "\n"
    if added:
        text += "Added: " + " | ".join(added)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_fix_state(finding: Finding, validation: ValidationResult) -> str:
    if validation.note:
        rescan = "the scanner still matches the pattern; re-triage of the fixed code judged it safe"
    else:
        rescan = "clean"
    tests = ("no project tests exist" if validation.test_output.strip() == "no tests found"
             else "all passed")
    review = f"approved: {validation.review}" if validation.review else "not run"
    return (
        f"Proposed fix for a static analysis finding: {' '.join(finding.message.split())[:MESSAGE_CHARS]} "
        f"(CWE {finding.cwe}) in {finding.file}.\n"
        "Verified facts about the fix:\n"
        f"- re-scan of the changed code: {rescan}\n"
        f"- project tests: {tests}\n"
        f"- fix attempts needed: {validation.attempts}\n"
        f"- independent AI security review: {review}\n"
        f"The change:\n{condensed_change(validation.fix_diff)}"
    )


def fix_trust(laya, finding: Finding, validation: ValidationResult) -> float | None:
    """Laya's trust score in [0, 1] for an accepted fix, or None when it can't
    be given: never raises, because a scoring problem must not fail a run."""
    if not validation.validated or not validation.fix_diff:
        return None
    # Only the lines Laya is shown can steer its score. Unchanged context (a comment
    # next to the fix, say) never reaches it, so it must not block the score either.
    if suspicious(condensed_change(validation.fix_diff, limit=10 ** 9)):
        # The fix itself adds or removes text aimed at the AI: don't score it.
        return None
    try:
        score, _ = laya.assess(build_fix_state(finding, validation), FIX_QUESTION, {})
        return round(float(score), 3)
    except Exception as exc:
        print(f"[fix trust warning: laya call failed for {finding.file}:{finding.line}: {exc}]",
              file=sys.stderr)
        return None
