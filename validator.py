import os
import subprocess
import sys

import pyflakes.api
import pyflakes.messages

from fixer import fix_finding, restore_file
from models import Finding, FixResult, ValidationResult
from scanner import scan


def count_same_rule_and_file(finding: Finding, findings: list[Finding]) -> int:
    return sum(
        1 for f in findings
        if f.rule_id == finding.rule_id and f.file == finding.file
    )


def finding_still_present(
    original: Finding,
    rescanned: list[Finding],
    baseline_count: int | None = None,
) -> bool:
    """Has the fix made no progress on `original`?

    Exact-line matching is unusable here — a patch shifts the line numbers of
    everything after it — so matching is on (rule_id, file). But a file can
    legitimately hold several instances of the same rule (sample_vuln_app has
    SQLi on two adjacent lines); matching on mere presence would then report
    "still present" forever after a correct fix of one instance, burning every
    retry and reverting good work.

    So when the pre-fix `baseline_count` of (rule_id, file) matches is known,
    compare counts: any decrease is progress. Without a baseline (callers that
    only care about presence), fall back to the simple presence check.
    """
    current = count_same_rule_and_file(original, rescanned)
    if baseline_count is None:
        return current > 0
    return current >= baseline_count


def _pytest_for(target_repo: str) -> str:
    """The target's own pytest when it has a .venv (where its dependencies
    live), else whatever pytest is on PATH."""
    own = os.path.join(os.path.abspath(target_repo), ".venv", "bin", "pytest")
    return own if os.path.exists(own) else "pytest"


def new_code_errors(file: str, before: str | None, after: str | None) -> list[str]:
    """Undefined names and syntax errors the fix INTRODUCED in a Python file.

    A security rescan can't tell a fix from a broken file: deleting the
    vulnerable function "fixes" the finding. This catches the commonest
    breakage — removing a line other code depends on — with no tests needed.
    Problems already present before the fix are not held against it.
    """
    if not file.endswith(".py") or before is None or after is None:
        return []

    def problems(source: str) -> list[str]:
        found = []

        class Collect:
            def unexpectedError(self, filename, msg):
                found.append(f"error: {msg}")

            def syntaxError(self, filename, msg, lineno, offset, text):
                found.append(f"syntax error: {msg}")

            def flake(self, message):
                if isinstance(message, (pyflakes.messages.UndefinedName,
                                        pyflakes.messages.UndefinedLocal)):
                    found.append(message.message % message.message_args)

        pyflakes.api.check(source, file, Collect())
        return found

    old = problems(before)
    return [p for p in problems(after) if p not in old]


def run_test_suite(target_repo: str) -> tuple[bool, str]:
    if not os.path.isdir(os.path.join(target_repo, "tests")):
        return True, "no tests found"

    result = subprocess.run(
        # "tests", not os.path.join(target_repo, "tests") — cwd is already
        # target_repo, so a prefixed path would resolve to
        # target_repo/target_repo/tests.
        [_pytest_for(target_repo), "tests", "-v"],
        capture_output=True,
        text=True,
        cwd=target_repo,
    )
    return result.returncode == 0, result.stdout + result.stderr


def _read(target_repo: str, file: str) -> str | None:
    try:
        with open(os.path.join(target_repo, file)) as f:
            return f.read()
    except OSError:
        return None


def _check(
    target_repo: str,
    semgrep_rulesets: list[str],
    finding: Finding,
    baseline_count: int | None = None,
    baseline_content: str | None = None,
):
    rescanned = scan(target_repo, semgrep_rulesets)
    still_present = finding_still_present(finding, rescanned, baseline_count)
    tests_passed, test_output = run_test_suite(target_repo)
    broken = new_code_errors(
        finding.file, baseline_content, _read(target_repo, finding.file)
    )
    if broken:
        tests_passed = False
        test_output = (
            f"The fix broke {finding.file}: " + "; ".join(broken) + "\n" + test_output
        )
    remaining_lines = sorted(
        f.line for f in rescanned
        if f.rule_id == finding.rule_id and f.file == finding.file
    )
    return still_present, tests_passed, test_output, remaining_lines


def build_feedback(
    finding: Finding,
    still_present: bool,
    remaining_lines: list[int],
    tests_passed: bool,
    test_output: str,
) -> str:
    parts = []
    if still_present:
        where = ", ".join(f"line {n}" for n in remaining_lines) or "the same place"
        parts.append(
            f"The rescan still flags {finding.rule_id} in {finding.file} at "
            f"{where} — the vulnerability is not fixed."
        )
    else:
        parts.append("The rescan no longer flags the finding.")
    if not tests_passed:
        parts.append(f"But the change breaks the code:\n{test_output[:2000]}")
    return " ".join(parts)


def _progress(finding: Finding, attempt: int, still_present: bool, tests_passed: bool) -> None:
    rescan = "still flagged" if still_present else "clean"
    tests = "pass" if tests_passed else "FAIL"
    print(
        f"    [fix attempt {attempt}] {finding.file}:{finding.line} rescan {rescan}, tests {tests}",
        file=sys.stderr, flush=True,
    )


def validate_and_retry(
    fix_result: FixResult,
    ollama,
    repo,
    target_repo: str,
    semgrep_rulesets: list[str],
    max_retries: int,
    baseline_count: int | None = None,
) -> ValidationResult:
    """Rescan + test an already-applied fix; on failure, feed the result back
    to the LLM for a new fix and rescan again, up to `max_retries` times.

    `baseline_count` is how many (rule_id, file) matches the target repo was
    expected to hold immediately BEFORE this fix was applied — see
    `finding_still_present`. Callers that know it (cli.run_pipeline tracks
    it) should pass it, so that fixing one of several same-rule instances in
    one file counts as progress instead of burning every retry.
    """
    finding = fix_result.finding
    baseline = fix_result.baseline

    # Validate the fix that was already applied before this call, before
    # spending any retries on it.
    still_present, tests_passed, test_output, remaining_lines = _check(
        target_repo, semgrep_rulesets, finding, baseline_count, baseline
    )
    attempts = 1
    _progress(finding, attempts, still_present, tests_passed)
    if not still_present and tests_passed:
        return ValidationResult(
            finding=finding, clean=True, test_output=test_output,
            validated=True, attempts=attempts,
        )

    applied_note = ""
    for _ in range(max_retries):
        feedback = build_feedback(
            finding, still_present, remaining_lines, tests_passed, test_output
        ) + applied_note
        current_fix = fix_finding(
            finding, ollama, repo, retry_feedback=feedback, baseline=baseline
        )
        attempts += 1

        if not current_fix.applied:
            applied_note = (
                " NOTE: the previous retry's diff failed to apply to the "
                "repo at all — produce a diff that applies cleanly against "
                "the numbered file contents shown above."
            )
        else:
            applied_note = ""

        # Every retry attempt gets validated, including the last one — a
        # fix that lands on the final retry must not be reverted just
        # because retries ran out before it could be checked.
        still_present, tests_passed, test_output, remaining_lines = _check(
            target_repo, semgrep_rulesets, finding, baseline_count, baseline
        )
        if current_fix.applied:
            _progress(finding, attempts, still_present, tests_passed)
        else:
            print(f"    [fix attempt {attempts}] diff did not apply", file=sys.stderr, flush=True)

        if not still_present and tests_passed:
            return ValidationResult(
                finding=finding, clean=True, test_output=test_output,
                validated=True, attempts=attempts,
            )

    # The rejected fix's edits are still sitting uncommitted in the working
    # tree (fix branches never commit — see fixer.fix_finding). Undo just
    # this finding's edits before leaving the branch, so
    # pr.commit_validated_findings' `git add <file>` can never pick them up.
    # restore_file rewinds to the pre-fix snapshot rather than HEAD, so any
    # earlier validated-but-uncommitted fix in the SAME file survives.
    restore_file(repo, finding.file, baseline)
    repo.git.checkout("main")
    return ValidationResult(
        finding=finding, clean=False, test_output=test_output,
        validated=False, attempts=attempts,
    )
