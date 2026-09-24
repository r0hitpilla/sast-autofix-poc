import os
import subprocess

from fixer import fix_finding
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


def run_test_suite(target_repo: str) -> tuple[bool, str]:
    if not os.path.isdir(os.path.join(target_repo, "tests")):
        return True, "no tests found"

    result = subprocess.run(
        # "tests", not os.path.join(target_repo, "tests") — cwd is already
        # target_repo, so a prefixed path would resolve to
        # target_repo/target_repo/tests.
        ["pytest", "tests", "-v"],
        capture_output=True,
        text=True,
        cwd=target_repo,
    )
    return result.returncode == 0, result.stdout + result.stderr


def _check(
    target_repo: str,
    semgrep_rulesets: list[str],
    finding: Finding,
    baseline_count: int | None = None,
):
    rescanned = scan(target_repo, semgrep_rulesets)
    still_present = finding_still_present(finding, rescanned, baseline_count)
    tests_passed, test_output = run_test_suite(target_repo)
    return still_present, tests_passed, test_output


def validate_and_retry(
    fix_result: FixResult,
    ollama,
    repo,
    target_repo: str,
    semgrep_rulesets: list[str],
    max_retries: int,
    baseline_count: int | None = None,
) -> ValidationResult:
    """Validate an already-applied fix, retrying up to `max_retries` times.

    `baseline_count` is how many (rule_id, file) matches the target repo was
    expected to hold immediately BEFORE this fix was applied — see
    `finding_still_present`. Callers that know it (cli.run_pipeline tracks
    it) should pass it, so that fixing one of several same-rule instances in
    one file counts as progress instead of burning every retry.
    """
    finding = fix_result.finding
    current_fix = fix_result

    # Validate the fix that was already applied before this call, before
    # spending any retries on it.
    still_present, tests_passed, test_output = _check(
        target_repo, semgrep_rulesets, finding, baseline_count
    )
    last_output = test_output
    if not still_present and tests_passed:
        return ValidationResult(
            finding=finding,
            clean=True,
            test_output=test_output,
            validated=True,
        )

    applied_note = ""
    for attempt in range(max_retries):
        feedback = (
            f"Rescan still found the issue: {still_present}. "
            f"Tests passed: {tests_passed}. Output: {test_output[:2000]}"
            f"{applied_note}"
        )
        current_fix = fix_finding(finding, ollama, repo, retry_feedback=feedback)

        if not current_fix.applied:
            applied_note = (
                " NOTE: the previous retry's diff failed to apply to the "
                "repo at all — produce a diff that applies cleanly."
            )
        else:
            applied_note = ""

        # Every retry attempt gets validated, including the last one — a
        # fix that lands on the final retry must not be reverted just
        # because retries ran out before it could be checked.
        still_present, tests_passed, test_output = _check(
            target_repo, semgrep_rulesets, finding, baseline_count
        )
        last_output = test_output

        if not still_present and tests_passed:
            return ValidationResult(
                finding=finding,
                clean=True,
                test_output=test_output,
                validated=True,
            )

    # The rejected fix's edits are still sitting uncommitted in the working
    # tree (fix branches never commit — see fixer.fix_finding). Discard just
    # this finding's file before leaving the branch, so a later validated
    # finding in the SAME file can never pick up these unvalidated edits
    # when pr.commit_validated_findings does `git add <file>`. Scoped to
    # this one file (not `reset --hard`) so any other finding's already-
    # validated-but-not-yet-committed edits elsewhere in the tree survive.
    repo.git.checkout("--", finding.file)
    repo.git.checkout("main")
    return ValidationResult(
        finding=finding,
        clean=False,
        test_output=last_output,
        validated=False,
    )
