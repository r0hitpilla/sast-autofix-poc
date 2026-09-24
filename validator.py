import os
import subprocess

from fixer import fix_finding
from models import Finding, FixResult, ValidationResult
from scanner import scan


def finding_still_present(original: Finding, rescanned: list[Finding]) -> bool:
    return any(
        f.rule_id == original.rule_id and f.file == original.file
        for f in rescanned
    )


def run_test_suite(target_repo: str) -> tuple[bool, str]:
    tests_dir = os.path.join(target_repo, "tests")
    if not os.path.isdir(tests_dir):
        return True, "no tests found"

    result = subprocess.run(
        ["pytest", tests_dir, "-v"],
        capture_output=True,
        text=True,
        cwd=target_repo,
    )
    return result.returncode == 0, result.stdout + result.stderr


def _check(target_repo: str, semgrep_rulesets: list[str], finding: Finding):
    rescanned = scan(target_repo, semgrep_rulesets)
    still_present = finding_still_present(finding, rescanned)
    tests_passed, test_output = run_test_suite(target_repo)
    return still_present, tests_passed, test_output


def validate_and_retry(
    fix_result: FixResult,
    ollama,
    repo,
    target_repo: str,
    semgrep_rulesets: list[str],
    max_retries: int,
) -> ValidationResult:
    finding = fix_result.finding
    current_fix = fix_result

    # Validate the fix that was already applied before this call, before
    # spending any retries on it.
    still_present, tests_passed, test_output = _check(target_repo, semgrep_rulesets, finding)
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
        still_present, tests_passed, test_output = _check(target_repo, semgrep_rulesets, finding)
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
