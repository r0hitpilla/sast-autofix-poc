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
    last_output = ""

    for attempt in range(max_retries):
        rescanned = scan(target_repo, semgrep_rulesets)
        still_present = finding_still_present(finding, rescanned)
        tests_passed, test_output = run_test_suite(target_repo)
        last_output = test_output

        if not still_present and tests_passed:
            return ValidationResult(
                finding=finding,
                clean=True,
                test_output=test_output,
                validated=True,
            )

        feedback = (
            f"Rescan still found the issue: {still_present}. "
            f"Tests passed: {tests_passed}. Output: {test_output[:2000]}"
        )
        current_fix = fix_finding(finding, ollama, repo, retry_feedback=feedback)

    repo.git.checkout("main")
    return ValidationResult(
        finding=finding,
        clean=False,
        test_output=last_output,
        validated=False,
    )
