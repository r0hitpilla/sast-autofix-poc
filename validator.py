import os
import subprocess
import sys

import pyflakes.api
import pyflakes.messages

from code_context import dependency_summary
from fix_review import file_diff, review_fix
from hallucination import check_references
from fixer import fix_finding, remove_created, restore_file
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


def tail(text: str, limit: int) -> str:
    """The last `limit` chars: test failures are reported at the end of the
    output, so a head-truncation shows only the session header."""
    return text if len(text) <= limit else "…" + text[-limit:]


def run_test_suite(target_repo: str) -> tuple[bool, str]:
    if not os.path.isdir(os.path.join(target_repo, "tests")):
        return True, "no tests found"

    result = subprocess.run(
        # "tests", not os.path.join(target_repo, "tests") — cwd is already
        # target_repo, so a prefixed path would resolve to
        # target_repo/target_repo/tests.
        # -q --tb=short -rf: the failure summary is short and sits at the
        # end, which is the part callers keep (see tail()).
        [_pytest_for(target_repo), "tests", "-q", "--tb=short", "-rf"],
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
    known_rules: set | None = None,
    created_files: list[str] | None = None,
    engines=("semgrep",),
):
    rescanned = scan(target_repo, semgrep_rulesets, engines)
    still_present = finding_still_present(finding, rescanned, baseline_count)
    tests_passed, test_output = run_test_suite(target_repo)
    if known_rules is not None:
        # A fix that trades one finding for another (escaping XSS via
        # render_template_string -> template injection) is not a fix.
        created = set(created_files or [])
        introduced = [
            f for f in rescanned
            if (f.file == finding.file and f.rule_id not in known_rules)
            or f.file in created  # anything flagged in a file the fix created is new
        ]
        if introduced:
            tests_passed = False
            test_output = (
                "The fix introduced new security findings: "
                + "; ".join(f"line {f.line} {f.cwe} ({f.rule_id}): {f.message}" for f in introduced)
                + "\n" + test_output
            )
    broken = new_code_errors(
        finding.file, baseline_content, _read(target_repo, finding.file)
    )
    # Invented imports and unpublished versions: code that compiles can still
    # depend on something that does not exist.
    requirements = _read(target_repo, "requirements.txt") or ""
    invented = check_references(
        finding.file, baseline_content, _read(target_repo, finding.file),
        target_repo, requirements,
    )
    for path in created_files or []:
        invented += check_references(path, None, _read(target_repo, path), target_repo, requirements)
    if invented:
        broken = broken + invented
    if broken:
        tests_passed = False
        test_output = (
            f"The fix broke {finding.file}: " + "; ".join(broken) + "\n" + test_output
        )
    remaining = sorted(
        (f for f in rescanned if f.rule_id == finding.rule_id and f.file == finding.file),
        key=lambda f: f.line,
    )
    return still_present, tests_passed, test_output, remaining


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
        parts.append(f"But the change breaks the code:\n{tail(test_output, 2000)}")
    return " ".join(parts)


def _progress(finding: Finding, attempt: int, still_present: bool, tests_passed: bool) -> None:
    rescan = "still flagged" if still_present else "clean"
    tests = "pass" if tests_passed else "FAIL"
    print(
        f"    [fix attempt {attempt}] {finding.file}:{finding.line} rescan {rescan}, tests {tests}",
        file=sys.stderr, flush=True,
    )


SCANNER_STILL_FLAGS_NOTE = (
    "scanner still flags this pattern, but re-triage of the fixed code (Laya and "
    "the LLM agreeing) judged it safe — reviewer, please confirm"
)


def _assess(
    finding: Finding,
    target_repo: str,
    baseline: str | None,
    still_present: bool,
    tests_passed: bool,
    test_output: str,
    remaining: list[Finding],
    attempts: int,
    ollama,
    review: bool,
    retriage,
    created_files: list[str] = (),
) -> ValidationResult | str:
    """Accept the applied fix (-> ValidationResult) or say why not (-> feedback).

    - rescan clean + tests pass -> accept, after the fix-quality review
    - rescan still flags + tests pass -> accept only if re-triaging the FIXED
      code makes Laya and the LLM both call it a false positive: some rules
      (e.g. Flask open-redirect) flag every validation-based fix, so a
      correct fix could otherwise never pass
    - anything else -> feedback for the next attempt
    """
    diff = file_diff(finding.file, baseline, _read(target_repo, finding.file))
    for path in created_files:
        diff += file_diff(path, "", _read(target_repo, path))
    if tests_passed and not still_present:
        if review:
            approved, reason = review_fix(
                ollama, finding, diff, dependency_summary(target_repo)
            )
            print(f"    [fix review] {'APPROVE' if approved else 'REJECT'}: {reason[:150]}",
                  file=sys.stderr, flush=True)
            if not approved:
                return (
                    "The rescan is clean, but a security review rejected the fix: "
                    f"{reason}. Produce a fix that follows current best practice."
                )
        return ValidationResult(
            finding=finding, clean=True, test_output=test_output,
            validated=True, attempts=attempts, fix_diff=diff,
            created_files=list(created_files),
        )

    if tests_passed and still_present and retriage is not None and remaining:
        nearest = min(remaining, key=lambda f: abs(f.line - finding.line))
        verdict = retriage(nearest)
        print(f"    [re-triage of fixed code] Laya {verdict.laya_score:.2f} -> {verdict.route}",
              file=sys.stderr, flush=True)
        if verdict.route == "reject":
            return ValidationResult(
                finding=finding, clean=False, test_output=test_output,
                validated=True, attempts=attempts, note=SCANNER_STILL_FLAGS_NOTE,
                fix_diff=diff, created_files=list(created_files),
            )

    return build_feedback(
        finding, still_present, [f.line for f in remaining], tests_passed, test_output
    )


def validate_and_retry(
    fix_result: FixResult,
    ollama,
    repo,
    target_repo: str,
    semgrep_rulesets: list[str],
    max_retries: int,
    baseline_count: int | None = None,
    base_branch: str = "main",
    review: bool = False,
    retriage=None,
    known_rules: set | None = None,
    fix_models: list[str] | None = None,
    engines=("semgrep",),
) -> ValidationResult:
    """Validate an already-applied fix; on failure feed the reason back to the
    LLM for a new fix, up to `max_retries` more attempts.

    `baseline_count` is how many (rule_id, file) matches the target repo was
    expected to hold immediately BEFORE this fix was applied — see
    `finding_still_present`. `review` turns on the fix-quality review;
    `retriage(finding) -> TriageResult` enables accepting a fix the scanner
    still flags (see `_assess`).
    """
    finding = fix_result.finding
    baseline = fix_result.baseline
    current_fix = fix_result
    attempts = 1
    last_proposal = fix_result.diff
    still_present = True

    while True:
        if not current_fix.applied:
            # An unusable reply (no edit blocks, or they didn't match the
            # file) is a failed attempt like any other: retry with the reason.
            print(f"    [fix attempt {attempts}] {current_fix.error[:120]}", file=sys.stderr, flush=True)
            still_present, test_output = True, current_fix.error
            feedback = current_fix.error
        else:
            # Every attempt gets validated, including the last one.
            still_present, tests_passed, test_output, remaining = _check(
                target_repo, semgrep_rulesets, finding, baseline_count, baseline,
                known_rules, current_fix.created_files, engines,
            )
            _progress(finding, attempts, still_present, tests_passed)
            outcome = _assess(
                finding, target_repo, baseline, still_present, tests_passed,
                test_output, remaining, attempts, ollama, review, retriage,
                current_fix.created_files,
            )
            if isinstance(outcome, ValidationResult):
                return outcome
            feedback = outcome
            if "security review rejected" in feedback:
                test_output = feedback

        if attempts > max_retries:
            break
        # Rotate models across retries: models fail differently, so a fix
        # one keeps getting wrong is often one another gets right.
        model = fix_models[attempts % len(fix_models)] if fix_models else None
        current_fix = fix_finding(
            finding, ollama, repo, retry_feedback=feedback, baseline=baseline,
            model=model, cleanup=current_fix.created_files,
        )
        attempts += 1
        last_proposal = current_fix.diff or last_proposal

    # The rejected fix's edits are still sitting uncommitted in the working
    # tree (fix branches never commit — see fixer.fix_finding). Undo just
    # this finding's edits before leaving the branch, so
    # pr.commit_validated_findings' `git add <file>` can never pick them up.
    # restore_file rewinds to the pre-fix snapshot rather than HEAD, so any
    # earlier validated-but-uncommitted fix in the SAME file survives.
    restore_file(repo, finding.file, baseline)
    remove_created(repo, current_fix.created_files)
    repo.git.checkout(base_branch)
    if not current_fix.applied:
        failure = "no usable fix"
    elif still_present:
        failure = "still flagged"
    else:
        failure = "breaks code or tests"
    return ValidationResult(
        finding=finding, clean=False, test_output=test_output,
        validated=False, attempts=attempts, failure=failure,
        last_proposal=last_proposal,
    )
