from unittest.mock import MagicMock, patch

from models import Finding, FixResult
from validator import (
    count_same_rule_and_file,
    finding_still_present,
    run_test_suite,
    validate_and_retry,
)


def make_finding(line=41):
    return Finding(
        file="app.py",
        line=line,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"...\"",
    )


def test_finding_still_present_true_when_same_rule_and_file_reappears():
    original = make_finding()
    rescanned = [make_finding()]
    assert finding_still_present(original, rescanned) is True


def test_finding_still_present_false_when_gone():
    original = make_finding()
    assert finding_still_present(original, []) is False


def test_count_same_rule_and_file_ignores_line_numbers():
    original = make_finding(line=41)
    rescanned = [make_finding(line=42), make_finding(line=44)]
    assert count_same_rule_and_file(original, rescanned) == 2


def test_finding_still_present_counts_a_decrease_as_progress():
    # sample_vuln_app has the same SQLi rule firing on two adjacent lines.
    # Fixing one of them leaves the other behind; a presence-only check would
    # call that "still failing" forever, burn every retry, and revert a
    # genuinely correct fix. A drop in the count is progress.
    original = make_finding(line=42)
    rescanned = [make_finding(line=44)]

    assert finding_still_present(original, rescanned, baseline_count=2) is False


def test_finding_still_present_true_when_count_did_not_drop():
    original = make_finding(line=42)
    rescanned = [make_finding(line=42), make_finding(line=44)]

    assert finding_still_present(original, rescanned, baseline_count=2) is True


def test_finding_still_present_without_baseline_uses_presence():
    original = make_finding()
    assert finding_still_present(original, [make_finding()]) is True


def test_run_test_suite_no_tests_dir(tmp_path):
    passed, output = run_test_suite(str(tmp_path))
    assert passed is True
    assert "no tests found" in output.lower()


def test_run_test_suite_runs_pytest_when_tests_dir_exists(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_dummy.py").write_text("def test_ok():\n    assert True\n")

    passed, output = run_test_suite(str(tmp_path))
    assert passed is True


def test_run_test_suite_does_not_double_prefix_a_relative_target_repo(tmp_path, monkeypatch):
    # cwd is already target_repo, so the pytest argument must be relative.
    # With a RELATIVE target_repo, a target_repo-prefixed argument resolves
    # to target_repo/target_repo/tests and pytest exits non-zero — which the
    # pipeline would read as "the target repo's tests failed".
    target = tmp_path / "target"
    tests_dir = target / "tests"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_dummy.py").write_text("def test_ok():\n    assert True\n")
    monkeypatch.chdir(tmp_path)

    passed, output = run_test_suite("target")

    assert passed is True, output


def test_validate_and_retry_marks_validated_when_rescan_clean():
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    repo = MagicMock()

    with patch("validator.scan", return_value=[]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")):
        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is True
    assert result.clean is True
    repo.git.checkout.assert_not_called()  # no revert needed


def test_validate_and_retry_validates_when_a_repeated_rule_count_drops():
    # Regression test for repeated same-rule findings in one file. The rescan
    # still reports the rule for this file (the OTHER instance), but one
    # fewer than before the fix — that is a successful fix, not a failure.
    finding = make_finding(line=42)
    other_instance = make_finding(line=44)
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    repo = MagicMock()

    with patch("validator.scan", return_value=[other_instance]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding") as mock_fix_finding:
        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
            baseline_count=2,
        )

    assert result.validated is True
    assert result.clean is True
    mock_fix_finding.assert_not_called()  # no retries burned
    repo.git.checkout.assert_not_called()  # nothing reverted


def test_validate_and_retry_retries_then_reverts_when_still_failing():
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    ollama.generate.return_value = "```diff\nstill broken\n```"
    repo = MagicMock()

    with patch("validator.scan", return_value=[finding]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding") as mock_fix_finding:
        mock_fix_finding.return_value = fix_result

        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is False
    assert mock_fix_finding.call_count == 2  # max_retries
    repo.git.checkout.assert_called_with("main")  # reverted off the branch


def test_validate_and_retry_succeeds_on_last_retry_without_reverting():
    # Regression test: the fix that lands on the final allowed retry must
    # still be rescanned/tested before deciding to revert. scan() is called
    # once before the loop (validating the already-applied fix_result) and
    # once after each retry; here only the very last call comes back clean.
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    repo = MagicMock()

    with patch("validator.scan", side_effect=[[finding], [finding], []]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding") as mock_fix_finding:
        mock_fix_finding.return_value = fix_result

        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is True
    assert result.clean is True
    assert mock_fix_finding.call_count == 2  # both retries attempted
    repo.git.checkout.assert_not_called()  # last retry succeeded, no revert


def test_validate_and_retry_restores_dirty_file_before_reverting():
    # A rejected fix attempt leaves its edits sitting uncommitted in the
    # working tree (fix branches never commit). On final failure, those
    # edits must be discarded for this finding's file specifically — not
    # just left dirty — so a later validated finding in the same file can
    # never pick them up via `git add <file>` in pr.commit_validated_findings.
    finding = make_finding()
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    ollama = MagicMock()
    ollama.generate.return_value = "```diff\nstill broken\n```"
    repo = MagicMock()

    with patch("validator.scan", return_value=[finding]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding") as mock_fix_finding:
        mock_fix_finding.return_value = fix_result

        result = validate_and_retry(
            fix_result, ollama, repo, target_repo=".",
            semgrep_rulesets=["p/security-audit"], max_retries=2,
        )

    assert result.validated is False
    # The dirty file is restored to HEAD's version before leaving the branch...
    repo.git.checkout.assert_any_call("--", finding.file)
    # ...and that restore happens strictly before switching back to main, so
    # the file is already clean by the time HEAD moves.
    checkout_calls = [c.args for c in repo.git.checkout.call_args_list]
    assert checkout_calls.index(("--", finding.file)) < checkout_calls.index(("main",))


def test_new_code_errors_flags_a_deleted_dependency_line():
    from validator import new_code_errors

    before = "def f(db):\n    conn = db()\n    return conn.execute('q')\n"
    after = "def f(db):\n    return conn.execute('q')\n"

    assert new_code_errors("app.py", before, after) == ["undefined name 'conn'"]


def test_new_code_errors_ignores_preexisting_problems_and_non_python():
    from validator import new_code_errors

    before = "x = undefined_thing\n"
    assert new_code_errors("app.py", before, before + "y = 1\n") == []
    assert new_code_errors("app.js", "a", "b(") == []
    assert new_code_errors("app.py", "x = 1\n", "x = (\n")[0].startswith("syntax error")


def test_validate_rejects_a_fix_that_clears_the_scan_but_breaks_the_code(tmp_path):
    (tmp_path / "app.py").write_text("def f(db):\n    return conn.execute('q')\n")
    finding = make_finding()
    fix_result = FixResult(
        finding=finding, diff="d", applied=True, branch="autofix/x",
        baseline="def f(db):\n    conn = db()\n    return conn.execute('q')\n",
    )
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)

    with patch("validator.scan", return_value=[]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")):
        result = validate_and_retry(
            fix_result, MagicMock(), repo, target_repo=str(tmp_path),
            semgrep_rulesets=[], max_retries=0,
        )

    assert result.validated is False
    assert "undefined name 'conn'" in result.test_output


def test_unusable_first_reply_is_retried_with_the_reason():
    finding = make_finding()
    unusable = FixResult(
        finding=finding, diff="", applied=False, branch="autofix/x",
        error="Your reply contained no edit blocks.",
    )
    good = FixResult(finding=finding, diff="d", applied=True, branch="autofix/x")
    repo = MagicMock()

    with patch("validator.scan", return_value=[]), \
         patch("validator.run_test_suite", return_value=(True, "no tests found")), \
         patch("validator.fix_finding", return_value=good) as mock_fix:
        result = validate_and_retry(
            unusable, MagicMock(), repo, target_repo=".",
            semgrep_rulesets=[], max_retries=2,
        )

    assert result.validated is True
    assert result.attempts == 2
    assert mock_fix.call_args.kwargs["retry_feedback"] == "Your reply contained no edit blocks."


def test_never_usable_reply_reports_no_usable_fix():
    finding = make_finding()
    unusable = FixResult(finding=finding, diff="", applied=False, branch="b", error="no blocks")

    with patch("validator.scan") as mock_scan, \
         patch("validator.fix_finding", return_value=unusable):
        result = validate_and_retry(
            unusable, MagicMock(), MagicMock(), target_repo=".",
            semgrep_rulesets=[], max_retries=2,
        )

    assert result.validated is False
    assert result.failure == "no usable fix"
    assert result.attempts == 3
    mock_scan.assert_not_called()  # nothing applied, nothing to rescan


def test_an_undefined_name_failure_tells_the_model_how_to_repair_it(tmp_path):
    from unittest.mock import patch

    import validator
    from models import Finding

    repo = tmp_path
    (repo / "tests").mkdir()
    (repo / "orders.py").write_text("def export(name):\n    abort(400)\n")     # abort is used but never imported
    finding = Finding(file="orders.py", line=2, rule_id="r", cwe="CWE-78", message="m", snippet="x")
    with patch.object(validator, "scan", return_value=[]):
        _, tests_passed, output, _ = validator._check(
            str(repo), [], finding, baseline_content="def export(name):\n    pass\n", known_rules=None, created_files=[])
    assert tests_passed is False
    assert "undefined name 'abort'" in output and "Add the missing import" in output
