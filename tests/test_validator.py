from unittest.mock import MagicMock, patch

from models import Finding, FixResult
from validator import finding_still_present, run_test_suite, validate_and_retry


def make_finding():
    return Finding(
        file="sample_vuln_app/app.py",
        line=41,
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
