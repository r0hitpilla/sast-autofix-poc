"""Behaviours added after the SV2 run: imports in the fix prompt, test-output
tails, fix review, accepting fixes the scanner can't recognise, and one
triage/fix per code location."""
from unittest.mock import MagicMock, patch

from code_context import numbered_header
from fix_review import file_diff, review_fix
from fixer import build_fix_prompt
from models import Finding, FixResult, TriageResult
from validator import tail, validate_and_retry


def make_finding(line=98, rule="r.md5", cwe="CWE-327"):
    return Finding(file="app.py", line=line, rule_id=rule, cwe=cwe,
                   message="m", snippet="return hashlib.md5(p).hexdigest()")


def test_numbered_header_shows_the_real_import_block(tmp_path):
    (tmp_path / "app.py").write_text(
        "import hashlib\nimport os\n\nfrom flask import Flask, request, send_file, abort, redirect\n"
        "\napp = Flask(__name__)\n"
    )
    header = numbered_header(str(tmp_path), "app.py")
    assert header.splitlines()[-1] == "4 | from flask import Flask, request, send_file, abort, redirect"
    assert "app = Flask" not in header


def test_fix_prompt_includes_the_import_block():
    prompt = build_fix_prompt(make_finding(), header="1 | import hashlib")
    assert "existing imports" in prompt and "1 | import hashlib" in prompt


def test_tail_keeps_the_end_where_failures_are():
    out = "=== test session starts ===\n" + "x" * 5000 + "\nFAILED tests/test_app.py::test_login - assert 302 == 401"
    assert tail(out, 200).endswith("assert 302 == 401")
    assert "session starts" not in tail(out, 200)


def test_review_rejects_weak_fix_and_parses_reason():
    ollama = MagicMock()
    ollama.generate.return_value = "Analysis...\nREVIEW: REJECT — use a salted slow hash such as werkzeug generate_password_hash"
    approved, reason = review_fix(ollama, make_finding(), "-md5\n+sha256")
    assert approved is False
    assert "generate_password_hash" in reason


def test_review_without_a_verdict_line_approves_with_a_note():
    ollama = MagicMock()
    ollama.generate.return_value = "looks fine"
    assert review_fix(ollama, make_finding(), "diff") == (True, "automated review inconclusive")


def test_file_diff_is_a_unified_diff():
    d = file_diff("app.py", "a\nb\n", "a\nc\n")
    assert "--- a/app.py" in d and "-b" in d and "+c" in d


def _repo(tmp_path, content):
    (tmp_path / "app.py").write_text(content)
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)
    return repo


def test_review_rejection_feeds_back_and_retries(tmp_path):
    finding = make_finding()
    repo = _repo(tmp_path, "h = 2\n")
    fix = FixResult(finding=finding, diff="d", applied=True, branch="b", baseline="h = 1\n")
    ollama = MagicMock()
    ollama.generate.side_effect = [
        "REVIEW: REJECT — unsalted fast hash",          # review of attempt 1
        "REVIEW: APPROVE — salted PBKDF2 via werkzeug",  # review of attempt 2
    ]

    with patch("validator.scan", return_value=[]), \
         patch("validator.run_test_suite", return_value=(True, "9 passed")), \
         patch("validator.fix_finding", return_value=fix) as mock_fix:
        result = validate_and_retry(fix, ollama, repo, str(tmp_path), [], max_retries=2, review=True)

    assert result.validated is True and result.attempts == 2
    assert "unsalted fast hash" in mock_fix.call_args.kwargs["retry_feedback"]


def test_fix_scanner_still_flags_is_accepted_when_retriage_agrees_it_is_safe(tmp_path):
    finding = make_finding(line=117, rule="r.redirect", cwe="CWE-601")
    repo = _repo(tmp_path, "s = 2\n")
    fix = FixResult(finding=finding, diff="d", applied=True, branch="b", baseline="s = 1\n")
    still = make_finding(line=119, rule="r.redirect", cwe="CWE-601")
    retriage = MagicMock(return_value=TriageResult(still, "safe now", 0.1, "reject"))

    with patch("validator.scan", return_value=[still]), \
         patch("validator.run_test_suite", return_value=(True, "9 passed")), \
         patch("validator.fix_finding") as mock_fix:
        result = validate_and_retry(fix, MagicMock(), repo, str(tmp_path), [],
                                    max_retries=2, baseline_count=1, retriage=retriage)

    assert result.validated is True and result.clean is False
    assert "scanner still flags" in result.note
    retriage.assert_called_once_with(still)
    mock_fix.assert_not_called()


def test_fix_scanner_still_flags_is_retried_when_retriage_disagrees(tmp_path):
    finding = make_finding(line=117, rule="r.redirect", cwe="CWE-601")
    repo = _repo(tmp_path, "x = 1\n")
    fix = FixResult(finding=finding, diff="d", applied=True, branch="b", baseline="x = 1\n")
    retriage = MagicMock(return_value=TriageResult(finding, "still bad", 0.9, "fix"))

    with patch("validator.scan", return_value=[finding]), \
         patch("validator.run_test_suite", return_value=(True, "9 passed")), \
         patch("validator.fix_finding", return_value=fix):
        result = validate_and_retry(fix, MagicMock(), repo, str(tmp_path), [],
                                    max_retries=1, baseline_count=1, retriage=retriage)

    assert result.validated is False and result.failure == "still flagged"


def test_fix_that_introduces_a_new_finding_is_rejected(tmp_path):
    finding = make_finding(line=123, rule="r.xss", cwe="CWE-79")
    repo = _repo(tmp_path, "y = 2\n")
    fix = FixResult(finding=finding, diff="d", applied=True, branch="b", baseline="y = 1\n")
    new_issue = make_finding(line=124, rule="r.render-template-string", cwe="CWE-96")

    with patch("validator.scan", return_value=[new_issue]), \
         patch("validator.run_test_suite", return_value=(True, "9 passed")), \
         patch("validator.fix_finding", return_value=fix) as mock_fix:
        result = validate_and_retry(fix, MagicMock(), repo, str(tmp_path), [], max_retries=1,
                                    known_rules={"r.xss"})

    assert result.validated is False
    assert "introduced new security findings" in mock_fix.call_args.kwargs["retry_feedback"]
    assert "r.render-template-string" in result.test_output


def test_fix_generation_skips_hidden_reasoning(tmp_path):
    from fixer import fix_finding
    (tmp_path / "app.py").write_text("x = 1\n")
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)
    ollama = MagicMock()
    ollama.generate.return_value = "no blocks"

    fix_finding(make_finding(line=1), ollama, repo)

    assert ollama.generate.call_args.kwargs["think"] is False
