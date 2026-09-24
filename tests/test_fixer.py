from unittest.mock import MagicMock

from models import Finding
from fixer import apply_diff, branch_name, build_fix_prompt, fix_finding

SAMPLE_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,1 +1,1 @@
-query = f"SELECT * FROM users WHERE username = '{username}'"
+query = "SELECT * FROM users WHERE username = ?"
"""


def make_finding():
    return Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"SELECT ... WHERE username = '{username}'\"",
    )


def test_branch_name_is_stable_and_safe():
    finding = make_finding()
    name = branch_name(finding)
    assert name.startswith("autofix/")
    assert " " not in name
    assert "CWE-89".lower() in name.lower() or "cwe-89" in name.lower()


def test_build_fix_prompt_without_retry_feedback():
    finding = make_finding()
    prompt = build_fix_prompt(finding)
    assert finding.file in prompt
    assert finding.snippet in prompt
    assert "unified diff" in prompt.lower()


def test_build_fix_prompt_includes_retry_feedback():
    finding = make_finding()
    prompt = build_fix_prompt(finding, retry_feedback="Previous patch broke test_search")
    assert "Previous patch broke test_search" in prompt


def test_apply_diff_calls_git_apply(tmp_path):
    repo = MagicMock()
    ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is True
    assert repo.git.apply.call_count == 1
    assert repo.git.apply.call_args[0][0] == "--whitespace=fix"


def test_apply_diff_returns_false_on_git_error():
    repo = MagicMock()
    repo.git.apply.side_effect = Exception("patch does not apply")
    ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is False


def test_fix_finding_extracts_diff_and_applies_it():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()

    result = fix_finding(finding, ollama, repo)

    assert result.finding is finding
    assert "SELECT * FROM users WHERE username = ?" in result.diff
    assert result.applied is True
    assert result.branch.startswith("autofix/")
    repo.git.checkout.assert_called_once_with("-b", result.branch)


def test_fix_finding_marks_not_applied_when_no_diff_found():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = "I don't think this needs a fix."
    repo = MagicMock()

    result = fix_finding(finding, ollama, repo)

    assert result.applied is False
    assert result.diff == ""
