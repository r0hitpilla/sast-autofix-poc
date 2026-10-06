from unittest.mock import MagicMock, patch

from git.exc import GitCommandError

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
        file="app.py",
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


def test_apply_diff_returns_false_when_tempfile_creation_fails():
    repo = MagicMock()
    with patch("fixer.tempfile.mkstemp", side_effect=OSError("disk full")):
        ok = apply_diff(repo, SAMPLE_DIFF)
    assert ok is False
    repo.git.apply.assert_not_called()


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


def test_fix_finding_survives_ollama_failure_instead_of_crashing():
    # Spec: an Ollama call failure is logged and the finding is skipped —
    # it must never take the whole pipeline down mid-run.
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.side_effect = ConnectionError("ollama unreachable")
    repo = MagicMock()

    result = fix_finding(finding, ollama, repo)

    assert result.applied is False
    assert result.diff == ""
    assert result.branch == branch_name(finding)
    repo.git.checkout.assert_not_called()


def test_fix_finding_reuses_existing_branch_instead_of_crashing():
    # branch_name is a pure function of the finding, so a retry (or a second
    # pipeline run over a repo with leftover branches) asks for a branch that
    # already exists. `checkout -b` raises there; the pipeline must not.
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()
    repo.git.checkout.side_effect = [
        GitCommandError("git checkout -b", 128),  # branch already exists
        None,                                     # plain checkout succeeds
    ]

    result = fix_finding(finding, ollama, repo)

    assert result.applied is True
    checkout_calls = [c.args for c in repo.git.checkout.call_args_list]
    assert checkout_calls == [("-b", result.branch), (result.branch,)]


def test_fix_finding_discards_previous_attempt_before_applying_a_retry():
    # The rejected retry-N edits are still uncommitted in the working tree.
    # Without a snapshot, the file falls back to HEAD — and that restore must
    # happen before the model is prompted, so it diffs against clean code.
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()

    with patch("fixer.apply_diff", return_value=True) as mock_apply:
        fix_finding(finding, ollama, repo, retry_feedback="previous attempt failed")

    checkout_calls = [c.args for c in repo.git.checkout.call_args_list]
    assert checkout_calls[0] == ("--", finding.file)
    mock_apply.assert_called_once()


def test_fix_finding_retry_restores_snapshot_not_head(tmp_path):
    # An earlier validated fix in the same file is uncommitted; restoring to
    # HEAD would wipe it. A retry must rewind only to this finding's snapshot.
    (tmp_path / "app.py").write_text("rejected attempt\n")
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)
    seen = {}

    def apply(repo_, diff):
        seen["content"] = (tmp_path / "app.py").read_text()
        return True

    with patch("fixer.apply_diff", side_effect=apply):
        result = fix_finding(
            finding, ollama, repo,
            retry_feedback="previous attempt failed",
            baseline="earlier validated fix\n",
        )

    assert seen["content"] == "earlier validated fix\n"
    assert result.baseline == "earlier validated fix\n"
    assert ("--", finding.file) not in [c.args for c in repo.git.checkout.call_args_list]


def test_fix_finding_snapshots_file_and_sends_numbered_context(tmp_path):
    (tmp_path / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 61)))
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()
    repo.working_tree_dir = str(tmp_path)

    with patch("fixer.apply_diff", return_value=True):
        result = fix_finding(finding, ollama, repo)

    assert result.baseline.startswith("line 1\n")
    prompt = ollama.generate.call_args[0][0]
    assert "41 | line 41" in prompt


def test_fix_finding_does_not_discard_on_the_first_attempt():
    finding = make_finding()
    ollama = MagicMock()
    ollama.generate.return_value = f"```diff\n{SAMPLE_DIFF}```"
    repo = MagicMock()

    fix_finding(finding, ollama, repo)

    checkout_calls = [c.args for c in repo.git.checkout.call_args_list]
    assert ("--", finding.file) not in checkout_calls
