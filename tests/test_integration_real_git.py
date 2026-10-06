"""Real-git integration test — no MagicMock repo anywhere in this file.

Every other fixer/validator/pr/cli test drives a `MagicMock` repo, which is
structurally blind to how git actually behaves: a mock happily accepts a
second `checkout -b` for an existing branch, a pathspec that doesn't resolve,
and a patch that git would reject. That blindness is exactly how the
branch-collision crash and the path-frame mismatch shipped.

So this test uses a real `git.Repo` on a real working tree: a real initial
commit, a real `git apply`, real branch checkouts, and assertions against the
bytes actually on disk.
"""

import git
import pytest

from fixer import branch_name, fix_finding
from git_utils import checkout_branch
from models import Finding

VULNERABLE_LINE = 'query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
FIXED_LINE = 'query = "SELECT * FROM users WHERE name = ?"\n'

UNIFIED_DIFF = (
    "```diff\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1 +1 @@\n"
    "-" + VULNERABLE_LINE +
    "+" + FIXED_LINE +
    "```"
)


class FakeOllama:
    """Stands in for the LLM only — the git side stays completely real."""

    def __init__(self, output=UNIFIED_DIFF):
        self.output = output
        self.prompts = []

    def generate(self, prompt, think=None):
        self.prompts.append(prompt)
        return self.output


@pytest.fixture
def real_repo(tmp_path):
    repo_path = tmp_path / "target"
    repo_path.mkdir()
    # newline="\n": the repo's own content is LF, like the diffs the model
    # emits, so a CRLF-vs-LF mismatch can't mask a real result here.
    (repo_path / "app.py").write_text(VULNERABLE_LINE, newline="\n")

    repo = git.Repo.init(repo_path)
    with repo.config_writer() as cw:
        cw.set_value("user", "name", "sast-autofix-test")
        cw.set_value("user", "email", "test@example.invalid")
    repo.index.add(["app.py"])
    repo.index.commit("initial")
    return repo, repo_path


def make_finding():
    # "app.py", repo-root-relative — the frame scanner.run_semgrep now
    # produces by scanning "." with cwd=target_repo.
    return Finding(
        file="app.py",
        line=1,
        rule_id="test.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet=VULNERABLE_LINE.strip(),
    )


def test_fix_finding_applies_a_real_patch_to_a_real_working_tree(real_repo):
    repo, repo_path = real_repo
    finding = make_finding()

    result = fix_finding(finding, FakeOllama(), repo)

    assert result.applied is True, "git apply rejected the patch"
    # The bytes on disk actually changed — not just a mock recording a call.
    assert (repo_path / "app.py").read_text() == FIXED_LINE
    # ...on a real branch, which really exists in the real repo.
    assert repo.active_branch.name == branch_name(finding)
    assert branch_name(finding) in [h.name for h in repo.heads]


def test_retrying_the_same_finding_does_not_crash_on_branch_collision(real_repo):
    # branch_name is a pure function of the finding, so validate_and_retry's
    # second fix_finding call for the SAME finding asks git to create a
    # branch that already exists. An unguarded `checkout -b` raises
    # GitCommandError there and takes the whole pipeline down, discarding
    # every finding validated so far.
    repo, repo_path = real_repo
    finding = make_finding()
    ollama = FakeOllama()

    first = fix_finding(finding, ollama, repo)
    assert first.applied is True

    second = fix_finding(finding, ollama, repo, retry_feedback="needs adjustment")

    assert second.applied is True, "retry could not re-apply its diff"
    assert second.branch == first.branch
    # The retry discarded attempt 1's uncommitted edits first, so its diff
    # (generated against the ORIGINAL snippet) still matched the file.
    assert (repo_path / "app.py").read_text() == FIXED_LINE
    assert "needs adjustment" in ollama.prompts[-1]


def test_fix_finding_reuses_a_branch_left_over_from_a_previous_run(real_repo):
    # Second pipeline run against a target repo still carrying autofix
    # branches from a prior run: same collision, on the FIRST call.
    repo, repo_path = real_repo
    finding = make_finding()
    repo.git.branch(branch_name(finding))  # leftover from "yesterday's run"

    result = fix_finding(finding, FakeOllama(), repo)

    assert result.applied is True
    assert (repo_path / "app.py").read_text() == FIXED_LINE


def test_checkout_branch_is_idempotent_against_real_git(real_repo):
    repo, _ = real_repo

    checkout_branch(repo, "autofix/some-branch")
    checkout_branch(repo, "autofix/some-branch")  # would raise unguarded

    assert repo.active_branch.name == "autofix/some-branch"


def test_git_add_and_restore_accept_the_repo_root_relative_finding_path(real_repo):
    # pr.commit_validated_findings does `repo.git.add(finding.file)` and
    # validator's failure path does `repo.git.checkout("--", finding.file)`.
    # Both raise GitCommandError on a pathspec that doesn't resolve, so this
    # pins that Finding.file's frame matches the GitPython repo's root.
    repo, repo_path = real_repo
    finding = make_finding()

    fix_finding(finding, FakeOllama(), repo)
    repo.git.add(finding.file)
    repo.git.commit("-m", "fix: automated")

    assert (repo_path / "app.py").read_text() == FIXED_LINE
    assert repo.git.status("--porcelain") == ""

    # And the validator's scoped revert resolves too.
    (repo_path / "app.py").write_text("garbage\n", newline="\n")
    repo.git.checkout("--", finding.file)
    assert (repo_path / "app.py").read_text() == FIXED_LINE


def test_a_wrongly_framed_finding_path_really_does_fail_against_git(real_repo):
    # The C2 failure mode, pinned: a Finding.file carrying the target-repo
    # prefix resolves to target/target/app.py inside the repo — git apply
    # silently fails (apply_diff swallows it) and git add raises. This is why
    # cli.run_pipeline checks os.path.exists before touching a finding.
    repo, repo_path = real_repo
    wrongly_framed = Finding(
        file="target/app.py",
        line=1,
        rule_id="test.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet=VULNERABLE_LINE.strip(),
    )

    with pytest.raises(git.exc.GitCommandError):
        repo.git.add(wrongly_framed.file)

    assert (repo_path / "app.py").read_text() == VULNERABLE_LINE
