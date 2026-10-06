from unittest.mock import MagicMock

from models import Finding, TriageResult, ValidationResult
from pr import build_pr_body, commit_validated_findings, open_or_update_pr


def make_entry(validated=True):
    finding = Finding(
        file="app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet="query = f\"...\"",
    )
    triage = TriageResult(
        finding=finding,
        llm_reasoning="Exploitable, no upstream sanitization.",
        laya_score=0.92,
        route="fix",
    )
    validation = ValidationResult(
        finding=finding,
        clean=True,
        test_output="no tests found",
        validated=validated,
    )
    return triage, validation


def test_build_pr_body_includes_required_fields_per_finding():
    entries = [make_entry()]
    body = build_pr_body(entries)

    triage, validation = entries[0]
    assert triage.finding.cwe in body
    assert triage.finding.snippet in body
    assert triage.llm_reasoning in body
    assert "0.92" in body
    assert "validated" in body.lower()
    assert "re-scan clean" in body.lower() or "no tests found" in body.lower()


def test_build_pr_body_skips_non_validated_entries():
    entries = [make_entry(validated=False)]
    body = build_pr_body(entries)
    assert body.strip() == "" or "no validated findings" in body.lower()


def test_commit_creates_the_fix_branch_from_the_developer_branch():
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branch = commit_validated_findings(repo, entries, "SV-fix")

    assert branch == "SV-fix"
    # -B: rebuilt from the current (developer) branch on every scan.
    repo.git.checkout.assert_called_once_with("-B", "SV-fix")
    repo.git.add.assert_called_once_with("app.py")  # same file added once
    repo.git.commit.assert_called_once()


def test_commit_falls_back_to_bot_identity_when_git_has_none():
    from git.exc import GitCommandError

    repo = MagicMock()
    repo.git.config.side_effect = GitCommandError("git config user.email", 1)

    commit_validated_findings(repo, [make_entry()], "SV-fix")

    repo.git.custom_environment.assert_called_once()
    assert repo.git.custom_environment.call_args.kwargs["GIT_AUTHOR_NAME"] == "sast-autofix[bot]"
    repo.git.commit.assert_called_once()


def _github(existing_prs):
    github_client = MagicMock()
    gh_repo = github_client.get_repo.return_value
    gh_repo.get_pulls.return_value = existing_prs
    new_pr = MagicMock(html_url="https://github.com/o/r/pull/9")
    gh_repo.create_pull.return_value = new_pr
    return github_client, gh_repo, new_pr


def test_opens_pr_from_fix_branch_into_developer_branch():
    github_client, gh_repo, new_pr = _github([])

    url = open_or_update_pr(github_client, "o/r", head="SV-fix", base="SV", title="t", body="b")

    assert url == "https://github.com/o/r/pull/9"
    gh_repo.get_pulls.assert_called_once_with(state="open", head="o:SV-fix", base="SV")
    gh_repo.create_pull.assert_called_once_with(title="t", body="b", head="SV-fix", base="SV")


def test_rescan_updates_the_existing_pr_instead_of_opening_another():
    existing = MagicMock(html_url="https://github.com/o/r/pull/3")
    github_client, gh_repo, _ = _github([existing])

    url = open_or_update_pr(github_client, "o/r", head="SV-fix", base="SV", title="t", body="new body")

    assert url == "https://github.com/o/r/pull/3"
    existing.edit.assert_called_once_with(title="t", body="new body")
    gh_repo.create_pull.assert_not_called()


def test_posts_inline_line_comments_as_a_review():
    github_client, _, new_pr = _github([])
    comments = [{"path": "app.py", "line": 44, "side": "RIGHT", "body": "fix"}]

    open_or_update_pr(github_client, "o/r", "SV-fix", "SV", "t", "b", line_comments=comments)

    kwargs = new_pr.create_review.call_args.kwargs
    assert kwargs["event"] == "COMMENT"
    assert kwargs["comments"] == comments


def test_keeps_pr_url_when_inline_review_fails():
    github_client, _, new_pr = _github([])
    new_pr.create_review.side_effect = RuntimeError("422 line not in diff")

    url = open_or_update_pr(github_client, "o/r", "SV-fix", "SV", "t", "b",
                            line_comments=[{"path": "a", "line": 1, "side": "RIGHT", "body": "x"}])

    assert url == "https://github.com/o/r/pull/9"


def test_pr_body_lists_unfixed_findings_with_suggestions():
    from report import FindingRecord

    fixed = make_entry()
    finding = Finding(file="app.py", line=60, rule_id="r", cwe="CWE-22",
                      message="m", snippet="return send_file(p)")
    triage = TriageResult(finding=finding, llm_reasoning="x", laya_score=0.9, route="fix",
                          evidence=[("Initial analysis", "blah\nVERDICT: user path reaches send_file")])
    failed = ValidationResult(finding=finding, clean=False, test_output="undefined name 'abort'",
                              validated=False, attempts=4, failure="breaks code or tests",
                              last_proposal="<<<<<<< ORIGINAL\nx\n=======\ny\n>>>>>>> FIXED")

    body = build_pr_body([fixed], [], "o/r", "SV-fix", base="SV",
                         unresolved=[FindingRecord(triage, "fix applied but failed validation", failed)])

    assert "`SV-fix` → `SV`" in body
    assert "Findings not fixed automatically" in body
    assert "`app.py:60` — CWE-22" in body
    assert "user path reaches send_file" in body
    assert "undefined name 'abort'" in body
    assert "Last proposed fix (unverified)" in body
