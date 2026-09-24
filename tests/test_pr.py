from unittest.mock import MagicMock

from models import Finding, TriageResult, ValidationResult
from pr import build_pr_body, commit_validated_findings, open_pr


def make_entry(validated=True):
    finding = Finding(
        file="sample_vuln_app/app.py",
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


def test_commit_validated_findings_single_strategy_uses_one_branch():
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branches = commit_validated_findings(repo, entries, strategy="single")

    assert len(set(branches)) == 1
    repo.git.checkout.assert_called()
    repo.git.add.assert_called()
    repo.git.commit.assert_called()


def test_commit_validated_findings_per_finding_strategy_uses_multiple_branches():
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branches = commit_validated_findings(repo, entries, strategy="per-finding")

    assert len(branches) == 2
    assert len(set(branches)) == 2


def test_commit_validated_findings_per_finding_strategy_disambiguates_same_rule_and_line():
    # Two validated findings sharing the same rule_id + file + line (e.g. a
    # re-triaged finding, or two closely related findings at the same
    # source line) must still produce distinct branch names.
    repo = MagicMock()
    entries = [make_entry(), make_entry()]

    branches = commit_validated_findings(repo, entries, strategy="per-finding")

    assert len(branches) == 2
    assert len(set(branches)) == 2


def test_open_pr_dry_run_returns_none_and_does_not_call_github():
    github_client = MagicMock()
    url = open_pr(github_client, "r0hitpilla/sast-poc-vuln-app", "autofix/x", "title", "body", dry_run=True)

    assert url is None
    github_client.get_repo.assert_not_called()


def test_open_pr_creates_pull_request_when_not_dry_run():
    github_client = MagicMock()
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_pr.html_url = "https://github.com/r0hitpilla/sast-poc-vuln-app/pull/1"
    mock_repo.create_pull.return_value = mock_pr
    github_client.get_repo.return_value = mock_repo

    url = open_pr(github_client, "r0hitpilla/sast-poc-vuln-app", "autofix/x", "title", "body", dry_run=False)

    assert url == "https://github.com/r0hitpilla/sast-poc-vuln-app/pull/1"
    mock_repo.create_pull.assert_called_once_with(
        title="title", body="body", head="autofix/x", base="main"
    )
