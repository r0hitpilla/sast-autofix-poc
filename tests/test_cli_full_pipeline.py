from unittest.mock import MagicMock, patch

from cli import build_parser, run_pipeline
from models import Finding, FixResult, TriageResult, ValidationResult


def test_pr_subcommand_has_dry_run_flag():
    parser = build_parser()
    args = parser.parse_args(["pr", "--target-repo", "x", "--dry-run"])
    assert args.dry_run is True


def test_run_subcommand_has_dry_run_flag():
    parser = build_parser()
    args = parser.parse_args(["run", "--target-repo", "x", "--dry-run"])
    assert args.dry_run is True


def test_run_subcommand_defaults_dry_run_false():
    parser = build_parser()
    args = parser.parse_args(["run", "--target-repo", "x"])
    assert args.dry_run is False


def test_run_pipeline_dry_run_never_reads_github_token(monkeypatch):
    # GITHUB_TOKEN is only read on the non-dry-run push/PR path. This proves
    # dry_run=True short-circuits before that read, even with every
    # collaborator mocked out and the token entirely unset — a KeyError here
    # would mean dry-run silently started depending on real credentials.
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    finding = Finding(
        file="sample_vuln_app/app.py",
        line=41,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet='query = f"..."',
    )
    triage_result = TriageResult(
        finding=finding, llm_reasoning="reasoning", laya_score=0.95, route="fix",
    )
    fix_result = FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")
    validation_result = ValidationResult(
        finding=finding, clean=True, test_output="no tests found", validated=True,
    )
    mock_repo = MagicMock()

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[finding]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=mock_repo), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding", return_value=fix_result), \
         patch("cli.validate_and_retry", return_value=validation_result), \
         patch("cli.commit_validated_findings", return_value=["autofix/x"]), \
         patch("cli.build_pr_body", return_value="pr body"):

        run_pipeline("sample_vuln_app", "config.yaml", dry_run=True)

    mock_repo.git.push.assert_not_called()
