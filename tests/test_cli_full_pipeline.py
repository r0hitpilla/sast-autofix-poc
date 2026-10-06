from unittest.mock import MagicMock, patch

import pytest

from cli import build_parser, run_pipeline
from models import Finding, FixResult, TriageResult, ValidationResult


@pytest.fixture(autouse=True)
def isolated_cwd(tmp_path, monkeypatch):
    # run_pipeline writes its report under ./reports — keep that out of the repo.
    monkeypatch.chdir(tmp_path)


def make_finding(file="app.py", line=41):
    return Finding(
        file=file,
        line=line,
        rule_id="python.flask.security.injection.sql-injection",
        cwe="CWE-89",
        message="Detected string-interpolated SQL query.",
        snippet='query = f"..."',
    )


def make_target_repo(tmp_path):
    """A directory holding the file a repo-root-relative Finding points at."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('query = f"..."\n')
    return str(target)


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


def test_run_pipeline_dry_run_never_reads_github_token(tmp_path, monkeypatch):
    # GITHUB_TOKEN is only read on the non-dry-run push/PR path. This proves
    # dry_run=True short-circuits before that read, even with every
    # collaborator mocked out and the token entirely unset — a KeyError here
    # would mean dry-run silently started depending on real credentials.
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    finding = make_finding()
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

        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    mock_repo.git.push.assert_not_called()


def test_run_pipeline_skips_findings_whose_file_is_not_in_the_target_repo(tmp_path, capsys):
    # Finding.file is repo-root-relative. If it ever comes back in another
    # frame (e.g. "target/app.py" while the repo is rooted AT target/), every
    # repo.git.* call would silently address a nonexistent path. That must be
    # a loud, diagnosable skip, not a no-op.
    finding = make_finding(file="target/app.py")
    triage_result = TriageResult(
        finding=finding, llm_reasoning="reasoning", laya_score=0.95, route="fix",
    )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[finding]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding") as mock_fix_finding:

        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    mock_fix_finding.assert_not_called()
    captured = capsys.readouterr()
    assert "target/app.py" in captured.err
    assert "does not exist" in captured.err
    assert "file not found in target repo" in captured.out.lower()


def test_run_pipeline_passes_a_baseline_count_that_tracks_validated_fixes(tmp_path):
    # Two instances of the same rule in the same file: the validator needs
    # the pre-fix count to recognise "one of them is gone" as progress, so
    # the first call gets the original count (2). And once that fix
    # validates, the second call must be measured against what is really
    # left (1) — a stale whole-run baseline of 2 would auto-pass the second
    # finding even if its own fix did nothing.
    first = make_finding(line=42)
    second = make_finding(line=44)
    triage_result = TriageResult(
        finding=first, llm_reasoning="reasoning", laya_score=0.95, route="fix",
    )
    fix_result = FixResult(finding=first, diff="some diff", applied=True, branch="autofix/x")
    validation_result = ValidationResult(
        finding=first, clean=True, test_output="no tests found", validated=True,
    )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[first, second]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding", return_value=fix_result), \
         patch("cli.validate_and_retry", return_value=validation_result) as mock_validate, \
         patch("cli.commit_validated_findings", return_value=["autofix/x"]), \
         patch("cli.build_pr_body", return_value="pr body"):

        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    baselines = [c.kwargs["baseline_count"] for c in mock_validate.call_args_list]
    assert baselines == [2, 1]


def test_run_pipeline_summarises_every_finding_outcome(tmp_path, capsys):
    # No finding may vanish silently: review/reject/failed-fix outcomes are
    # all accounted for in the end-of-run summary, not just the fixed ones.
    to_fix = make_finding(line=41)
    to_review = make_finding(line=50)
    to_reject = make_finding(line=60)
    no_diff = make_finding(line=70)

    routes = {
        41: TriageResult(finding=to_fix, llm_reasoning="r", laya_score=0.95, route="fix"),
        50: TriageResult(finding=to_review, llm_reasoning="r", laya_score=0.6, route="review"),
        60: TriageResult(finding=to_reject, llm_reasoning="r", laya_score=0.1, route="reject"),
        70: TriageResult(finding=no_diff, llm_reasoning="r", laya_score=0.95, route="fix"),
    }

    def fake_triage(finding, *args, **kwargs):
        return routes[finding.line]

    def fake_fix(finding, *args, **kwargs):
        if finding.line == 70:  # model produced no usable diff
            return FixResult(finding=finding, diff="", applied=False, branch="autofix/x")
        return FixResult(finding=finding, diff="some diff", applied=True, branch="autofix/x")

    validation_result = ValidationResult(
        finding=to_fix, clean=True, test_output="no tests found", validated=True,
    )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[to_fix, to_review, to_reject, no_diff]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", side_effect=fake_triage), \
         patch("cli.fix_finding", side_effect=fake_fix), \
         patch("cli.validate_and_retry", return_value=validation_result), \
         patch("cli.commit_validated_findings", return_value=["autofix/x"]), \
         patch("cli.build_pr_body", return_value="pr body"):

        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    out = capsys.readouterr().out.lower()
    assert "scanned: 4 findings" in out
    assert "fixed and validated: 1" in out
    assert "sent to review: 1" in out
    assert "rejected (likely false positive): 1" in out
    assert "fix generation failed: 1" in out


def test_run_pipeline_skips_entirely_while_an_autofix_pr_is_open(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.Github"), \
         patch("cli.open_autofix_prs", return_value=["https://github.com/o/r/pull/7"]), \
         patch("cli.scan") as mock_scan:
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=False, skip_if_open_pr=True)

    mock_scan.assert_not_called()
    assert "pull/7" in capsys.readouterr().out


def test_run_pipeline_writes_report_and_job_summary(tmp_path, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    finding = make_finding()
    triage_result = TriageResult(
        finding=finding, llm_reasoning="r", laya_score=0.95, route="fix",
        evidence=[("Initial analysis", "r")],
    )
    validation_result = ValidationResult(
        finding=finding, clean=True, test_output="no tests found", validated=True,
    )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", side_effect=[[finding], []]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding", return_value=FixResult(finding, "d", True, "b")), \
         patch("cli.validate_and_retry", return_value=validation_result), \
         patch("cli.commit_validated_findings", return_value=["autofix/run-1"]), \
         patch("cli.branch_hunks", return_value=[]):
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True,
                     report_dir=str(tmp_path / "out"))

    md = (tmp_path / "out" / "sast-autofix-report.md").read_text()
    assert "| 1 | 1 | 1 | 100% | 0 | 0 | 0 |" in md
    assert "`app.py:41`" in md
    assert summary.read_text() == md
    assert (tmp_path / "out" / "sast-autofix-report.json").exists()


def test_run_pipeline_never_auto_fixes_workflow_files(tmp_path, capsys):
    finding = make_finding(file=".github/workflows/ci.yml")
    triage_result = TriageResult(
        finding=finding, llm_reasoning="r", laya_score=0.95, route="fix",
    )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[finding]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding") as mock_fix_finding:
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    mock_fix_finding.assert_not_called()
    assert "ci/workflow file, never auto-fixed): 1" in capsys.readouterr().out.lower()
