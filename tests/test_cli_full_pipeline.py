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
         patch("cli.commit_validated_findings", return_value="main-fix"), \
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
         patch("cli.commit_validated_findings", return_value="main-fix"), \
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

    def fake_validate(fix_result, *args, **kwargs):
        if not fix_result.applied:  # retries never produced a usable fix
            return ValidationResult(
                finding=fix_result.finding, clean=False, test_output="no edit blocks",
                validated=False, attempts=3, failure="no usable fix",
            )
        return ValidationResult(
            finding=fix_result.finding, clean=True, test_output="no tests found", validated=True,
        )

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[to_fix, to_review, to_reject, no_diff]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", side_effect=fake_triage), \
         patch("cli.fix_finding", side_effect=fake_fix), \
         patch("cli.validate_and_retry", side_effect=fake_validate), \
         patch("cli.commit_validated_findings", return_value="main-fix"), \
         patch("cli.build_pr_body", return_value="pr body"):

        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True)

    out = capsys.readouterr().out.lower()
    assert "scanned: 4 findings" in out
    # A "review" finding is no longer skipped: it gets a fix attempt, and the
    # validator decides whether that fix is accepted.
    assert "fixed and validated: 2" in out
    assert "sent to review" not in out
    assert "rejected (likely false positive): 1" in out
    assert "no usable fix from the llm: 1" in out


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
         patch("cli.commit_validated_findings", return_value="main-fix"), \
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


def test_run_pipeline_scans_developer_branch_and_targets_its_fix_branch(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    finding = make_finding()
    triage_result = TriageResult(finding=finding, llm_reasoning="r", laya_score=0.95, route="fix")
    validation_result = ValidationResult(
        finding=finding, clean=True, test_output="no tests found", validated=True,
    )
    mock_repo = MagicMock()

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.Github"), \
         patch("cli.scan", return_value=[finding]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=mock_repo), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding", return_value=FixResult(finding, "d", True, "b")), \
         patch("cli.validate_and_retry", return_value=validation_result) as mock_validate, \
         patch("cli.commit_validated_findings", return_value="SV-fix") as mock_commit, \
         patch("cli.branch_hunks", return_value=[]) as mock_hunks, \
         patch("cli.open_or_update_pr", return_value="https://github.com/o/r/pull/5") as mock_pr:
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=False, base_branch="SV")

    mock_repo.git.checkout.assert_any_call("SV")
    assert mock_validate.call_args.kwargs["base_branch"] == "SV"
    assert mock_commit.call_args.args[2] == "SV-fix"
    mock_hunks.assert_called_once_with(mock_repo, "SV", "SV-fix")
    mock_repo.git.push.assert_called_once_with("--force", "origin", "SV-fix:SV-fix")
    assert mock_pr.call_args.kwargs["head"] == "SV-fix"
    assert mock_pr.call_args.kwargs["base"] == "SV"


def test_merge_gate_fails_while_confirmed_findings_remain(tmp_path):
    from cli import main
    from report import FindingRecord, RunReport

    finding = make_finding()
    report = RunReport(target="t")
    report.records.append(FindingRecord(
        TriageResult(finding=finding, llm_reasoning="r", laya_score=0.9, route="fix"),
        "fixed and validated",
    ))

    with patch("cli.run_pipeline", return_value=report):
        with pytest.raises(SystemExit) as exc:
            main(["run", "--target-repo", str(tmp_path), "--fail-on-findings"])
    assert exc.value.code == 1


def test_merge_gate_passes_when_only_false_positives_remain(tmp_path):
    from cli import main
    from report import FindingRecord, RunReport

    report = RunReport(target="t")
    report.records.append(FindingRecord(
        TriageResult(finding=make_finding(), llm_reasoning="r", laya_score=0.1, route="reject"),
        "rejected (likely false positive)",
    ))

    with patch("cli.run_pipeline", return_value=report):
        main(["run", "--target-repo", str(tmp_path), "--fail-on-findings"])  # no SystemExit


def test_check_only_mode_triages_and_reports_but_never_fixes(tmp_path, capsys):
    finding = make_finding()
    triage_result = TriageResult(finding=finding, llm_reasoning="r", laya_score=0.95, route="fix")

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[finding]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result), \
         patch("cli.fix_finding") as mock_fix, \
         patch("cli.commit_validated_findings") as mock_commit:
        report = run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True,
                              base_branch="SV-fix", check_only=True)

    mock_fix.assert_not_called()
    mock_commit.assert_not_called()
    assert len(report.blocking) == 1  # still gates
    assert "confirmed (check only, not fixed): 1" in capsys.readouterr().out.lower()


def test_fix_branch_gets_a_status_from_the_final_rescan(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    fixed = make_finding(line=41)
    rejected = Finding(file="app.py", line=90, rule_id="other.rule", cwe="CWE-1",
                       message="m", snippet="s")
    routes = {
        41: TriageResult(finding=fixed, llm_reasoning="r", laya_score=0.95, route="fix"),
        90: TriageResult(finding=rejected, llm_reasoning="r", laya_score=0.1, route="reject"),
    }
    validation = ValidationResult(finding=fixed, clean=True, test_output="ok", validated=True)
    mock_repo = MagicMock()
    mock_repo.head.commit.hexsha = "abc123"

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.Github"), \
         patch("cli.scan", side_effect=[[fixed, rejected], [rejected]]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=mock_repo), \
         patch("cli.triage_finding", side_effect=lambda f, *a, **k: routes[f.line]), \
         patch("cli.fix_finding", return_value=FixResult(fixed, "d", True, "b")), \
         patch("cli.validate_and_retry", return_value=validation), \
         patch("cli.commit_validated_findings", return_value="SV-fix"), \
         patch("cli.branch_hunks", return_value=[]), \
         patch("cli.open_or_update_pr", return_value="u"), \
         patch("cli.set_commit_status") as mock_status:
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=False, base_branch="SV")

    args, kwargs = mock_status.call_args
    assert args[2] == "abc123"
    # Only a rejected false positive is left on SV-fix -> it passes.
    assert kwargs["state"] == "success"
    assert kwargs["target_url"].endswith("/actions/runs/42")


def test_same_line_is_triaged_and_fixed_once(tmp_path, capsys):
    a = Finding(file="app.py", line=41, rule_id="xss.one", cwe="CWE-79", message="m1", snippet="s")
    b = Finding(file="app.py", line=41, rule_id="xss.two", cwe="CWE-79", message="m2", snippet="s")
    triage_result = TriageResult(finding=a, llm_reasoning="r", laya_score=0.9, route="fix")
    failed = ValidationResult(finding=a, clean=False, test_output="t", validated=False,
                              attempts=4, failure="still flagged")

    with patch("cli.load_config", return_value=MagicMock()), \
         patch("cli.scan", return_value=[a, b]), \
         patch("cli.OllamaClient"), \
         patch("cli.LayaClient"), \
         patch("cli.git.Repo", return_value=MagicMock()), \
         patch("cli.triage_finding", return_value=triage_result) as mock_triage, \
         patch("cli.fix_finding", return_value=FixResult(a, "d", True, "b")) as mock_fix, \
         patch("cli.validate_and_retry", return_value=failed):
        run_pipeline(make_target_repo(tmp_path), "config.yaml", dry_run=True, base_branch="SV2")

    assert mock_triage.call_count == 1       # verdict reused for the second rule
    assert mock_fix.call_count == 1          # no second round of attempts
    # ...and the one fix was told about both rules on that line.
    assert "xss.two" in mock_fix.call_args.args[0].message
    assert "not fixed (same code as a failed fix): 1" in capsys.readouterr().out.lower()
