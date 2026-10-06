import argparse
import dataclasses
import json
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone

import git
from github import Auth, Github

from config import load_config
from fixer import fix_finding
from laya_client import LayaClient
from ollama_client import OllamaClient
from code_context import numbered_context
from diff_utils import branch_hunks
from pr import (
    build_line_comments,
    build_pr_body,
    commit_validated_findings,
    open_or_update_pr,
    set_commit_status,
)
from provenance import provenance
from report import FindingRecord, RunReport, write_report
from risk import by_risk
from scanner import scan
from triage import triage_finding
from validator import count_same_rule_and_file, validate_and_retry


def cmd_scan(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets, cfg.engines)
    print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))


def cmd_triage(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets, cfg.engines)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)

    results = triage_all(findings, args.target_repo, cfg, ollama, laya)

    print(json.dumps([
        {
            "finding": dataclasses.asdict(r.finding),
            "llm_reasoning": r.llm_reasoning,
            "laya_score": r.laya_score,
            "route": r.route,
            "evidence": [{"question": q, "answer": a} for q, a in r.evidence],
        }
        for r in results
    ], indent=2))


def triage_all(findings, target_repo, cfg, ollama, laya):
    """Triage every finding against the UNMODIFIED repo, before any fix lands —
    later fixes shift line numbers, which would skew the code context."""
    results = []
    by_location = {}
    for n, f in enumerate(findings, start=1):
        print(f"[triage {n}/{len(findings)}] {f.file}:{f.line} {f.cwe}", file=sys.stderr, flush=True)
        earlier = by_location.get((f.file, f.line))
        if earlier is not None:
            # Several rules often flag the same line (three XSS rules on one
            # f-string). It's the same code, so it gets the same verdict:
            # investigating it again only costs minutes of LLM time.
            print(f"    same code as an earlier finding -> {earlier.route} (verdict reused)",
                  file=sys.stderr, flush=True)
            results.append(dataclasses.replace(earlier, finding=f))
            continue
        context = numbered_context(target_repo, f)
        result = triage_finding(
            f, ollama, laya, cfg.threshold_fix, cfg.threshold_review,
            max_rounds=cfg.triage_max_rounds,
            context=context,
        )
        result = dataclasses.replace(result, context=context)
        asked = len(result.evidence) - 1 if result.evidence else 0
        print(
            f"    Laya asked the LLM {asked} follow-up question(s) -> "
            f"score {result.laya_score:.2f} -> {result.route}",
            file=sys.stderr, flush=True,
        )
        results.append(result)
        by_location[(f.file, f.line)] = result
    return results


def with_all_rules(finding, findings):
    """`finding`, with the message listing every rule flagged on its line, so
    one fix addresses all of them instead of satisfying one rule at a time."""
    others = [
        f for f in findings
        if (f.file, f.line) == (finding.file, finding.line) and f.rule_id != finding.rule_id
    ]
    if not others:
        return finding
    extra = "\n".join(f"- {f.rule_id}: {f.message}" for f in others)
    return dataclasses.replace(
        finding,
        message=f"{finding.message}\nThe same line is also flagged by:\n{extra}",
    )


PROTECTED_PREFIXES = (".github/",)


def fix_branch_residual(report: RunReport) -> list:
    """Findings the final rescan (on the fix branch) still reports, minus the
    ones Laya rejected as false positives — those never block anything."""
    rejected = {
        (r.triage.finding.rule_id, r.triage.finding.file)
        for r in report.records
        if r.triage.route == "reject"
        # fixed code the scanner still matches, but triage judged safe
        or (r.validation is not None and r.validation.validated and r.validation.note)
    }
    return [f for f in report.residual if (f.rule_id, f.file) not in rejected]


def _pr_number(url: str | None) -> int | None:
    try:
        return int(str(url).rstrip("/").rsplit("/", 1)[-1])
    except ValueError:
        return None


def run_url(repo_full_name: str) -> str | None:
    run_id = os.environ.get("GITHUB_RUN_ID")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo_full_name}/actions/runs/{run_id}" if run_id else None


@contextmanager
def timed(timings: dict, stage: str):
    start = time.monotonic()
    try:
        yield
    finally:
        timings[stage] = timings.get(stage, 0.0) + time.monotonic() - start


def run_pipeline(
    target_repo: str,
    config_path: str,
    dry_run: bool,
    report_dir: str = "reports",
    base_branch: str | None = None,
    fix_branch: str | None = None,
    check_only: bool = False,
):
    """Scan the developer's branch (`base_branch`, e.g. SV) as a whole repo
    and propose fixes on `fix_branch` (default "<base>-fix") via a PR into
    the developer's branch — never into main directly."""
    cfg = load_config(config_path)
    repo_full_name = os.environ.get("GITHUB_REPO", "r0hitpilla/sast-poc-vuln-app")
    github_client = None if dry_run else Github(auth=Auth.Token(os.environ["GITHUB_TOKEN"]))

    repo = git.Repo(target_repo)
    if base_branch:
        repo.git.checkout(base_branch)
    else:
        base_branch = repo.active_branch.name
    fix_branch = fix_branch or f"{base_branch}-fix"

    report = RunReport(target=f"{repo_full_name if not dry_run else target_repo} @ {base_branch}")
    timings = report.timings
    started = datetime.now(timezone.utc)
    report.meta = {
        "run": {
            "id": os.environ.get("GITHUB_RUN_ID") or f"local-{started:%Y%m%d-%H%M%S}",
            "url": run_url(repo_full_name),
            "trigger": os.environ.get("GITHUB_EVENT_NAME", "local"),
            "repository": repo_full_name,
            "base_branch": base_branch,
            "fix_branch": fix_branch,
            "commit": repo.head.commit.hexsha,
            "mode": "check-only" if check_only else "fix",
            "dry_run": dry_run,
            "started_at": started.isoformat(),
        },
        "provenance": provenance(cfg),
        "pull_request": None,
        "fix_branch_status": None,
    }

    with timed(timings, "scan"):
        findings = scan(target_repo, cfg.semgrep_rulesets, cfg.engines)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)

    # Every finding ends up in exactly one of these buckets — a human reading
    # the run output must be able to account for all of them, not just the
    # ones that made it into the PR.
    outcomes = {
        "fixed and validated": 0,
        "fixed (scanner still flags; triage judged safe)": 0,
        "sent to review": 0,
        "sent to review (CI/workflow file, never auto-fixed)": 0,
        "rejected (likely false positive)": 0,
        "confirmed (check only, not fixed)": 0,
        "skipped (file not found in target repo)": 0,
        "resolved by an earlier fix": 0,
        "not fixed (same code as a failed fix)": 0,
        "no usable fix from the llm": 0,
        "fix applied but failed validation": 0,
    }

    def record(triage_result, outcome, validation=None):
        outcomes[outcome] += 1
        report.records.append(FindingRecord(triage_result, outcome, validation))

    # How many instances of each (rule_id, file) the target repo is still
    # expected to hold. Seeded from the original scan and decremented as
    # fixes validate, so each finding's validation compares the rescan
    # against the count that was really there just before ITS fix — not a
    # stale whole-run baseline that would auto-pass later same-rule findings.
    remaining = {
        (f.rule_id, f.file): count_same_rule_and_file(f, findings)
        for f in findings
    }

    with timed(timings, "triage (Laya + LLM)"):
        triage_results = triage_all(findings, target_repo, cfg, ollama, laya)

    if check_only:
        # Used on fix branches (SV-fix): report and gate, but never generate
        # fixes — that would mean a SV-fix-fix branch and a loop.
        for t in triage_results:
            record(t, {
                "fix": "confirmed (check only, not fixed)",
                "review": "sent to review",
            }.get(t.route, "rejected (likely false positive)"))
        print(f"\nCheck only — scanned: {len(findings)} findings.")
        for label, count in outcomes.items():
            if count:
                print(f"  {label.capitalize()}: {count}")
        print("Report:", write_report(report, report_dir))
        return report

    entries = []
    failed_at = {}  # (file, line) -> ValidationResult of a fix that never validated
    # Riskiest first: a run cut short still leaves the worst findings fixed.
    for triage_result in by_risk(triage_results):
        finding = triage_result.finding
        # Every finding that isn't a confirmed false positive gets a fix
        # attempt. "review" used to skip the fix; now the validator is the
        # gate: a fix that doesn't validate is never committed.
        if triage_result.route not in ("fix", "review"):
            record(triage_result, "rejected (likely false positive)")
            continue

        # GitHub refuses workflow-file changes pushed with the Actions token,
        # and an LLM editing CI config is exactly where a prompt injection
        # would do the most damage — these always go to a human.
        if finding.file.startswith(PROTECTED_PREFIXES):
            record(triage_result, "sent to review (CI/workflow file, never auto-fixed)")
            continue

        # Finding.file is repo-root-relative (scanner runs Semgrep with
        # cwd=target_repo), so it must resolve under target_repo. If it
        # doesn't, every downstream repo.git.* call would silently target a
        # nonexistent path — fail loudly and diagnosably here instead.
        resolved = os.path.join(target_repo, finding.file)
        if not os.path.exists(resolved):
            print(
                f"[skip] {finding.rule_id} at {finding.file}:{finding.line} — "
                f"expected the file at {resolved!r} but it does not exist; "
                "Finding.file is not in the target repo's frame.",
                file=sys.stderr,
            )
            record(triage_result, "skipped (file not found in target repo)")
            continue

        rule_file_key = (finding.rule_id, finding.file)
        if entries:
            # An earlier fix may already have removed this one too (e.g. two
            # rules flagging the same SQL string); don't spend LLM time on it.
            with timed(timings, "fix + rescan loop"):
                still_there = count_same_rule_and_file(
                    finding, scan(target_repo, cfg.semgrep_rulesets, cfg.engines)
                )
            if still_there < remaining[rule_file_key]:
                remaining[rule_file_key] = still_there
                record(triage_result, "resolved by an earlier fix")
                continue

        if (finding.file, finding.line) in failed_at:
            # Every retry on this exact code already failed; the next rule on
            # the same line would just repeat those attempts.
            record(triage_result, "not fixed (same code as a failed fix)",
                   failed_at[(finding.file, finding.line)])
            continue

        with timed(timings, "fix + rescan loop"):
            fix_result = fix_finding(
                with_all_rules(finding, findings), ollama, repo, model=cfg.fix_models[0],
            )
            validation_result = validate_and_retry(
                fix_result, ollama, repo, target_repo,
                cfg.semgrep_rulesets, cfg.max_fix_retries,
                engines=cfg.engines,
                baseline_count=remaining[rule_file_key],
                base_branch=base_branch,
                review=cfg.fix_review,
                known_rules={f.rule_id for f in findings if f.file == finding.file},
                fix_models=cfg.fix_models,
                retriage=lambda f: triage_finding(
                    f, ollama, laya, cfg.threshold_fix, cfg.threshold_review,
                    max_rounds=cfg.triage_max_rounds,
                    context=numbered_context(target_repo, f),
                ),
            )
        entries.append((triage_result, validation_result))
        if validation_result.validated and validation_result.note:
            # The scanner still matches here, so the count doesn't drop.
            record(triage_result, "fixed (scanner still flags; triage judged safe)", validation_result)
        elif validation_result.validated:
            remaining[rule_file_key] -= 1
            record(triage_result, "fixed and validated", validation_result)
        elif validation_result.failure == "no usable fix":
            failed_at[(finding.file, finding.line)] = validation_result
            record(triage_result, "no usable fix from the llm", validation_result)
        else:
            failed_at[(finding.file, finding.line)] = validation_result
            record(triage_result, "fix applied but failed validation", validation_result)

    print(f"\nScanned: {len(findings)} findings.")
    for label, count in outcomes.items():
        if count:
            print(f"  {label.capitalize()}: {count}")

    # Final whole-repo rescan with every validated fix in place: what's left
    # is exactly what this run did NOT fix.
    with timed(timings, "final rescan"):
        report.residual = scan(target_repo, cfg.semgrep_rulesets, cfg.engines)
    print(f"Final rescan: {len(report.residual)} finding(s) remain.")
    for f in report.residual:
        print(f"  - {f.file}:{f.line} {f.cwe} ({f.rule_id})")

    validated = [(t, v) for t, v in entries if v.validated]
    unresolved = [
        r for r in report.records
        if r.triage.route in ("fix", "review") and not (r.validation and r.validation.validated)
        and r.outcome not in ("resolved by an earlier fix", "not fixed (same code as a failed fix)")
    ]
    if not validated:
        # No code change means no branch to open a PR from; the findings and
        # suggestions still land in the run report / job summary.
        print("No findings validated for a fix.")
        if unresolved:
            print(f"{len(unresolved)} confirmed finding(s) need a developer — see the report.")
        print("Report:", write_report(report, report_dir))
        return report

    commit_validated_findings(repo, entries, fix_branch)

    # Built from the fix branch's real diff against the developer's branch,
    # so the line numbers in the body and the inline comments are exactly
    # the ones GitHub shows on the PR.
    hunks = branch_hunks(repo, base_branch, fix_branch)
    body = build_pr_body(
        entries, hunks, repo_full_name, fix_branch, base=base_branch, unresolved=unresolved,
    )
    comments = build_line_comments(entries, hunks)
    title = f"Security fixes for {base_branch} (sast-autofix)"

    if dry_run:
        print(f"[dry-run] Would push {fix_branch} and open/update PR {fix_branch} -> {base_branch}")
        print("[dry-run] PR body:\n", body)
        print(f"[dry-run] Inline line comments ({len(comments)}):")
        for c in comments:
            lines = f"L{c['start_line']}-L{c['line']}" if "start_line" in c else f"L{c['line']}"
            print(f"  {c['path']} {lines} ({c['side']}): {c['body'].splitlines()[0]}")
        # Leave the local repo where we found it; the commit stays on its branch.
        repo.git.checkout(base_branch)
        print("Report:", write_report(report, report_dir))
        return report

    # --force: SV-fix is owned by this tool and rebuilt from the latest SV on
    # every scan; a previous run's version of it is meant to be replaced.
    repo.git.push("--force", "origin", f"{fix_branch}:{fix_branch}")
    url = open_or_update_pr(
        github_client, repo_full_name, head=fix_branch, base=base_branch,
        title=title, body=body, line_comments=comments,
    )

    # The bot's push of SV-fix doesn't trigger a workflow run of its own
    # (GitHub never does for pushes made with the Actions token), but this
    # run already rescanned SV-fix: publish that as the fix commit's check.
    remaining = fix_branch_residual(report)
    status = {
        "sha": repo.head.commit.hexsha,
        "state": "failure" if remaining else "success",
        "description": (
            f"Rescan of {fix_branch}: {len(remaining)} confirmed finding(s) remain"
            if remaining else f"Rescan of {fix_branch}: no confirmed findings remain"
        ),
    }
    set_commit_status(
        github_client, repo_full_name, status["sha"],
        state=status["state"], description=status["description"],
        target_url=run_url(repo_full_name),
    )
    report.meta["fix_branch_status"] = status
    report.meta["pull_request"] = {
        "url": url, "number": _pr_number(url), "head": fix_branch, "base": base_branch,
    }
    report.pr_urls.append(url)
    print(f"PR: {url}")
    print("Report:", write_report(report, report_dir))
    return report


def cmd_fix(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets, cfg.engines)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(args.target_repo)

    results = []
    for triage_result in triage_all(findings, args.target_repo, cfg, ollama, laya):
        if triage_result.route != "fix":
            continue
        results.append(fix_finding(triage_result.finding, ollama, repo))

    print(json.dumps([dataclasses.asdict(r) for r in results], indent=2, default=str))


def run_and_gate(args):
    report = run_pipeline(args.target_repo, args.config, args.dry_run, args.report_dir,
                          args.base_branch, args.fix_branch, args.check_only)
    if args.fail_on_findings and report is not None and report.blocking:
        # The branch itself still contains these until the developer merges
        # the fix PR (or resolves them by hand); fail so a required status
        # check on main blocks the merge until a rescan comes back clean.
        print(
            f"Merge gate: {len(report.blocking)} confirmed finding(s) still on "
            "this branch — failing the check.",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_pr(args):
    run_and_gate(args)


def cmd_run(args):
    run_and_gate(args)


def build_parser():
    parser = argparse.ArgumentParser(prog="cli.py")
    parser.add_argument("--config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Run semgrep and print findings")
    scan_parser.add_argument("--target-repo", default="sample_vuln_app")
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = sub.add_parser("triage", help="Scan and triage findings")
    triage_parser.add_argument("--target-repo", default="sample_vuln_app")
    triage_parser.set_defaults(func=cmd_triage)

    fix_parser = sub.add_parser("fix", help="Scan, triage, and fix (no PR)")
    fix_parser.add_argument("--target-repo", default="sample_vuln_app")
    fix_parser.set_defaults(func=cmd_fix)

    pr_parser = sub.add_parser("pr", help="Full pipeline through PR creation")
    pr_parser.add_argument("--target-repo", default="sample_vuln_app")
    pr_parser.add_argument("--dry-run", action="store_true", default=False)
    pr_parser.add_argument("--report-dir", default="reports",
                           help="where to write sast-autofix-report.md/.json")
    pr_parser.add_argument("--base-branch", default=None,
                           help="developer branch to scan, e.g. SV (default: current branch)")
    pr_parser.add_argument("--fix-branch", default=None,
                           help="branch to push fixes to (default: <base-branch>-fix)")
    pr_parser.add_argument("--check-only", action="store_true", default=False,
                           help="scan, triage, report and gate only; never generate fixes "
                                "(used for *-fix branches)")
    pr_parser.add_argument("--fail-on-findings", action="store_true", default=False,
                           help="exit 1 if confirmed findings remain on the scanned branch "
                                "(use as a required status check before merging to main)")
    pr_parser.set_defaults(func=cmd_pr)

    run_parser = sub.add_parser("run", help="Full pipeline: scan -> triage -> fix -> validate -> pr")
    run_parser.add_argument("--target-repo", default="sample_vuln_app")
    run_parser.add_argument("--dry-run", action="store_true", default=False)
    run_parser.add_argument("--report-dir", default="reports",
                           help="where to write sast-autofix-report.md/.json")
    run_parser.add_argument("--base-branch", default=None,
                           help="developer branch to scan, e.g. SV (default: current branch)")
    run_parser.add_argument("--fix-branch", default=None,
                           help="branch to push fixes to (default: <base-branch>-fix)")
    run_parser.add_argument("--check-only", action="store_true", default=False,
                           help="scan, triage, report and gate only; never generate fixes "
                                "(used for *-fix branches)")
    run_parser.add_argument("--fail-on-findings", action="store_true", default=False,
                           help="exit 1 if confirmed findings remain on the scanned branch "
                                "(use as a required status check before merging to main)")
    run_parser.set_defaults(func=cmd_run)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
