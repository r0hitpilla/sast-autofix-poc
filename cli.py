import argparse
import dataclasses
import json
import os
import sys

import git
from github import Github

from config import load_config
from fixer import fix_finding
from laya_client import LayaClient
from ollama_client import OllamaClient
from code_context import numbered_context
from diff_utils import branch_hunks
from pr import build_line_comments, build_pr_body, commit_validated_findings, open_pr
from scanner import scan
from triage import triage_finding
from validator import count_same_rule_and_file, validate_and_retry


def cmd_scan(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))


def cmd_triage(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
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
    return [
        triage_finding(
            f, ollama, laya, cfg.threshold_fix, cfg.threshold_review,
            max_rounds=cfg.triage_max_rounds,
            context=numbered_context(target_repo, f),
        )
        for f in findings
    ]


def run_pipeline(target_repo: str, config_path: str, dry_run: bool):
    cfg = load_config(config_path)
    findings = scan(target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(target_repo)
    repo_full_name = os.environ.get("GITHUB_REPO", "r0hitpilla/sast-poc-vuln-app")

    # Every finding ends up in exactly one of these buckets — a human reading
    # the run output must be able to account for all of them, not just the
    # ones that made it into the PR.
    outcomes = {
        "fixed and validated": 0,
        "sent to review": 0,
        "rejected (likely false positive)": 0,
        "skipped (file not found in target repo)": 0,
        "fix generation failed": 0,
        "fix did not apply": 0,
        "fix applied but failed validation": 0,
    }

    # How many instances of each (rule_id, file) the target repo is still
    # expected to hold. Seeded from the original scan and decremented as
    # fixes validate, so each finding's validation compares the rescan
    # against the count that was really there just before ITS fix — not a
    # stale whole-run baseline that would auto-pass later same-rule findings.
    remaining = {
        (f.rule_id, f.file): count_same_rule_and_file(f, findings)
        for f in findings
    }

    entries = []
    for triage_result in triage_all(findings, target_repo, cfg, ollama, laya):
        finding = triage_result.finding
        if triage_result.route == "review":
            outcomes["sent to review"] += 1
            continue
        if triage_result.route != "fix":
            outcomes["rejected (likely false positive)"] += 1
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
            outcomes["skipped (file not found in target repo)"] += 1
            continue

        fix_result = fix_finding(finding, ollama, repo)
        if not fix_result.diff:
            outcomes["fix generation failed"] += 1
            continue
        if not fix_result.applied:
            outcomes["fix did not apply"] += 1
            continue

        rule_file_key = (finding.rule_id, finding.file)
        validation_result = validate_and_retry(
            fix_result, ollama, repo, target_repo,
            cfg.semgrep_rulesets, cfg.max_fix_retries,
            baseline_count=remaining[rule_file_key],
        )
        entries.append((triage_result, validation_result))
        if validation_result.validated:
            remaining[rule_file_key] -= 1
            outcomes["fixed and validated"] += 1
        else:
            outcomes["fix applied but failed validation"] += 1

    print(f"\nScanned: {len(findings)} findings.")
    for label, count in outcomes.items():
        if count:
            print(f"  {label.capitalize()}: {count}")

    # Final whole-repo rescan with every validated fix in place: what's left
    # is exactly what this run did NOT fix.
    residual = scan(target_repo, cfg.semgrep_rulesets)
    print(f"Final rescan: {len(residual)} finding(s) remain.")
    for f in residual:
        print(f"  - {f.file}:{f.line} {f.cwe} ({f.rule_id})")

    validated = [(t, v) for t, v in entries if v.validated]
    if not validated:
        print("No findings validated for a fix.")
        return

    branches = commit_validated_findings(repo, entries, cfg.pr_strategy)
    # "single" strategy returns the same branch repeated once per validated
    # finding; "per-finding" returns N distinct branches. Dedupe (preserving
    # order) so every distinct branch gets pushed and gets its own PR —
    # branches[0] alone would silently drop findings 2..N under per-finding.
    unique_branches = list(dict.fromkeys(branches))

    # Built per branch from the branch's real diff against main, so the line
    # numbers in the body and the inline comments are the ones GitHub shows.
    prs = []
    for branch in unique_branches:
        hunks = branch_hunks(repo, "main", branch)
        body = build_pr_body(entries, hunks, repo_full_name, branch)
        prs.append((branch, body, build_line_comments(entries, hunks)))

    if dry_run:
        for branch, body, comments in prs:
            print(f"[dry-run] Would push branch: {branch}")
            print("[dry-run] PR body:\n", body)
            print(f"[dry-run] Inline line comments ({len(comments)}):")
            for c in comments:
                lines = f"L{c['start_line']}-L{c['line']}" if "start_line" in c else f"L{c['line']}"
                print(f"  {c['path']} {lines} ({c['side']}): {c['body'].splitlines()[0]}")
        return

    github_client = Github(os.environ["GITHUB_TOKEN"])
    for branch, body, comments in prs:
        repo.git.push("--set-upstream", "origin", branch)
        url = open_pr(
            github_client, repo_full_name, branch,
            title="Automated security fixes (sast-autofix-poc)",
            body=body, dry_run=dry_run, line_comments=comments,
        )
        print(f"Opened PR: {url}")


def cmd_fix(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(args.target_repo)

    results = []
    for triage_result in triage_all(findings, args.target_repo, cfg, ollama, laya):
        if triage_result.route != "fix":
            continue
        results.append(fix_finding(triage_result.finding, ollama, repo))

    print(json.dumps([dataclasses.asdict(r) for r in results], indent=2, default=str))


def cmd_pr(args):
    run_pipeline(args.target_repo, args.config, args.dry_run)


def cmd_run(args):
    run_pipeline(args.target_repo, args.config, args.dry_run)


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
    pr_parser.set_defaults(func=cmd_pr)

    run_parser = sub.add_parser("run", help="Full pipeline: scan -> triage -> fix -> validate -> pr")
    run_parser.add_argument("--target-repo", default="sample_vuln_app")
    run_parser.add_argument("--dry-run", action="store_true", default=False)
    run_parser.set_defaults(func=cmd_run)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
