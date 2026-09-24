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
from pr import build_pr_body, commit_validated_findings, open_pr
from scanner import scan
from triage import triage_finding
from validator import validate_and_retry


def cmd_scan(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))


def cmd_triage(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)

    results = [
        triage_finding(f, ollama, laya, cfg.threshold_fix, cfg.threshold_review)
        for f in findings
    ]

    print(json.dumps([
        {
            "finding": dataclasses.asdict(r.finding),
            "llm_reasoning": r.llm_reasoning,
            "laya_score": r.laya_score,
            "route": r.route,
        }
        for r in results
    ], indent=2))


def run_pipeline(target_repo: str, config_path: str, dry_run: bool):
    cfg = load_config(config_path)
    findings = scan(target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(target_repo)

    entries = []
    for finding in findings:
        triage_result = triage_finding(
            finding, ollama, laya, cfg.threshold_fix, cfg.threshold_review
        )
        if triage_result.route != "fix":
            continue

        fix_result = fix_finding(finding, ollama, repo)
        if not fix_result.applied:
            continue

        validation_result = validate_and_retry(
            fix_result, ollama, repo, target_repo,
            cfg.semgrep_rulesets, cfg.max_fix_retries,
        )
        entries.append((triage_result, validation_result))

    validated = [(t, v) for t, v in entries if v.validated]
    if not validated:
        print("No findings validated for a fix.")
        return

    branches = commit_validated_findings(repo, entries, cfg.pr_strategy)
    body = build_pr_body(entries)
    # "single" strategy returns the same branch repeated once per validated
    # finding; "per-finding" returns N distinct branches. Dedupe (preserving
    # order) so every distinct branch gets pushed and gets its own PR —
    # branches[0] alone would silently drop findings 2..N under per-finding.
    unique_branches = list(dict.fromkeys(branches))

    if dry_run:
        print("[dry-run] Would push branch(es):", unique_branches)
        print("[dry-run] PR body:\n", body)
        return

    github_client = Github(os.environ["GITHUB_TOKEN"])
    repo_full_name = os.environ.get("GITHUB_REPO", "r0hitpilla/sast-poc-vuln-app")
    for branch in unique_branches:
        repo.git.push("--set-upstream", "origin", branch)
        url = open_pr(
            github_client, repo_full_name, branch,
            title="Automated security fixes (sast-autofix-poc)",
            body=body, dry_run=dry_run,
        )
        print(f"Opened PR: {url}")


def cmd_fix(args):
    cfg = load_config(args.config)
    findings = scan(args.target_repo, cfg.semgrep_rulesets)
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    repo = git.Repo(args.target_repo)

    results = []
    for finding in findings:
        triage_result = triage_finding(
            finding, ollama, laya, cfg.threshold_fix, cfg.threshold_review
        )
        if triage_result.route != "fix":
            continue
        results.append(fix_finding(finding, ollama, repo))

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
