import argparse
import dataclasses
import json
import sys

from config import load_config
from laya_client import LayaClient
from ollama_client import OllamaClient
from scanner import scan
from triage import triage_finding


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

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])
