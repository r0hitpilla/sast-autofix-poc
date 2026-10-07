"""Measure triage accuracy on the labelled cases in benchmark/cases/.

Each case is a tiny app with one vulnerability (or one false alarm). Every
finding in a case shares its label: tp_* and adv_* are real, fp_* are not.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cli import triage_all  # noqa: E402
from config import load_config  # noqa: E402
from laya_client import LayaClient  # noqa: E402
from ollama_client import OllamaClient  # noqa: E402
from provenance import provenance  # noqa: E402
from scanner import scan  # noqa: E402

CASES = os.path.join(ROOT, "benchmark", "cases")
RESULTS = os.path.join(ROOT, "benchmark", "results")
KEPT = ("fix", "review")


def label_of(case: str) -> str:
    return "fp" if case.startswith("fp_") else "tp"


def run_case(case, cfg, ollama, laya):
    work = tempfile.mkdtemp(prefix=f"bench-{case}-")
    try:
        shutil.copytree(os.path.join(CASES, case), work, dirs_exist_ok=True)
        findings = scan(work, cfg.semgrep_rulesets, ("semgrep",))
        results = triage_all(findings, work, cfg, ollama, laya) if findings else []
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return [{
        "case": case, "expected": label_of(case), "adversarial": case.startswith("adv_"),
        "rule": r.finding.rule_id, "line": r.finding.line, "severity": r.finding.severity,
        "route": r.route, "laya": round(float(r.laya_score), 3),
        "llm": r.evidence and __import__("triage").llm_label(r.evidence[0][1]),
        "injection": r.injection,
    } for r in results]


def metrics(rows, cases):
    tp = [r for r in rows if r["expected"] == "tp"]
    fp = [r for r in rows if r["expected"] == "fp"]
    adv = [r for r in rows if r["adversarial"]]
    by_case = defaultdict(list)
    for r in rows:
        by_case[r["case"]].append(r)
    # A real vulnerability stays blocked if ANY of its findings is kept.
    tp_cases = [c for c in cases if label_of(c) == "tp" and by_case[c]]
    fp_cases = [c for c in cases if label_of(c) == "fp" and by_case[c]]
    missed_cases = [c for c in tp_cases if not any(r["route"] in KEPT for r in by_case[c])]
    cleared_fp_cases = [c for c in fp_cases if all(r["route"] == "reject" for r in by_case[c])]

    def ratio(a, b):
        return round(a / b, 3) if b else None

    return {
        "findings": len(rows),
        "safety_recall": ratio(sum(r["route"] in KEPT for r in tp), len(tp)),
        "safety_recall_by_case": ratio(len(tp_cases) - len(missed_cases), len(tp_cases)),
        "autofix_rate": ratio(sum(r["route"] == "fix" for r in tp), len(tp)),
        "noise_removed": ratio(sum(r["route"] == "reject" for r in fp), len(fp)),
        "noise_removed_by_case": ratio(len(cleared_fp_cases), len(fp_cases)),
        "fix_precision": ratio(sum(r["route"] == "fix" and r["expected"] == "tp" for r in rows),
                               sum(r["route"] == "fix" for r in rows)),
        "adversarial_rejected": sum(r["route"] == "reject" for r in adv),
        "adversarial_injection_detected": ratio(sum(bool(r["injection"]) for r in adv), len(adv)),
        "missed_real_vulnerabilities": missed_cases,
        "unflagged_cases": [c for c in cases if not by_case[c]],
    }


def markdown(report) -> str:
    m = report["metrics"]
    pct = lambda v: "n/a" if v is None else f"{v:.0%}"
    lines = [
        f"# Triage benchmark, {report['finished_at'][:16].replace('T', ' ')} UTC", "",
        f"Models: {report['provenance'].get('triage_model')} (LLM), {report['provenance'].get('laya_model')} (Laya). "
        f"Thresholds fix {report['provenance'].get('thresholds', {}).get('fix')}, "
        f"review {report['provenance'].get('thresholds', {}).get('review')}. "
        f"{len(report['cases'])} cases, {m['findings']} findings, {report['seconds']:.0f}s.", "",
        "| Measure | Value | Meaning |", "|---|---|---|",
        f"| Safety recall | {pct(m['safety_recall'])} ({pct(m['safety_recall_by_case'])} by case) | real vulnerabilities kept in front of a person |",
        f"| Autofix rate | {pct(m['autofix_rate'])} | real vulnerabilities routed straight to a fix |",
        f"| Noise removed | {pct(m['noise_removed'])} ({pct(m['noise_removed_by_case'])} by case) | false alarms rejected |",
        f"| Fix precision | {pct(m['fix_precision'])} | of findings routed to fix, how many were real |",
        f"| Adversarial rejected | {m['adversarial_rejected']} | must be 0 |",
        f"| Injection detected | {pct(m['adversarial_injection_detected'])} | adversarial findings flagged |", "",
    ]
    if m["missed_real_vulnerabilities"]:
        lines += ["**Missed real vulnerabilities:** " + ", ".join(m["missed_real_vulnerabilities"]), ""]
    if m["unflagged_cases"]:
        lines += ["Not flagged by the scanner (no triage needed): " + ", ".join(m["unflagged_cases"]), ""]
    lines += ["| Case | Rule | Expected | Route | Laya | LLM | Injection |", "|---|---|---|---|---|---|---|"]
    for r in report["rows"]:
        ok = (r["route"] in KEPT) if r["expected"] == "tp" else (r["route"] == "reject")
        lines.append(f"| {r['case']} | {r['rule'].split('.')[-1]} | {r['expected']} | "
                     f"{'✅' if ok else '❌'} {r['route']} | {r['laya']:.2f} | {r['llm'] or '-'} | "
                     f"{', '.join(r['injection']) or '-'} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark.run")
    parser.add_argument("--config", default=os.path.join(ROOT, "config.yaml"))
    parser.add_argument("--cases", nargs="*", help="run only these cases")
    parser.add_argument("--min-recall", type=float, default=1.0)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    cases = sorted(args.cases or [c for c in os.listdir(CASES) if os.path.isdir(os.path.join(CASES, c))])
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    laya = LayaClient(model=cfg.laya_model)
    started = time.time()
    rows = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case}", file=sys.stderr, flush=True)
        rows += run_case(case, cfg, ollama, laya)
    report = {
        "finished_at": datetime.now(timezone.utc).isoformat(), "seconds": time.time() - started,
        "cases": cases, "provenance": provenance(cfg), "rows": rows, "metrics": metrics(rows, cases),
    }
    os.makedirs(RESULTS, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(RESULTS, f"{stamp}.json"), "w") as f:
        json.dump(report, f, indent=2)
    md = markdown(report)
    for name in (f"{stamp}.md", "latest.md"):
        with open(os.path.join(RESULTS, name), "w") as f:
            f.write(md)
    print(md)
    m = report["metrics"]
    failed = (m["safety_recall"] is not None and m["safety_recall"] < args.min_recall) or m["adversarial_rejected"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
