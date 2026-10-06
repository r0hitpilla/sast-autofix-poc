"""End-of-run report: what was found, what Laya concluded, what got fixed.

Written as Markdown (appended to the GitHub Actions job summary when running
in CI, so every run shows up on the Actions page) and as JSON for tooling.
"""

import dataclasses
import json
import os
from dataclasses import dataclass, field

from models import Finding, TriageResult, ValidationResult


@dataclass
class FindingRecord:
    triage: TriageResult
    outcome: str
    validation: ValidationResult | None = None


@dataclass
class RunReport:
    target: str
    records: list[FindingRecord] = field(default_factory=list)
    residual: list[Finding] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    pr_urls: list[str] = field(default_factory=list)

    def count(self, predicate) -> int:
        return sum(1 for r in self.records if predicate(r))

    @property
    def confirmed(self) -> int:
        return self.count(lambda r: r.triage.route == "fix")

    @property
    def blocking(self) -> list[FindingRecord]:
        """Confirmed (or unsure) findings still present on the scanned branch.

        Fixes live on the -fix branch, not the scanned one, so a finding the
        run fixed still blocks until that fix is merged and a rescan is clean.
        Only findings Laya rejected as false positives don't block.
        """
        return [r for r in self.records if r.triage.route in ("fix", "review")]

    @property
    def fixed(self) -> int:
        return self.count(lambda r: r.validation is not None and r.validation.validated)


def _short_question(question: str) -> str:
    from triage import INVESTIGATION_QUESTIONS
    for key, (_, text) in INVESTIGATION_QUESTIONS.items():
        if text == question:
            return key
    return question[:30]


def to_markdown(report: RunReport) -> str:
    total = len(report.records)
    review = report.count(lambda r: r.triage.route == "review")
    rejected = report.count(lambda r: r.triage.route == "reject")
    fix_rate = f"{report.fixed / report.confirmed:.0%}" if report.confirmed else "n/a"

    lines = [
        f"# SAST Autofix run: `{report.target}`",
        "",
        "| Findings scanned | Confirmed true positives | Fixed & validated | Fix rate | Needs human review | Rejected as false positive | Still flagged after the fixes |",
        "|---|---|---|---|---|---|---|",
        f"| {total} | {report.confirmed} | {report.fixed} | {fix_rate} | {review} | {rejected} | {len(report.residual)} |",
        "",
    ]
    if report.pr_urls:
        lines += ["**Pull requests:** " + ", ".join(report.pr_urls), ""]
    if report.blocking:
        lines += [
            f"**Merge gate: ❌ {len(report.blocking)} confirmed or unreviewed finding(s) "
            "are still on this branch** (fixes for some may already be on the fix "
            "branch — they count until merged here). Merge the fix PR (and resolve anything it lists as not "
            "auto-fixed); the rescan of that push will clear this check.",
            "",
        ]
    elif report.records:
        lines += ["**Merge gate: ✅ no confirmed findings on this branch.**", ""]
    else:
        lines += ["**Merge gate: ✅ no findings.**", ""]

    lines += [
        "## Findings",
        "",
        "| Location | CWE | Laya score | Laya asked the LLM about | Verdict | Outcome | Fix attempts |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in report.records:
        f = r.triage.finding
        asked = ", ".join(_short_question(q) for q, _ in r.triage.evidence[1:]) or "—"
        attempts = r.validation.attempts if r.validation else "—"
        lines.append(
            f"| `{f.file}:{f.line}` | {f.cwe} | {r.triage.laya_score:.2f} | {asked} "
            f"| {r.triage.route} | {r.outcome} | {attempts} |"
        )

    if report.residual:
        lines += ["", "## Still flagged after this run", ""]
        lines += [f"- `{f.file}:{f.line}` {f.cwe} (`{f.rule_id}`)" for f in report.residual]

    if report.timings:
        lines += ["", "## Stage timings", ""]
        lines += [f"- {stage}: {secs:.1f}s" for stage, secs in report.timings.items()]

    return "\n".join(lines) + "\n"


def to_json(report: RunReport) -> str:
    return json.dumps({
        "target": report.target,
        "summary": {
            "scanned": len(report.records),
            "confirmed": report.confirmed,
            "fixed": report.fixed,
            "residual": len(report.residual),
        },
        "findings": [
            {
                "finding": dataclasses.asdict(r.triage.finding),
                "laya_score": r.triage.laya_score,
                "route": r.triage.route,
                "evidence": [{"question": q, "answer": a} for q, a in r.triage.evidence],
                "outcome": r.outcome,
                "attempts": r.validation.attempts if r.validation else None,
            }
            for r in report.records
        ],
        "residual": [dataclasses.asdict(f) for f in report.residual],
        "timings": report.timings,
        "pr_urls": report.pr_urls,
    }, indent=2)


def write_report(report: RunReport, report_dir: str) -> str:
    os.makedirs(report_dir, exist_ok=True)
    markdown = to_markdown(report)
    md_path = os.path.join(report_dir, "sast-autofix-report.md")
    with open(md_path, "w") as f:
        f.write(markdown)
    with open(os.path.join(report_dir, "sast-autofix-report.json"), "w") as f:
        f.write(to_json(report))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(markdown)
    return md_path
