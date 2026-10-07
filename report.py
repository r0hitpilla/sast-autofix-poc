"""End-of-run report: what was found, what Laya concluded, what got fixed.

Written as Markdown (appended to the GitHub Actions job summary when running
in CI, so every run shows up on the Actions page) and as JSON for tooling.
"""

import dataclasses
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from models import Finding, TriageResult, ValidationResult
from identity import distinct_locations, finding_fingerprint
from policy import STRICT, Policy
from risk import risk_score


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
    # Run identity, provenance and outcome details, filled in by the
    # pipeline (cli.run_pipeline) — see SCHEMA_VERSION / to_json.
    meta: dict = field(default_factory=dict)
    # The security policy in force and people's decisions (fingerprint ->
    # decision). STRICT and no decisions: every confirmed finding blocks.
    policy: Policy = STRICT
    decisions: dict = field(default_factory=dict)

    @property
    def repository(self) -> str:
        return (self.meta.get("run") or {}).get("repository", "")

    def blocks(self, finding: Finding) -> bool:
        decision = self.decisions.get(fingerprint(finding, self.repository))
        return self.policy.blocks(finding.severity, decision)

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
        Findings Laya rejected as false positives don't block, nor do those
        the security policy allows (or that a person decided, where the
        policy lets a decision clear them).
        """
        return [r for r in self.records
                if r.triage.route in ("fix", "review") and self.blocks(r.triage.finding)]

    @property
    def fixed(self) -> int:
        return self.count(lambda r: r.validation is not None and r.validation.validated)


def _short_question(question: str) -> str:
    from triage import INVESTIGATION_QUESTIONS
    for key, (_, text) in INVESTIGATION_QUESTIONS.items():
        if text == question:
            return key
    return question[:30]


def _distinct(records) -> int:
    return distinct_locations((r.triage.finding.file, r.triage.finding.snippet) for r in records)


def to_markdown(report: RunReport) -> str:
    total = len(report.records)
    review = report.count(lambda r: r.triage.route == "review")
    rejected = report.count(lambda r: r.triage.route == "reject")
    confirmed_records = [r for r in report.records if r.triage.route == "fix"]
    fix_rate = f"{report.fixed / report.confirmed:.0%}" if report.confirmed else "n/a"
    # Rule hits are what the scanners reported; distinct findings are the
    # places in the code, which is what gets fixed and what a reader counts.
    scanned_cell = f"{total} rule hit(s), {_distinct(report.records)} distinct"
    confirmed_cell = f"{report.confirmed} rule hit(s), {_distinct(confirmed_records)} distinct"

    lines = [
        f"# SAST Autofix run: `{report.target}`",
        "",
        "| Findings scanned | Confirmed true positives | Fixed & validated | Fix rate | Needs human review | Rejected as false positive | Still flagged after the fixes |",
        "|---|---|---|---|---|---|---|",
        f"| {scanned_cell} | {confirmed_cell} | {report.fixed} | {fix_rate} | {review} | {rejected} | {len(report.residual)} |",
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


# Version of the JSON report contract read by the dashboard (dashboard/ingest.py).
# Bump it on any change a reader must know about.
SCHEMA_VERSION = 2


def fingerprint(finding: Finding, repository: str = "") -> str:
    """Stable identity of a finding across runs, branches and repositories.
    See identity.py for what it covers and what it deliberately leaves out."""
    return finding_fingerprint(repository, finding.rule_id, finding.file, finding.snippet)


def _record_json(r: FindingRecord, repository: str = "") -> dict:
    from triage import llm_label, question_label

    v = r.validation
    return {
        "fingerprint": fingerprint(r.triage.finding, repository),
        "finding": dataclasses.asdict(r.triage.finding),
        "risk": risk_score(r.triage.finding),
        "triage": {
            "laya_score": r.triage.laya_score,
            "route": r.triage.route,
            "llm_label": llm_label(r.triage.evidence[0][1]) if r.triage.evidence else None,
            "rounds": max(len(r.triage.evidence) - 1, 0),
            "context": r.triage.context or None,
            "evidence": [
                {"key": question_label(q), "question": q, "answer": a}
                for q, a in r.triage.evidence
            ],
        },
        "outcome": r.outcome,
        "fix": None if v is None else {
            "validated": v.validated,
            "scanner_clean": v.clean,
            "attempts": v.attempts,
            "failure": v.failure or None,
            "note": v.note or None,
            "diff": v.fix_diff or None,
            "created_files": v.created_files,
            "check_output": v.test_output[-2000:] if v.test_output else None,
            "last_proposal": None if v.validated else (v.last_proposal or None),
        },
    }


def to_json(report: RunReport) -> str:
    repository = (report.meta.get("run") or {}).get("repository", "")
    return json.dumps({
        "schema_version": SCHEMA_VERSION,
        "target": report.target,
        **report.meta,
        "summary": {
            "scanned": len(report.records),
            "scanned_distinct": _distinct(report.records),
            "confirmed": report.confirmed,
            "confirmed_distinct": _distinct(r for r in report.records if r.triage.route == "fix"),
            "fixed": report.fixed,
            "review": report.count(lambda r: r.triage.route == "review"),
            "rejected": report.count(lambda r: r.triage.route == "reject"),
            "blocking": len(report.blocking),
            "residual": len(report.residual),
        },
        "findings": [_record_json(r, repository) for r in report.records],
        "residual": [dataclasses.asdict(f) for f in report.residual],
        "timings": report.timings,
        "pr_urls": report.pr_urls,
        # default=str: a report must never fail to write at the very end of
        # a run over one odd value (a datetime, a library object).
    }, indent=2, default=str)


def write_report(report: RunReport, report_dir: str) -> str:
    if "run" in report.meta:
        report.meta["run"]["finished_at"] = datetime.now(timezone.utc).isoformat()
    report.meta["gate"] = {"passed": not report.blocking, "blocking": len(report.blocking)}
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
