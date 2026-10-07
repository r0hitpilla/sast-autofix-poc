"""Load a pipeline run report (sast-autofix-report.json) into the database.

    python -m dashboard.ingest path/to/sast-autofix-report.json

Idempotent: re-ingesting a run replaces it, so CI can safely retry.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from sqlalchemy import delete, select

from .db import FindingRow, LlmCall, Run, make_sessionmaker
from .integrations import enqueue_for_run
from .tracking import refresh

SUPPORTED_SCHEMA_VERSIONS = {2}


class ReportError(ValueError):
    """The report can't be ingested (unsupported version or missing fields)."""


def _ts(value) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def run_from_report(report: dict) -> Run:
    version = report.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ReportError(
            f"unsupported report schema_version {version!r} "
            f"(this dashboard reads {sorted(SUPPORTED_SCHEMA_VERSIONS)}); "
            "upgrade the dashboard or re-run the pipeline"
        )
    meta = report.get("run") or {}
    if not meta.get("id"):
        raise ReportError("report has no run.id")
    summary = report.get("summary", {})
    pr = report.get("pull_request") or {}
    status = report.get("fix_branch_status") or {}
    gate = report.get("gate") or {}

    run = Run(
        id=str(meta["id"]),
        repository=meta.get("repository") or report.get("target", "unknown"),
        base_branch=meta.get("base_branch") or "unknown",
        fix_branch=meta.get("fix_branch"),
        commit=meta.get("commit"),
        trigger=meta.get("trigger"),
        mode=meta.get("mode") or "fix",
        dry_run=bool(meta.get("dry_run")),
        url=meta.get("url"),
        started_at=_ts(meta.get("started_at")),
        finished_at=_ts(meta.get("finished_at")),
        scanned=summary.get("scanned", 0),
        confirmed=summary.get("confirmed", 0),
        fixed=summary.get("fixed", 0),
        review=summary.get("review", 0),
        rejected=summary.get("rejected", 0),
        residual=summary.get("residual", 0),
        blocking=gate.get("blocking", summary.get("blocking", 0)),
        gate_passed=gate.get("passed"),
        pr_number=pr.get("number"),
        pr_url=pr.get("url"),
        fix_branch_state=status.get("state"),
        fix_branch_description=status.get("description"),
        timings=report.get("timings") or {},
        provenance=report.get("provenance") or {},
        report=report,
        schema_version=version,
        ingested_at=datetime.now(timezone.utc),
    )
    for position, rec in enumerate(report.get("findings", [])):
        f, triage, fix = rec["finding"], rec.get("triage", {}), rec.get("fix")
        run.findings.append(FindingRow(
            position=position,
            fingerprint=rec["fingerprint"],
            rule_id=f["rule_id"], cwe=f["cwe"], severity=f.get("severity") or "Medium",
            owasp=f.get("owasp") or [], file=f["file"], line=f["line"],
            end_line=f.get("end_line"), cvss=f.get("cvss"), risk=rec.get("risk"),
            message=f.get("message", ""), snippet=f.get("snippet", ""),
            laya_score=triage.get("laya_score", 0.0), route=triage.get("route", "review"),
            llm_label=triage.get("llm_label"), rounds=triage.get("rounds", 0),
            evidence=triage.get("evidence") or [], context=triage.get("context"),
            outcome=rec.get("outcome", ""),
            fix_validated=bool(fix and fix.get("validated")),
            fix_attempts=fix.get("attempts") if fix else None,
            fix=fix,
        ))
    return run


def llm_calls_from_report(report: dict, run_id: str) -> list[LlmCall]:
    """The run's AI calls from `llm_usage.calls` (absent in reports written
    before usage tracking: then there are none)."""
    rows = []
    for c in ((report.get("llm_usage") or {}).get("calls") or []):
        try:
            rows.append(LlmCall(
                run_id=run_id, at=_ts(c.get("at")) or datetime.now(timezone.utc),
                purpose=str(c.get("purpose") or "other")[:48], model=str(c.get("model") or "?")[:160],
                provider=str(c.get("provider") or "?")[:32],
                prompt_tokens=c.get("prompt_tokens"), completion_tokens=c.get("completion_tokens"),
                duration_ms=int(c.get("duration_ms") or 0), ok=bool(c.get("ok", True)),
                truncated=bool(c.get("truncated", False)), ref=c.get("ref"),
                error=(str(c["error"])[:500] if c.get("error") else None),
            ))
        except (TypeError, ValueError):
            continue  # one malformed entry must not lose the run
    return rows


def ingest(report: dict, sessionmaker=None) -> Run:
    run = run_from_report(report)
    Session = sessionmaker or make_sessionmaker()
    with Session.begin() as session:
        # Identities this run touched before and now: both need refreshing,
        # since a re-ingest can drop a finding a previous ingest recorded.
        old = session.scalars(select(FindingRow.fingerprint).where(FindingRow.run_id == run.id)).all()
        session.execute(delete(FindingRow).where(FindingRow.run_id == run.id))
        session.execute(delete(LlmCall).where(LlmCall.run_id == run.id))
        session.execute(delete(Run).where(Run.id == run.id))
        session.add(run)
        session.flush()
        session.add_all(llm_calls_from_report(report, run.id))
        refresh(session, list(old) + [row.fingerprint for row in run.findings])
        # Notifications are queued here and sent by the dashboard service,
        # which holds the key to the integration secrets; CI doesn't.
        enqueue_for_run(session, run)
    return run


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dashboard.ingest")
    parser.add_argument("report", help="path to sast-autofix-report.json")
    args = parser.parse_args(argv)
    try:
        with open(args.report) as f:
            report = json.load(f)
        run = ingest(report)
    except (OSError, json.JSONDecodeError, ReportError) as exc:
        print(f"ingest failed: {exc}", file=sys.stderr)
        return 1
    print(f"ingested run {run.id} ({run.repository} @ {run.base_branch}): "
          f"{len(run.findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
