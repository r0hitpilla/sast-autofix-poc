"""Read models for the dashboard. Every number the UI shows is defined here.

Definitions (kept in one place so the UI, exports and tests agree):
- latest run of a branch: the most recent non-dry-run run for (repository, base_branch)
- open finding: a finding routed `fix` or `review` in the latest run of its
  branch — exactly what that branch's merge gate is blocking on
- autofix success: validated fixes / confirmed findings, over runs in the window
- run status: "Passed" (gate green) | "Fix PR open" (fixes proposed, gate still
  red) | "Blocked" (gate red, nothing auto-fixed) | "Checked" (check-only run)
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, selectinload

from identity import distinct_locations, normalise_code
from .db import FindingRow, LlmCall, Run, TrackedFinding

SEVERITIES = ["Critical", "High", "Medium", "Low"]
OPEN_ROUTES = ("fix", "review")


# ---- small helpers ---------------------------------------------------------

def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC like PostgreSQL does."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: datetime | None) -> str | None:
    dt = aware(dt)
    return dt.isoformat() if dt else None


def cwe_id(cwe: str) -> str:
    return cwe.split(":", 1)[0].strip()


def cwe_title(cwe: str) -> str:
    """"CWE-89: Improper ... ('SQL Injection')" -> "SQL Injection"."""
    m = re.search(r"\('([^']+)'\)", cwe)
    if m:
        return m.group(1)
    rest = cwe.split(":", 1)[1].strip() if ":" in cwe else cwe
    return rest[:60] or cwe


def duration_seconds(run: Run) -> float | None:
    if run.started_at and run.finished_at:
        return (aware(run.finished_at) - aware(run.started_at)).total_seconds()
    return None


def run_status(run: Run) -> str:
    if run.mode == "check-only":
        return "Checked"
    if run.gate_passed:
        return "Passed"
    return "Fix PR open" if run.fixed else "Blocked"


def fix_status(row: FindingRow) -> str:
    if row.route == "reject":
        return "False positive"
    if row.route == "review":
        return "Needs review"
    if row.fix_validated:
        return "Fixed"
    if row.outcome.startswith("resolved by"):
        return "Fixed"
    return "Not fixed"


def verdict(row: FindingRow) -> str:
    return {"fix": "True positive", "review": "Uncertain", "reject": "False positive"}.get(row.route, row.route)


# ---- runs ------------------------------------------------------------------

def run_summary(run: Run) -> dict:
    return {
        "id": run.id, "repository": run.repository, "base_branch": run.base_branch,
        "fix_branch": run.fix_branch, "commit": run.commit, "trigger": run.trigger,
        "mode": run.mode, "url": run.url,
        "started_at": iso(run.started_at), "finished_at": iso(run.finished_at),
        "duration_s": duration_seconds(run),
        "scanned": run.scanned, "confirmed": run.confirmed, "fixed": run.fixed,
        "review": run.review, "rejected": run.rejected, "residual": run.residual,
        "blocking": run.blocking, "gate_passed": run.gate_passed,
        "status": run_status(run),
        "pr_number": run.pr_number, "pr_url": run.pr_url,
        "fix_branch_state": run.fix_branch_state,
    }


def _real_runs():
    return select(Run).where(Run.dry_run.is_(False))


def _filtered(stmt, repository: str | None, since: datetime | None):
    if repository:
        stmt = stmt.where(Run.repository == repository)
    if since:
        stmt = stmt.where(Run.started_at >= since)
    return stmt


def list_runs(session: Session, repository=None, since=None, limit=50, offset=0) -> dict:
    base = _filtered(_real_runs(), repository, since)
    total = session.scalar(select(func.count()).select_from(base.subquery()))
    rows = session.scalars(base.order_by(Run.started_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [run_summary(r) for r in rows]}


def latest_runs(session: Session, repository=None, as_of: datetime | None = None) -> list[Run]:
    """Latest real run of each (repository, base_branch), optionally as of a time."""
    stmt = _real_runs()
    if repository:
        stmt = stmt.where(Run.repository == repository)
    if as_of:
        stmt = stmt.where(Run.started_at <= as_of)
    latest: dict[tuple, Run] = {}
    for run in session.scalars(stmt.order_by(Run.started_at.asc())).all():
        latest[(run.repository, run.base_branch)] = run
    return list(latest.values())


def one_per_identity(rows: list[FindingRow]) -> list[FindingRow]:
    """Keep the newest occurrence of each finding identity. The same
    vulnerability on several branches, or in several runs, is one finding."""
    newest: dict[str, FindingRow] = {}
    for row in sorted(rows, key=lambda r: aware(r.run.started_at) or now(), reverse=True):
        newest.setdefault(row.fingerprint, row)
    return list(newest.values())


def group_by_location(rows: list[FindingRow]) -> list[tuple[FindingRow, list[str]]]:
    """One entry per place in the code, however many rules flag it.

    Semgrep often reports one flaw under several rules (three XSS rules on one
    f-string; two MD5 rules on one line), and a dependency's advisories share
    one manifest line. Each entry is the newest rule hit plus the other rules
    that flag the same code, so the list shows one finding, not one per rule.
    """
    grouped: dict[tuple, tuple[FindingRow, list[str]]] = {}
    for row in one_per_identity(rows):
        key = (row.run.repository, row.file, normalise_code(row.snippet))
        if key not in grouped:
            grouped[key] = (row, [])
        else:
            rep, others = grouped[key]
            if row.rule_id != rep.rule_id and row.rule_id not in others:
                others.append(row.rule_id)
    return list(grouped.values())


def open_findings(session: Session, repository=None, as_of=None) -> list[FindingRow]:
    ids = [r.id for r in latest_runs(session, repository, as_of)]
    if not ids:
        return []
    stmt = (select(FindingRow).where(FindingRow.run_id.in_(ids), FindingRow.route.in_(OPEN_ROUTES))
            .options(selectinload(FindingRow.run)))
    return [row for row, _ in group_by_location(list(session.scalars(stmt).all()))]


def tracked_for(session: Session, rows: list[FindingRow]) -> dict[str, TrackedFinding]:
    fingerprints = {r.fingerprint for r in rows}
    if not fingerprints:
        return {}
    found = session.scalars(select(TrackedFinding).where(TrackedFinding.fingerprint.in_(fingerprints))).all()
    return {t.fingerprint: t for t in found}


STAGES = [  # (timing key written by the pipeline, display name)
    ("scan", "Scan"),
    ("triage (Laya + LLM)", "Triage"),
    ("fix + rescan loop", "Fix & validate"),
    ("final rescan", "Final rescan"),
]


def stage_text(run: Run, key: str) -> str:
    if key == "scan":
        return f"Semgrep scanned the repository and reported {run.scanned} finding(s)."
    if key.startswith("triage"):
        return (f"The LLM investigated each finding and Laya decided: {run.confirmed} confirmed, "
                f"{run.review} sent to review, {run.rejected} rejected as false positives.")
    if key.startswith("fix"):
        return (f"{run.fixed} fix(es) passed every check: Semgrep rescan, no new findings, "
                "broken-code check, the project's tests and an AI security review.")
    return (f"{run.residual} finding(s) still flagged on the fix branch. "
            + ("Merge gate passed." if run.gate_passed else f"Merge gate blocked on {run.blocking}."))


def _usage_cols():
    return (
        func.count(LlmCall.id).label("calls"),
        func.coalesce(func.sum(LlmCall.prompt_tokens), 0).label("prompt"),
        func.coalesce(func.sum(LlmCall.completion_tokens), 0).label("completion"),
        func.coalesce(func.sum(LlmCall.duration_ms), 0).label("ms"),
        func.coalesce(func.sum(case((LlmCall.ok.is_(False), 1), else_=0)), 0).label("errors"),
    )


def _usage_row(r, **extra) -> dict:
    prompt, completion = int(r.prompt), int(r.completion)
    return {**extra, "calls": int(r.calls), "prompt_tokens": prompt, "completion_tokens": completion,
            "total_tokens": prompt + completion, "duration_ms": int(r.ms), "errors": int(r.errors),
            "avg_ms": int(r.ms / r.calls) if r.calls else 0}


def usage_overview(session: Session, repository=None, since=None, top_runs=5) -> dict:
    """Every AI call of the real (non-dry) runs in the window: totals, then by
    model, by purpose, by day, and the runs that used the most tokens."""
    def scoped(stmt):
        stmt = stmt.join(Run, LlmCall.run_id == Run.id).where(Run.dry_run.is_(False))
        return _filtered(stmt, repository, since)

    cols = _usage_cols()
    totals = session.execute(scoped(select(*cols))).one()
    runs = session.scalar(scoped(select(func.count(func.distinct(LlmCall.run_id))))) or 0
    by_model = session.execute(scoped(select(LlmCall.model, LlmCall.provider, *cols))
                               .group_by(LlmCall.model, LlmCall.provider)).all()
    by_purpose = session.execute(scoped(select(LlmCall.purpose, *cols)).group_by(LlmCall.purpose)).all()
    day = func.date(LlmCall.at)
    by_day = session.execute(scoped(select(day.label("day"), *cols)).group_by(day).order_by(day)).all()
    heavy = session.execute(
        scoped(select(Run.id, Run.repository, Run.base_branch, Run.started_at, *cols))
        .group_by(Run.id, Run.repository, Run.base_branch, Run.started_at)
        .order_by((func.coalesce(func.sum(LlmCall.prompt_tokens), 0)
                   + func.coalesce(func.sum(LlmCall.completion_tokens), 0)).desc())
        .limit(top_runs)).all()
    by_total = lambda items: sorted(items, key=lambda i: -i["total_tokens"])  # noqa: E731
    return {
        "runs": runs,
        "totals": _usage_row(totals),
        "by_model": by_total([_usage_row(r, model=r.model, provider=r.provider) for r in by_model]),
        "by_purpose": by_total([_usage_row(r, purpose=r.purpose) for r in by_purpose]),
        "by_day": [_usage_row(r, day=str(r.day)) for r in by_day],
        "top_runs": [_usage_row(r, run_id=r.id, repository=r.repository, branch=r.base_branch,
                                started_at=iso(r.started_at)) for r in heavy],
    }


def run_usage(session: Session, run_id: str) -> dict:
    """The AI calls of one run (empty for runs recorded before usage tracking)."""
    cols = _usage_cols()
    totals = session.execute(select(*cols).where(LlmCall.run_id == run_id)).one()
    by_purpose = session.execute(select(LlmCall.purpose, *cols).where(LlmCall.run_id == run_id)
                                 .group_by(LlmCall.purpose)).all()
    by_model = session.execute(select(LlmCall.model, LlmCall.provider, *cols).where(LlmCall.run_id == run_id)
                               .group_by(LlmCall.model, LlmCall.provider)).all()
    slowest = session.scalars(select(LlmCall).where(LlmCall.run_id == run_id)
                              .order_by(LlmCall.duration_ms.desc()).limit(5)).all()
    return {
        "totals": _usage_row(totals),
        "by_purpose": sorted([_usage_row(r, purpose=r.purpose) for r in by_purpose], key=lambda i: -i["total_tokens"]),
        "by_model": sorted([_usage_row(r, model=r.model, provider=r.provider) for r in by_model],
                           key=lambda i: -i["total_tokens"]),
        "slowest": [{"purpose": c.purpose, "model": c.model, "ref": c.ref, "duration_ms": c.duration_ms,
                     "prompt_tokens": c.prompt_tokens, "completion_tokens": c.completion_tokens, "ok": c.ok}
                    for c in slowest],
    }


def run_detail(session: Session, run_id: str) -> dict | None:
    run = session.get(Run, run_id, options=[selectinload(Run.findings)])
    if run is None:
        return None
    stages = [
        {"key": key, "name": name, "seconds": run.timings.get(key), "text": stage_text(run, key)}
        for key, name in STAGES if key in run.timings
    ]
    fixed = [r for r in run.findings if r.fix_validated]
    return {
        **run_summary(run),
        "stages": stages,
        "provenance": run.provenance,
        "fix_branch_description": run.fix_branch_description,
        "usage": run_usage(session, run.id),
        "patches": [
            {"finding_id": r.id, "title": cwe_title(r.cwe), "cwe": cwe_id(r.cwe), "file": r.file,
             "line": r.line, "diff": (r.fix or {}).get("diff"), "attempts": r.fix_attempts,
             "created_files": (r.fix or {}).get("created_files", []),
             "note": (r.fix or {}).get("note")}
            for r in fixed
        ],
        "findings": [finding_summary(r, run) for r in run.findings],
    }


# ---- findings --------------------------------------------------------------

ADVISORY_BASE = "https://osv.dev/vulnerability/"


def advisory_url(rule_id: str) -> str | None:
    """Public advisory page for a dependency finding (osv.<id>); none otherwise."""
    if not rule_id.startswith("osv."):
        return None
    advisory = rule_id[len("osv."):]
    # OSV ids are plain tokens; anything else is not a link we should build.
    return ADVISORY_BASE + advisory if re.fullmatch(r"[A-Za-z0-9._-]+", advisory) else None


def finding_summary(row: FindingRow, run: Run | None = None, tracked: TrackedFinding | None = None) -> dict:
    run = run or row.run
    history = {} if tracked is None else {
        "occurrences": tracked.occurrences,
        "first_seen": iso(tracked.first_seen),
        "last_seen": iso(tracked.last_seen),
        "decision": tracked.decision,
        "decision_reason": tracked.decision_reason,
        "decided_by": tracked.decided_by,
        "decided_at": iso(tracked.decided_at),
        "issue_key": tracked.issue_key,
        "issue_url": tracked.issue_url,
    }
    return {
        **history,
        "id": row.id, "run_id": row.run_id, "fingerprint": row.fingerprint,
        "severity": row.severity, "title": cwe_title(row.cwe), "cwe": cwe_id(row.cwe),
        "rule_id": row.rule_id, "repository": run.repository, "branch": run.base_branch,
        "file": row.file, "line": row.line, "verdict": verdict(row), "route": row.route,
        "cvss": row.cvss, "risk": row.risk, "advisory_url": advisory_url(row.rule_id),
        "confidence": row.laya_score, "fix_status": fix_status(row), "outcome": row.outcome,
        "detected_at": iso(run.started_at),
    }


def list_findings(session: Session, state="open", repository=None, severity=None,
                  route=None, since=None, limit=100, offset=0) -> dict:
    if state == "open":
        rows = open_findings(session, repository)
    else:
        stmt = (select(FindingRow).join(Run).where(Run.dry_run.is_(False))
                .options(selectinload(FindingRow.run)))
        stmt = _filtered(stmt, repository, since)
        rows = list(session.scalars(stmt).all())
    if severity:
        rows = [r for r in rows if r.severity == severity]
    if route:
        rows = [r for r in rows if r.route == route]
    # Riskiest first. Rows without a risk score (recorded before it existed)
    # fall back to severity order, after the scored ones.
    order = {s: i for i, s in enumerate(SEVERITIES)}
    grouped = group_by_location(rows)
    grouped.sort(key=lambda g: (
        g[0].risk is None, -(g[0].risk or 0.0), order.get(g[0].severity, 9),
        -(aware(g[0].run.started_at) or now()).timestamp(),
    ))
    tracked = tracked_for(session, [row for row, _ in grouped])
    items = []
    for row, others in grouped[offset:offset + limit]:
        item = finding_summary(row, tracked=tracked.get(row.fingerprint))
        item["also_flagged_by"] = others
        items.append(item)
    return {"total": len(grouped), "items": items}


def history_for(session: Session, repository: str) -> list[dict]:
    """What earlier runs found and tried for this repository's findings.

    The pipeline reads this before triage and fixing, so the LLM knows what
    was already concluded and what already failed instead of starting cold.
    """
    tracked = session.scalars(select(TrackedFinding).where(TrackedFinding.repository == repository)).all()
    if not tracked:
        return []
    run_ids = {t.latest_run_id for t in tracked}
    rows = session.scalars(select(FindingRow).where(FindingRow.run_id.in_(run_ids))).all()
    latest = {(r.fingerprint, r.run_id): r for r in rows}
    out = []
    for t in tracked:
        row = latest.get((t.fingerprint, t.latest_run_id))
        fix = (row.fix or {}) if row else {}
        out.append({
            "fingerprint": t.fingerprint, "rule_id": t.rule_id, "cwe": t.cwe, "file": t.file,
            "occurrences": t.occurrences, "first_seen": iso(t.first_seen), "last_seen": iso(t.last_seen),
            "llm_label": t.llm_label, "laya_score": t.laya_score, "rounds": t.rounds,
            "fix_attempts": t.fix_attempts, "fix_validated": t.fix_validated,
            "disposition": t.disposition, "pr_url": t.pr_url,
            "decision": t.decision, "decision_reason": t.decision_reason,
            "fix_failure": fix.get("failure"),
            "fix_check_output": (fix.get("check_output") or "")[-600:] or None,
            "last_proposal": (fix.get("last_proposal") or "")[:800] or None,
        })
    return out


def _parse_context(context: str | None, start: int, end: int) -> list[dict]:
    lines = []
    for raw in (context or "").splitlines():
        num, _, code = raw.partition(" | ")
        if num.strip().isdigit():
            n = int(num)
            lines.append({"n": n, "text": code, "flagged": start <= n <= end})
    return lines


def finding_detail(session: Session, finding_id: int) -> dict | None:
    row = session.get(FindingRow, finding_id, options=[selectinload(FindingRow.run)])
    if row is None:
        return None
    run = row.run
    seen = session.execute(
        select(func.min(Run.started_at), func.max(Run.started_at), func.count(Run.id))
        .join(FindingRow).where(FindingRow.fingerprint == row.fingerprint, Run.dry_run.is_(False))
    ).one()
    evidence = row.evidence or []
    return {
        **finding_summary(row, run, session.get(TrackedFinding, row.fingerprint)),
        "message": row.message, "owasp": row.owasp, "end_line": row.end_line,
        "snippet": row.snippet,
        "code": _parse_context(row.context, row.line, row.end_line or row.line),
        "commit": run.commit, "run_url": run.url, "pr_number": run.pr_number, "pr_url": run.pr_url,
        "first_detected": iso(seen[0]), "last_detected": iso(seen[1]), "times_detected": seen[2],
        "investigation": {
            "llm_label": row.llm_label, "laya_score": row.laya_score, "rounds": row.rounds,
            "max_rounds": run.provenance.get("triage_max_rounds"),
            "initial": evidence[0]["answer"] if evidence else None,
            "questions": [
                {"key": e.get("key"), "question": e["question"], "answer": e["answer"]}
                for e in evidence[1:]
            ],
        },
        "fix": row.fix,
        "provenance": run.provenance,
    }


# ---- pull requests ---------------------------------------------------------

def list_prs(session: Session, repository=None) -> list[dict]:
    stmt = _real_runs().where(Run.pr_number.is_not(None))
    if repository:
        stmt = stmt.where(Run.repository == repository)
    by_pr: dict[tuple, Run] = {}
    for run in session.scalars(stmt.order_by(Run.started_at.asc())).all():
        by_pr[(run.repository, run.pr_number)] = run  # latest run that touched the PR
    gate = {(r.repository, r.base_branch): r for r in latest_runs(session, repository)}
    out = []
    for (repo, number), run in sorted(by_pr.items(), key=lambda kv: -kv[0][1]):
        base_gate = gate.get((repo, run.base_branch))
        out.append({
            "number": number, "url": run.pr_url, "repository": repo,
            "head": run.fix_branch, "base": run.base_branch, "run_id": run.id,
            "findings": run.scanned, "fixes": run.fixed,
            "validation": run.fix_branch_state,  # status posted on the fix branch
            "gate_passed": base_gate.gate_passed if base_gate else None,
            "updated_at": iso(run.finished_at or run.started_at),
        })
    return out


def pr_detail(session: Session, repository: str, number: int) -> dict | None:
    run = session.scalars(
        _real_runs().where(Run.repository == repository, Run.pr_number == number)
        .order_by(Run.started_at.desc()).limit(1).options(selectinload(Run.findings))
    ).first()
    if run is None:
        return None
    base_gate = next((r for r in latest_runs(session, repository) if r.base_branch == run.base_branch), None)
    return {
        "number": number, "url": run.pr_url, "repository": repository,
        "head": run.fix_branch, "base": run.base_branch, "run": run_summary(run),
        "summary": {"scanned": run.scanned, "confirmed": run.confirmed, "fixed": run.fixed,
                    "review": run.review, "rejected": run.rejected,
                    "scanned_distinct": distinct_locations((f.file, f.snippet) for f in run.findings),
                    "confirmed_distinct": distinct_locations(
                        (f.file, f.snippet) for f in run.findings if f.route == "fix"),
                    # fixes an exploit test backs: it failed on the original code and passes now
                    "proven": sum(1 for f in run.findings
                                  if ((f.fix or {}).get("proof") or {}).get("status") == "proven")},
        "validation": {"state": run.fix_branch_state, "description": run.fix_branch_description},
        "gate": {"passed": base_gate.gate_passed if base_gate else None,
                 "blocking": base_gate.blocking if base_gate else None,
                 "run_id": base_gate.id if base_gate else None},
        "findings": [finding_summary(r, run) for r in run.findings],
    }


# ---- overview & reports ----------------------------------------------------

def _window(days: int) -> tuple[datetime, datetime]:
    end = now()
    return end - timedelta(days=days), end


def _runs_between(session, repository, start, end=None) -> list[Run]:
    stmt = _filtered(_real_runs(), repository, start)
    if end:
        stmt = stmt.where(Run.started_at < end)
    return list(session.scalars(stmt.options(selectinload(Run.findings))).all())


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def overview(session: Session, repository=None, days=7) -> dict:
    start, end = _window(days)
    prev_start = start - (end - start)
    runs, prev_runs = _runs_between(session, repository, start), _runs_between(session, repository, prev_start, start)
    open_now, open_prev = open_findings(session, repository), open_findings(session, repository, as_of=start)

    def sev_counts(rows):
        c = Counter(r.severity for r in rows)
        return {s: c.get(s, 0) for s in SEVERITIES}

    sev_now, sev_prev = sev_counts(open_now), sev_counts(open_prev)
    confirmed, fixed = sum(r.confirmed for r in runs), sum(r.fixed for r in runs)
    p_confirmed, p_fixed = sum(r.confirmed for r in prev_runs), sum(r.fixed for r in prev_runs)
    durations = [d for d in (duration_seconds(r) for r in runs) if d]
    latest = latest_runs(session, repository)

    activity = []
    for run in sorted(runs, key=lambda r: aware(r.started_at), reverse=True)[:10]:
        for row in run.findings:
            if row.route in OPEN_ROUTES or row.fix_validated:
                activity.append({"finding_id": row.id, "at": iso(run.finished_at or run.started_at),
                                 "title": cwe_title(row.cwe), "status": fix_status(row),
                                 "where": f"{row.file}:{row.line}", "pr_number": run.pr_number,
                                 "repository": run.repository})
    repos = defaultdict(list)
    for run in latest:
        repos[run.repository].append(run)

    return {
        "window_days": days,
        "kpis": {
            "open_findings": len(open_now), "open_findings_prev": len(open_prev),
            "critical": sev_now["Critical"], "high": sev_now["High"],
            "critical_prev": sev_prev["Critical"], "high_prev": sev_prev["High"],
            "autofix_success": _rate(fixed, confirmed), "autofix_success_prev": _rate(p_fixed, p_confirmed),
            "fixed": fixed, "fixed_prev": p_fixed,
            "avg_run_seconds": round(sum(durations) / len(durations), 1) if durations else None,
            "blocked_branches": sum(1 for r in latest if r.mode == "fix" and not r.gate_passed),
            "runs": len(runs),
        },
        "posture": [{"severity": s, "count": sev_now[s], "prev": sev_prev[s]} for s in SEVERITIES],
        "activity": activity[:8],
        "repositories": [
            {"repository": repo,
             "open_findings": sum(r.blocking for r in rs),
             "critical": sum(1 for r in rs for f in r.findings
                             if f.route in OPEN_ROUTES and f.severity == "Critical"),
             "branches": len(rs),
             "last_scan": iso(max(aware(r.started_at) for r in rs)),
             "status": "Healthy" if all(r.gate_passed for r in rs) else "Blocked"}
            for repo, rs in sorted(repos.items())
        ],
        "recent_runs": [run_summary(r) for r in sorted(runs, key=lambda r: aware(r.started_at), reverse=True)[:6]],
    }


def report(session: Session, repository=None, days=30) -> dict:
    start, _ = _window(days)
    runs = _runs_between(session, repository, start)
    rows = [f for r in runs for f in r.findings]
    scanned, confirmed = len(rows), sum(1 for f in rows if f.route == "fix")
    fixed = sum(1 for f in rows if f.fix_validated)
    attempted = [f for f in rows if f.fix_attempts]
    failed_attempts = sum((f.fix_attempts or 0) - (1 if f.fix_validated else 0) for f in attempted)
    total_attempts = sum(f.fix_attempts or 0 for f in attempted)
    durations = [d for d in (duration_seconds(r) for r in runs) if d]

    def bars(counter: Counter, n=6):
        return [{"label": k, "value": v} for k, v in counter.most_common(n)]

    buckets = Counter()
    for f in rows:
        s = f.laya_score
        buckets["90–100%" if s >= .9 else "80–89%" if s >= .8 else "70–79%" if s >= .7 else "< 70%"] += 1
    return {
        "window_days": days,
        "kpis": {
            "runs": len(runs), "findings": scanned,
            "autofix_success": _rate(fixed, confirmed),
            "false_positive_rate": _rate(sum(1 for f in rows if f.route == "reject"), scanned),
            "fix_attempt_failure_rate": _rate(failed_attempts, total_attempts),
            "avg_run_seconds": round(sum(durations) / len(durations), 1) if durations else None,
            "blocked_runs": sum(1 for r in runs if r.mode == "fix" and not r.gate_passed),
        },
        "charts": {
            "by_cwe": bars(Counter(cwe_id(f.cwe) for f in rows)),
            "by_repository": bars(Counter(r.repository for r in runs for _ in r.findings)),
            "confidence": [{"label": k, "value": buckets.get(k, 0)}
                           for k in ("90–100%", "80–89%", "70–79%", "< 70%")],
            "by_severity": [{"label": s, "value": sum(1 for f in rows if f.severity == s)} for s in SEVERITIES],
        },
    }


def export_rows(session: Session, repository=None, days=30) -> list[dict]:
    start, _ = _window(days)
    out = []
    for run in _runs_between(session, repository, start):
        for f in run.findings:
            out.append({
                "run_id": run.id, "repository": run.repository, "branch": run.base_branch,
                "started_at": iso(run.started_at), "severity": f.severity, "cwe": cwe_id(f.cwe),
                "title": cwe_title(f.cwe), "rule_id": f.rule_id, "file": f.file, "line": f.line,
                "verdict": verdict(f), "laya_score": f.laya_score, "fix_status": fix_status(f),
                "fix_attempts": f.fix_attempts, "fingerprint": f.fingerprint,
            })
    return out


def repositories(session: Session) -> list[str]:
    return list(session.scalars(select(Run.repository).distinct().order_by(Run.repository)).all())
