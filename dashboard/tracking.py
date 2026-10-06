"""Keeps one TrackedFinding per finding identity up to date.

The record is recomputed from the stored finding rows every time, rather
than incremented, so ingesting a run twice (CI retries) gives the same
answer as ingesting it once.
"""

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import FindingRow, Run, TrackedFinding


def refresh(session: Session, fingerprints) -> None:
    """Rebuild the TrackedFinding for each identity from its real (non-dry) rows."""
    for fp in set(fingerprints):
        rows = session.execute(
            select(FindingRow, Run)
            .join(Run, FindingRow.run_id == Run.id)
            .where(FindingRow.fingerprint == fp, Run.dry_run.is_(False))
            .order_by(Run.started_at.asc(), FindingRow.position.asc())
        ).all()
        if not rows:
            session.execute(delete(TrackedFinding).where(TrackedFinding.fingerprint == fp))
            continue
        latest, run = rows[-1]
        tracked = session.get(TrackedFinding, fp) or TrackedFinding(fingerprint=fp)
        tracked.repository = run.repository
        tracked.rule_id = latest.rule_id
        tracked.cwe = latest.cwe
        tracked.file = latest.file
        tracked.first_seen = rows[0][1].started_at
        tracked.last_seen = run.started_at
        tracked.occurrences = len({r.run_id for r, _ in rows})
        tracked.severity = latest.severity
        tracked.cvss = latest.cvss
        tracked.risk = latest.risk
        tracked.latest_run_id = run.id
        tracked.route = latest.route
        tracked.llm_label = latest.llm_label
        tracked.laya_score = latest.laya_score
        tracked.rounds = latest.rounds
        tracked.fix_attempts = latest.fix_attempts
        tracked.fix_validated = latest.fix_validated
        tracked.disposition = latest.outcome
        tracked.commit = run.commit
        tracked.pr_number = run.pr_number
        tracked.pr_url = run.pr_url
        session.merge(tracked)
