"""Database schema. One row per pipeline run and one per finding in it; the
full report is kept verbatim (runs.report) so nothing the pipeline recorded
is ever lost to a schema that didn't anticipate it."""

from datetime import datetime

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, create_engine, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .settings import get_settings

# JSONB on PostgreSQL (indexable, compact); plain JSON elsewhere (tests).
JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repository: Mapped[str] = mapped_column(String(200), index=True)
    base_branch: Mapped[str] = mapped_column(String(200))
    fix_branch: Mapped[str | None] = mapped_column(String(200))
    commit: Mapped[str | None] = mapped_column(String(64))
    trigger: Mapped[str | None] = mapped_column(String(40))
    mode: Mapped[str] = mapped_column(String(20), default="fix")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    url: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scanned: Mapped[int] = mapped_column(Integer, default=0)
    confirmed: Mapped[int] = mapped_column(Integer, default=0)
    fixed: Mapped[int] = mapped_column(Integer, default=0)
    review: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    residual: Mapped[int] = mapped_column(Integer, default=0)
    blocking: Mapped[int] = mapped_column(Integer, default=0)
    gate_passed: Mapped[bool | None] = mapped_column(Boolean)

    pr_number: Mapped[int | None] = mapped_column(Integer)
    pr_url: Mapped[str | None] = mapped_column(Text)
    fix_branch_state: Mapped[str | None] = mapped_column(String(20))
    fix_branch_description: Mapped[str | None] = mapped_column(Text)

    timings: Mapped[dict] = mapped_column(JSONType, default=dict)
    provenance: Mapped[dict] = mapped_column(JSONType, default=dict)
    report: Mapped[dict] = mapped_column(JSONType)
    schema_version: Mapped[int] = mapped_column(Integer)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="FindingRow.position")

    __table_args__ = (Index("ix_runs_repo_branch_started", "repository", "base_branch", "started_at"),)


class User(Base):
    __tablename__ = "users"
    # Sign-in uses the name, so it must be unique regardless of case.
    __table_args__ = (Index("ix_users_name_lower", text("lower(name)"), unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(Text, unique=True)      # stored lower-case; for contact and audit
    name: Mapped[str] = mapped_column(Text)                    # the sign-in name
    role: Mapped[str] = mapped_column(String(32))              # see auth.ROLES
    password_hash: Mapped[str] = mapped_column(Text)           # scrypt$salt$digest
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthSession(Base):
    """A signed-in browser. Only a hash of the cookie's token is stored."""
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)


class AuditEvent(Base):
    """Append-only record of who did what. Never edited, only read."""
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor_email: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16))           # success | failure | denied
    target: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))


class TrackedFinding(Base):
    """One record per finding identity (see identity.py), across every run,
    branch and repository it has appeared in. Rebuilt from the finding rows
    by tracking.refresh, so re-ingesting a run never double-counts it."""
    __tablename__ = "tracked_findings"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    repository: Mapped[str] = mapped_column(Text, index=True)
    rule_id: Mapped[str] = mapped_column(Text)
    cwe: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    occurrences: Mapped[int] = mapped_column(Integer)      # distinct runs it appeared in
    severity: Mapped[str] = mapped_column(String(16))
    cvss: Mapped[float | None] = mapped_column(Float)
    risk: Mapped[float | None] = mapped_column(Float)
    # The latest occurrence's state:
    latest_run_id: Mapped[str] = mapped_column(String(64))
    route: Mapped[str] = mapped_column(String(16))          # fix | review | reject
    llm_label: Mapped[str | None] = mapped_column(String(8))
    laya_score: Mapped[float] = mapped_column(Float)
    rounds: Mapped[int] = mapped_column(Integer, default=0)  # follow-up questions asked
    fix_attempts: Mapped[int | None] = mapped_column(Integer)
    fix_validated: Mapped[bool] = mapped_column(Boolean, default=False)
    disposition: Mapped[str] = mapped_column(Text)          # the pipeline's outcome text
    commit: Mapped[str | None] = mapped_column(String(64))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    pr_url: Mapped[str | None] = mapped_column(Text)
    # A person's decision about this finding. Kept across pipeline runs: the
    # refresh recomputes the fields above and never touches these.
    decision: Mapped[str | None] = mapped_column(String(16))   # false_positive | suppressed
    decision_reason: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(Text)        # email of the decider
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Ticket created for this finding (e.g. a Jira issue).
    issue_key: Mapped[str | None] = mapped_column(String(64))
    issue_url: Mapped[str | None] = mapped_column(Text)


class Integration(Base):
    """A connection to an outside system. Secrets are encrypted (integrations.py)."""
    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(32), unique=True)   # see integrations.PROVIDERS
    config: Mapped[dict] = mapped_column(JSONType, default=dict)      # non-secret settings
    secret_enc: Mapped[str] = mapped_column(Text)                     # encrypted JSON of secrets
    events: Mapped[list] = mapped_column(JSONType, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="untested")  # connected | failing | untested
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_detail: Mapped[list] = mapped_column(JSONType, default=list)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OutboxMessage(Base):
    """A notification waiting to be delivered. Written by ingest, sent by the
    dashboard service (which alone holds the key to the integration secrets)."""
    __tablename__ = "notification_outbox"
    __table_args__ = (Index("ux_outbox_once", "integration_id", "event", "run_id", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    event: Mapped[str] = mapped_column(String(32))
    run_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    rule_id: Mapped[str] = mapped_column(Text)
    cwe: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    owasp: Mapped[list] = mapped_column(JSONType, default=list)
    file: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    # CVSS base score (dependency advisories) and the pipeline's risk score;
    # null for runs recorded before these existed.
    cvss: Mapped[float | None] = mapped_column(Float)
    risk: Mapped[float | None] = mapped_column(Float, index=True)
    message: Mapped[str] = mapped_column(Text)
    snippet: Mapped[str] = mapped_column(Text)

    laya_score: Mapped[float] = mapped_column(Float)
    route: Mapped[str] = mapped_column(String(16), index=True)   # fix | review | reject
    llm_label: Mapped[str | None] = mapped_column(String(8))      # tp | fp
    rounds: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[list] = mapped_column(JSONType, default=list)
    context: Mapped[str | None] = mapped_column(Text)

    outcome: Mapped[str] = mapped_column(Text)
    fix_validated: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_attempts: Mapped[int | None] = mapped_column(Integer)
    fix: Mapped[dict | None] = mapped_column(JSONType)

    run: Mapped[Run] = relationship(back_populates="findings")


def make_engine(url: str | None = None):
    url = url or get_settings().db_url
    kwargs = {"pool_pre_ping": True} if url.startswith("postgresql") else {}
    return create_engine(url, **kwargs)


def make_sessionmaker(engine=None):
    return sessionmaker(bind=engine or make_engine(), expire_on_commit=False)
