"""Database schema. One row per pipeline run and one per finding in it; the
full report is kept verbatim (runs.report) so nothing the pipeline recorded
is ever lost to a schema that didn't anticipate it."""

from datetime import datetime

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, create_engine)
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


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(32), index=True)

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
