"""findings: repository-scoped identity; tracked_findings table

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07

Widens the fingerprint to a full SHA-256, recomputes it for every stored
finding (it now includes the repository), and builds one tracked_findings
record per identity from the existing runs.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

from identity import finding_fingerprint

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    # batch mode: SQLite (used by the tests) can't ALTER COLUMN in place.
    with op.batch_alter_table('findings') as batch:
        batch.alter_column('fingerprint', existing_type=sa.String(32),
                           type_=sa.String(64), existing_nullable=False)
    op.create_table(
        'tracked_findings',
        sa.Column('fingerprint', sa.String(64), primary_key=True),
        sa.Column('repository', sa.Text(), nullable=False, index=True),
        sa.Column('rule_id', sa.Text(), nullable=False),
        sa.Column('cwe', sa.Text(), nullable=False),
        sa.Column('file', sa.Text(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('occurrences', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('cvss', sa.Float(), nullable=True),
        sa.Column('risk', sa.Float(), nullable=True),
        sa.Column('latest_run_id', sa.String(64), nullable=False),
        sa.Column('route', sa.String(16), nullable=False),
        sa.Column('llm_label', sa.String(8), nullable=True),
        sa.Column('laya_score', sa.Float(), nullable=False),
        sa.Column('rounds', sa.Integer(), nullable=False),
        sa.Column('fix_attempts', sa.Integer(), nullable=True),
        sa.Column('fix_validated', sa.Boolean(), nullable=False),
        sa.Column('disposition', sa.Text(), nullable=False),
        sa.Column('commit', sa.String(64), nullable=True),
        sa.Column('pr_number', sa.Integer(), nullable=True),
        sa.Column('pr_url', sa.Text(), nullable=True),
    )

    # Backfill: recompute each stored fingerprint with its run's repository,
    # then build the tracked records from the corrected rows.
    from dashboard.db import FindingRow, Run
    from dashboard.tracking import refresh

    session = Session(bind=op.get_bind())
    rows = session.execute(sa.select(FindingRow, Run).join(Run, FindingRow.run_id == Run.id)).all()
    for row, run in rows:
        row.fingerprint = finding_fingerprint(run.repository, row.rule_id, row.file, row.snippet)
    session.flush()
    refresh(session, {row.fingerprint for row, _ in rows})
    session.commit()
    session.close()


def downgrade():
    op.drop_table('tracked_findings')
    with op.batch_alter_table('findings') as batch:
        batch.alter_column('fingerprint', existing_type=sa.String(64),
                           type_=sa.String(32), existing_nullable=False)
