"""tracked_findings: a person's decision (false positive, suppressed)

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('tracked_findings', sa.Column('decision', sa.String(16), nullable=True))
    op.add_column('tracked_findings', sa.Column('decision_reason', sa.Text(), nullable=True))
    op.add_column('tracked_findings', sa.Column('decided_by', sa.Text(), nullable=True))
    op.add_column('tracked_findings', sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('tracked_findings', 'decided_at')
    op.drop_column('tracked_findings', 'decided_by')
    op.drop_column('tracked_findings', 'decision_reason')
    op.drop_column('tracked_findings', 'decision')
