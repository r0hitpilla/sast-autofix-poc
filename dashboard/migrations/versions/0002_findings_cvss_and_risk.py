"""findings: CVSS score and risk score

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07

Both are nullable: runs recorded before this migration have neither.
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('findings', sa.Column('cvss', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('risk', sa.Float(), nullable=True))
    op.create_index('ix_findings_risk', 'findings', ['risk'])


def downgrade():
    op.drop_index('ix_findings_risk', table_name='findings')
    op.drop_column('findings', 'risk')
    op.drop_column('findings', 'cvss')
