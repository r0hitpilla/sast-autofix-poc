"""policy_versions: the published security policy, one row per version

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.create_table(
        'policy_versions',
        sa.Column('version', sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column('content', JSONType, nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('published_by', sa.Text(), nullable=False),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table('policy_versions')
