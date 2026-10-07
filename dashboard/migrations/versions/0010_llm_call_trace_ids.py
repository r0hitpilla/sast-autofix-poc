"""llm_calls: where Langfuse shows each call (trace and span id)

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('llm_calls', sa.Column('trace_id', sa.String(32), nullable=True))
    op.add_column('llm_calls', sa.Column('span_id', sa.String(16), nullable=True))


def downgrade():
    op.drop_column('llm_calls', 'span_id')
    op.drop_column('llm_calls', 'trace_id')
