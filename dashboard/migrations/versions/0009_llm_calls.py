"""llm_calls: every AI call a run made (tokens, time, purpose)

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'llm_calls',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('run_id', sa.String(64), sa.ForeignKey('runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('purpose', sa.String(48), nullable=False),
        sa.Column('model', sa.String(160), nullable=False),
        sa.Column('provider', sa.String(32), nullable=False),
        sa.Column('prompt_tokens', sa.Integer(), nullable=True),
        sa.Column('completion_tokens', sa.Integer(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=False),
        sa.Column('ok', sa.Boolean(), nullable=False),
        sa.Column('truncated', sa.Boolean(), nullable=False),
        sa.Column('ref', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
    )
    op.create_index('ix_llm_calls_run_id', 'llm_calls', ['run_id'])
    op.create_index('ix_llm_calls_at', 'llm_calls', ['at'])
    op.create_index('ix_llm_calls_purpose', 'llm_calls', ['purpose'])
    op.create_index('ix_llm_calls_model', 'llm_calls', ['model'])


def downgrade():
    op.drop_table('llm_calls')
