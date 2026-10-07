"""integrations, notification outbox, ticket link on tracked findings

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

JSONType = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade():
    op.add_column('tracked_findings', sa.Column('issue_key', sa.String(64), nullable=True))
    op.add_column('tracked_findings', sa.Column('issue_url', sa.Text(), nullable=True))
    op.create_table(
        'integrations',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('provider', sa.String(32), nullable=False, unique=True),
        sa.Column('config', JSONType, nullable=False),
        sa.Column('secret_enc', sa.Text(), nullable=False),
        sa.Column('events', JSONType, nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('last_test_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_test_detail', JSONType, nullable=False),
        sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        'notification_outbox',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('integration_id', sa.Integer(), sa.ForeignKey('integrations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event', sa.String(32), nullable=False),
        sa.Column('run_id', sa.String(64), nullable=False),
        sa.Column('payload', JSONType, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
    )
    op.create_index('ix_notification_outbox_integration_id', 'notification_outbox', ['integration_id'])
    op.create_index('ix_notification_outbox_next_attempt_at', 'notification_outbox', ['next_attempt_at'])
    op.create_index('ix_notification_outbox_delivered_at', 'notification_outbox', ['delivered_at'])
    op.create_index('ux_outbox_once', 'notification_outbox', ['integration_id', 'event', 'run_id'], unique=True)


def downgrade():
    op.drop_table('notification_outbox')
    op.drop_table('integrations')
    op.drop_column('tracked_findings', 'issue_url')
    op.drop_column('tracked_findings', 'issue_key')
