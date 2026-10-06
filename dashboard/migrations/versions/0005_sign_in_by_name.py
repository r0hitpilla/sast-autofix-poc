"""users: sign in with a unique name

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-07

Accounts created without a name get their email's first part as a stand-in,
so every user has a name to sign in with. Names are unique, ignoring case.
"""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    users = sa.table('users', sa.column('id', sa.Integer), sa.column('email', sa.Text),
                     sa.column('name', sa.Text))
    conn = op.get_bind()
    for row in conn.execute(sa.select(users.c.id, users.c.email, users.c.name)).all():
        if not (row.name or "").strip():
            conn.execute(users.update().where(users.c.id == row.id)
                         .values(name=row.email.split("@")[0] or f"user{row.id}"))
    op.create_index('ix_users_name_lower', 'users', [sa.text('lower(name)')], unique=True)


def downgrade():
    op.drop_index('ix_users_name_lower', table_name='users')
