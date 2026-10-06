from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from dashboard.db import Base
from dashboard.settings import get_settings

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)


def run_migrations_online():
    engine = create_engine(config.get_main_option("sqlalchemy.url") or get_settings().db_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
