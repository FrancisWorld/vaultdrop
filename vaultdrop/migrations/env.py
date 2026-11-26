from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from vaultdrop import models  # noqa: F401  (registers tables on Base.metadata)
from vaultdrop.config import get_settings
from vaultdrop.database import Base

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata

MIGRATION_LOCK_KEY = 7_345_001


def database_url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        if connection.dialect.name == "postgresql":
            # Several replicas may start at once; only one may run migrations.
            connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        context.configure(connection=connection, target_metadata=target_metadata)
        try:
            with context.begin_transaction():
                context.run_migrations()
        finally:
            if connection.dialect.name == "postgresql":
                connection.commit()
                connection.execute(
                    text("SELECT pg_advisory_unlock(:key)"), {"key": MIGRATION_LOCK_KEY}
                )
                connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
