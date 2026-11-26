from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from vaultdrop import migrate
from vaultdrop.database import Base

EXPECTED = {
    "users", "sessions", "multipart_uploads", "multipart_parts", "files",
    "share_links", "attempt_log", "audit_events",
}  # fmt: skip


def test_upgrade_creates_every_table_and_matches_the_models(database_url: str) -> None:
    migrate.upgrade(database_url)
    engine = create_engine(database_url)
    try:
        assert EXPECTED <= set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            drift = compare_metadata(MigrationContext.configure(connection), Base.metadata)
        assert drift == [], f"models and migrations disagree: {drift}"
    finally:
        engine.dispose()


def test_upgrade_is_idempotent_and_downgrade_removes_the_schema(database_url: str) -> None:
    migrate.upgrade(database_url)
    migrate.upgrade(database_url)
    migrate.downgrade(database_url, "base")
    engine = create_engine(database_url)
    try:
        assert not EXPECTED & set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    migrate.upgrade(database_url)  # and back up again
