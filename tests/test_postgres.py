"""Checks that only mean something on PostgreSQL (skipped on SQLite runs)."""

import subprocess
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import BigInteger, inspect, text

pytestmark = pytest.mark.postgres


def test_byte_counters_are_bigint_after_migration(app: FastAPI, client: TestClient) -> None:
    engine = app.state.container.database.engine
    inspector = inspect(engine)
    for table, column in [
        ("users", "quota_bytes"),
        ("files", "size_bytes"),
        ("multipart_uploads", "size_bytes"),
        ("multipart_uploads", "reserved_bytes"),
        ("multipart_parts", "size_bytes"),
    ]:
        kind = next(c["type"] for c in inspector.get_columns(table) if c["name"] == column)
        assert isinstance(kind, BigInteger), f"{table}.{column} would overflow at 2 GiB"


def test_foreign_keys_cascade_in_the_database(app: FastAPI, client: TestClient) -> None:
    database = app.state.container.database
    assert database.is_postgres
    with database.session() as db:
        db.execute(text("DELETE FROM users"))
        assert db.scalar(text("SELECT count(*) FROM sessions")) == 0  # ON DELETE CASCADE


def test_advisory_locks_serialise_on_the_same_key(app: FastAPI, client: TestClient) -> None:
    database = app.state.container.database
    with database.session() as first:
        database.advisory_lock(first, "scope:key")
        with database.session() as second:
            second.execute(text("SET LOCAL lock_timeout = '200ms'"))
            database.advisory_lock(second, "scope:other")  # a different key is not blocked
            with pytest.raises(Exception, match="lock timeout"):
                database.advisory_lock(second, "scope:key")


def test_replicas_migrating_at_once_do_not_collide(database_url: str) -> None:
    code = "import sys; from vaultdrop import migrate; migrate.upgrade(sys.argv[1])"
    workers = [subprocess.Popen([sys.executable, "-c", code, database_url]) for _ in range(4)]
    assert [worker.wait(timeout=120) for worker in workers] == [0, 0, 0, 0]
