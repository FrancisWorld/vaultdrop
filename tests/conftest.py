import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import boto3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from moto import mock_aws
from sqlalchemy import create_engine, text

from vaultdrop import migrate
from vaultdrop.api import create_app
from vaultdrop.config import Settings

BUCKET = "vaultdrop-test-bucket"
PASSWORD = "correct-horse-battery"
DATABASE_URL = os.environ.get("VAULTDROP_TEST_DATABASE_URL")
REQUIRE_SERVICES = os.environ.get("VAULTDROP_REQUIRE_SERVICES") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    on_postgres = bool(DATABASE_URL and DATABASE_URL.startswith("postgresql"))
    for item in items:
        if "postgres" in item.keywords and not on_postgres:
            if REQUIRE_SERVICES:
                item.add_marker(
                    pytest.mark.xfail(reason="PostgreSQL required", run=True, strict=True)
                )
            else:
                item.add_marker(
                    pytest.mark.skip(reason="set VAULTDROP_TEST_DATABASE_URL to a postgresql URL")
                )


@pytest.fixture
def database_url(tmp_path: Path) -> Iterator[str]:
    """A fresh, isolated database per test: a SQLite file or a throwaway PostgreSQL schema."""
    if not DATABASE_URL:
        yield f"sqlite:///{tmp_path / 'vaultdrop.db'}"
        return
    schema = f"t_{uuid.uuid4().hex[:12]}"
    admin = create_engine(DATABASE_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    separator = "&" if "?" in DATABASE_URL else "?"
    yield f"{DATABASE_URL}{separator}options=-csearch_path%3D{schema}"
    with admin.connect() as connection:
        connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    admin.dispose()


@pytest.fixture
def settings(database_url: str) -> Settings:
    return Settings(
        _env_file=None,
        database_url=database_url,
        s3_bucket=BUCKET,
        cookie_secure=False,
        argon2_memory_kib=1024,
        argon2_time_cost=1,
        sweep_interval_seconds=0,
    )


@pytest.fixture
def aws() -> Iterator[object]:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


@pytest.fixture
def app(settings: Settings, aws: object) -> FastAPI:
    migrate.upgrade(settings.database_url)  # clients created without `with` skip the lifespan
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        registered = test_client.post(
            "/v1/auth/register", json={"username": "alice", "password": PASSWORD}
        )
        assert registered.status_code == 200
        yield test_client


def new_user(app: FastAPI, username: str, *, source: str = "testclient") -> TestClient:
    """An additional, independently authenticated client against the same app."""
    other = TestClient(app, client=(source, 50000))
    response = other.post("/v1/auth/register", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return other


def db_scalar(app: FastAPI, statement: object) -> object:
    """Run a read-only statement against the application's own database."""
    with app.state.container.database.session() as db:
        return db.scalar(statement)


def db_execute(app: FastAPI, statement: object) -> None:
    with app.state.container.database.session() as db:
        db.execute(statement)
