from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class Database:
    """Engine plus session factory.

    SQLite is supported for local development: every transaction starts with
    `BEGIN IMMEDIATE`, so writers are fully serialised. PostgreSQL relies on row
    locks (`SELECT ... FOR UPDATE`) and advisory locks, which SQLite renders as no-ops.
    """

    def __init__(self, url: str, *, pool_size: int = 10) -> None:
        self.url = url
        if url.startswith("sqlite"):
            self.engine: Engine = create_engine(
                url, connect_args={"check_same_thread": False, "timeout": 30}
            )
            self._configure_sqlite(self.engine)
        else:
            self.engine = create_engine(
                url, pool_size=pool_size, max_overflow=pool_size * 2, pool_pre_ping=True
            )
        self.is_postgres = self.engine.dialect.name == "postgresql"
        self._factory = sessionmaker(bind=self.engine, expire_on_commit=False, autoflush=False)

    @staticmethod
    def _configure_sqlite(engine: Engine) -> None:
        @event.listens_for(engine, "connect")
        def on_connect(dbapi_connection: Any, _record: Any) -> None:
            dbapi_connection.isolation_level = None  # we emit BEGIN ourselves
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        @event.listens_for(engine, "begin")
        def on_begin(connection: Any) -> None:
            connection.exec_driver_sql("BEGIN IMMEDIATE")

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Commit on success, roll back on any exception."""
        session = self._factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def advisory_lock(self, session: Session, key: str) -> None:
        """Serialise concurrent transactions touching the same logical key (PostgreSQL)."""
        if self.is_postgres:
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}
            )

    def dispose(self) -> None:
        self.engine.dispose()
