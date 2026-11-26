import datetime as dt
import hashlib

from sqlalchemy import delete, func, select

from .database import Database
from .models import AttemptLog, utcnow


class AttemptLimiter:
    """Sliding-window limiter backed by the database.

    `acquire` records an attempt and commits it *before* the caller does the
    expensive credential check, so a rejected guess still counts. Concurrent
    callers for the same (scope, key) are serialised with an advisory lock, which
    makes the count-then-insert sequence race free.
    """

    def __init__(self, database: Database, limit: int, window_seconds: int) -> None:
        self.database = database
        self.limit = limit
        self.window = dt.timedelta(seconds=window_seconds)

    @staticmethod
    def _digest(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    def acquire(self, scope: str, key: str) -> bool:
        digest = self._digest(key)
        with self.database.session() as db:
            self.database.advisory_lock(db, f"{scope}:{digest}")
            recent = db.scalar(
                select(func.count(AttemptLog.id)).where(
                    AttemptLog.scope == scope,
                    AttemptLog.key_hash == digest,
                    AttemptLog.attempted_at >= utcnow() - self.window,
                )
            )
            if int(recent or 0) >= self.limit:
                return False
            db.add(AttemptLog(scope=scope, key_hash=digest))
            return True

    def clear(self, scope: str, key: str) -> None:
        with self.database.session() as db:
            db.execute(
                delete(AttemptLog).where(
                    AttemptLog.scope == scope, AttemptLog.key_hash == self._digest(key)
                )
            )

    @property
    def retry_after(self) -> int:
        return int(self.window.total_seconds())
