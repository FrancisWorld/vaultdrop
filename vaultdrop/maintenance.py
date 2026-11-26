import asyncio
import datetime as dt
import logging

from sqlalchemy import delete

from .database import Database
from .models import AttemptLog, UserSession, utcnow
from .services.uploads import UploadService

log = logging.getLogger(__name__)


class Maintenance:
    """Periodic housekeeping: expired uploads, sessions and rate-limit ledger rows."""

    def __init__(
        self, database: Database, uploads: UploadService, attempt_window_seconds: int
    ) -> None:
        self.database = database
        self.uploads = uploads
        self.ledger_retention = dt.timedelta(seconds=attempt_window_seconds * 2)

    def run_once(self) -> dict[str, int]:
        swept = self.uploads.sweep_expired()
        with self.database.session() as db:
            sessions = db.execute(delete(UserSession).where(UserSession.expires_at <= utcnow()))
            attempts = db.execute(
                delete(AttemptLog).where(AttemptLog.attempted_at < utcnow() - self.ledger_retention)
            )
            return {
                "uploads_aborted": swept,
                "sessions_purged": int(getattr(sessions, "rowcount", 0) or 0),
                "attempts_purged": int(getattr(attempts, "rowcount", 0) or 0),
            }

    async def run_forever(self, interval_seconds: int) -> None:
        while True:
            try:
                result = await asyncio.to_thread(self.run_once)
                if any(result.values()):
                    log.info("maintenance pass: %s", result)
            except Exception:
                log.exception("maintenance pass failed")
            await asyncio.sleep(interval_seconds)
