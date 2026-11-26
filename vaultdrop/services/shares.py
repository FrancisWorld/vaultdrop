import datetime as dt
import hashlib
import secrets
from dataclasses import dataclass
from typing import cast

from sqlalchemy import or_, select, update
from sqlalchemy.engine import CursorResult

from ..auth import PasswordService
from ..config import Settings
from ..database import Database
from ..errors import Forbidden, NotFound, TooManyAttempts, Unauthorized
from ..models import FileRecord, ShareLink, as_utc, utcnow
from ..ratelimit import AttemptLimiter
from ..repositories import find_file
from ..s3 import S3Service
from .audit import audit

UNAVAILABLE = "Share unavailable"


@dataclass(frozen=True)
class Redemption:
    download_url: str
    filename: str
    size_bytes: int


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ShareService:
    def __init__(
        self,
        database: Database,
        s3: S3Service,
        passwords: PasswordService,
        limiter: AttemptLimiter,
        settings: Settings,
    ) -> None:
        self.database = database
        self.s3 = s3
        self.passwords = passwords
        self.limiter = limiter
        self.settings = settings

    def create(
        self,
        user_id: str,
        file_id: str,
        *,
        password: str | None,
        expires_in_seconds: int | None,
        max_downloads: int | None,
    ) -> tuple[str, ShareLink]:
        password_hash = self.passwords.hash(password) if password else None
        token = secrets.token_urlsafe(32)
        with self.database.session() as db:
            if find_file(db, file_id, user_id) is None:
                raise NotFound("File not found")
            share = ShareLink(
                file_id=file_id,
                token_hash=hash_token(token),
                password_hash=password_hash,
                expires_at=(
                    utcnow() + dt.timedelta(seconds=expires_in_seconds)
                    if expires_in_seconds
                    else None
                ),
                max_downloads=max_downloads,
            )
            db.add(share)
            db.flush()
            audit(db, user_id, "share.created", share.id, f"Share for file {file_id}")
            return token, share

    def list(self, user_id: str) -> list[ShareLink]:
        with self.database.session() as db:
            return list(
                db.scalars(
                    select(ShareLink)
                    .join(FileRecord, ShareLink.file_id == FileRecord.id)
                    .where(FileRecord.owner_id == user_id)
                    .order_by(ShareLink.created_at.desc())
                )
            )

    def revoke(self, user_id: str, share_id: str) -> None:
        with self.database.session() as db:
            share = db.scalar(
                select(ShareLink)
                .join(FileRecord, ShareLink.file_id == FileRecord.id)
                .where(ShareLink.id == share_id, FileRecord.owner_id == user_id)
            )
            if share is None:
                raise NotFound("Share not found")
            db.delete(share)
            audit(db, user_id, "share.revoked", share_id, "Share revoked")

    def redeem(self, token: str, password: str | None, source: str) -> Redemption:
        """Validate a share link and hand out a presigned download URL.

        The download slot is claimed with a single conditional UPDATE, so
        concurrent redeemers can never exceed `max_downloads`. Password guesses are
        recorded (and committed) before the argon2 check so failures cannot be
        retried for free.
        """
        token_hash = hash_token(token)
        with self.database.session() as db:
            share = db.scalar(select(ShareLink).where(ShareLink.token_hash == token_hash))
            if share is None or self._unavailable(share):
                raise NotFound(UNAVAILABLE)
            share_id, password_hash = share.id, share.password_hash

        if password_hash:
            if not password:
                raise Unauthorized("Password required")
            scope = f"share:{share_id}"
            if not self.limiter.acquire(scope, source):
                raise TooManyAttempts(
                    "Too many password attempts",
                    headers={"Retry-After": str(self.limiter.retry_after)},
                )
            if not self.passwords.verify(password_hash, password):
                raise Forbidden("Invalid password")
            self.limiter.clear(scope, source)

        with self.database.session() as db:
            now = utcnow()
            claimed = cast(
                CursorResult[tuple[object, ...]],
                db.execute(
                    update(ShareLink)
                    .where(
                        ShareLink.id == share_id,
                        or_(ShareLink.expires_at.is_(None), ShareLink.expires_at > now),
                        or_(
                            ShareLink.max_downloads.is_(None),
                            ShareLink.downloads < ShareLink.max_downloads,
                        ),
                    )
                    .values(downloads=ShareLink.downloads + 1)
                ),
            )
            if claimed.rowcount != 1:
                raise NotFound(UNAVAILABLE)
            file_record = db.scalar(
                select(FileRecord)
                .join(ShareLink, ShareLink.file_id == FileRecord.id)
                .where(ShareLink.id == share_id)
            )
            if file_record is None:
                raise NotFound(UNAVAILABLE)
            audit(
                db,
                file_record.owner_id,
                "share.redeemed",
                share_id,
                f"Redeemed from source {hashlib.sha256(source.encode()).hexdigest()[:12]}",
            )
            url = self.s3.presign_download(file_record.s3_key, file_record.filename)
            return Redemption(url, file_record.filename, file_record.size_bytes)

    @staticmethod
    def _unavailable(share: ShareLink) -> bool:
        if share.expires_at is not None and as_utc(share.expires_at) <= utcnow():
            return True
        return share.max_downloads is not None and share.downloads >= share.max_downloads
