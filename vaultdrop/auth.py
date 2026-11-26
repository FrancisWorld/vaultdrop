import datetime as dt
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings
from .errors import Unauthorized
from .models import User, UserSession, as_utc, utcnow


class PasswordService:
    """Argon2id hashing with parameters taken from configuration."""

    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
        )
        # Verified against when a username does not exist, so that unknown users
        # cost the same as known ones and timing does not reveal registration.
        self._decoy = self._hasher.hash(secrets.token_urlsafe(16))

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def verify_decoy(self, password: str) -> None:
        self.verify(self._decoy, password)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_session(db: Session, user_id: str, ttl_seconds: int) -> str:
    """Create a server-side session and return the opaque bearer token.

    Only the SHA-256 of the token is stored, so a leaked database cannot be
    replayed as cookies, and logout/expiry are enforced by the server.
    """
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=token_digest(token),
            user_id=user_id,
            expires_at=utcnow() + dt.timedelta(seconds=ttl_seconds),
        )
    )
    return token


def authenticate(db: Session, token: str | None) -> User:
    if token:
        row = db.execute(
            select(User, UserSession.expires_at)
            .join(UserSession, UserSession.user_id == User.id)
            .where(UserSession.token_hash == token_digest(token))
        ).first()
        if row and as_utc(row[1]) > utcnow():
            return row[0]
    raise Unauthorized("Authentication required")


def revoke_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == token_digest(token)))
