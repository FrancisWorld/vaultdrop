from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..auth import PasswordService, issue_session, revoke_session
from ..config import Settings
from ..database import Database
from ..errors import Conflict, Forbidden, TooManyAttempts, Unauthorized
from ..models import User
from ..ratelimit import AttemptLimiter
from .audit import audit


class AccountService:
    def __init__(
        self,
        database: Database,
        passwords: PasswordService,
        limiter: AttemptLimiter,
        settings: Settings,
    ) -> None:
        self.database = database
        self.passwords = passwords
        self.limiter = limiter
        self.settings = settings

    def register(self, username: str, password: str) -> tuple[User, str]:
        if not self.settings.allow_registration:
            raise Forbidden("Registration is disabled")
        username = username.lower()
        password_hash = self.passwords.hash(password)
        try:
            with self.database.session() as db:
                if db.scalar(select(User).where(User.username == username)):
                    raise Conflict("Username already exists")
                user = User(
                    username=username,
                    password_hash=password_hash,
                    quota_bytes=self.settings.default_quota_bytes,
                )
                db.add(user)
                db.flush()
                audit(db, user.id, "auth.registered", user.id, "User registered")
                token = issue_session(db, user.id, self.settings.session_ttl_seconds)
        except IntegrityError:
            raise Conflict("Username already exists") from None
        return user, token

    def login(self, username: str, password: str, source: str) -> tuple[User, str]:
        username = username.lower()
        if not self.limiter.acquire("login", f"{source}|{username}"):
            raise TooManyAttempts(
                "Too many login attempts",
                headers={"Retry-After": str(self.limiter.retry_after)},
            )
        with self.database.session() as db:
            user = db.scalar(select(User).where(User.username == username))
        if user is None:
            self.passwords.verify_decoy(password)
            raise Unauthorized("Invalid credentials")
        if not self.passwords.verify(user.password_hash, password):
            raise Unauthorized("Invalid credentials")
        self.limiter.clear("login", f"{source}|{username}")
        with self.database.session() as db:
            audit(db, user.id, "auth.login", user.id, "Session issued")
            token = issue_session(db, user.id, self.settings.session_ttl_seconds)
        return user, token

    def logout(self, token: str | None) -> None:
        with self.database.session() as db:
            revoke_session(db, token)
