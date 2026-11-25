import base64
import hashlib
import hmac
import json
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import User

passwords = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=2)


def hash_password(password: str) -> str:
    return passwords.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return passwords.verify(password_hash, password)
    except (VerifyMismatchError, ValueError):
        return False


def sign_session(user_id: str) -> str:
    payload = json.dumps(
        {"sub": user_id, "iat": int(time.time()), "nonce": secrets.token_urlsafe(16)},
        separators=(",", ":"),
    ).encode()
    body = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(
        get_settings().session_secret.encode(), body, hashlib.sha256
    ).digest()
    return f"{body.decode()}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def verify_session(token: str) -> str | None:
    try:
        body, signature_text = token.rsplit(".", 1)
        pad = "=" * (-len(signature_text) % 4)
        signature = base64.urlsafe_b64decode(signature_text + pad)
        expected = hmac.new(
            get_settings().session_secret.encode(), body.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        issued = int(payload["iat"])
        if int(time.time()) - issued > 7 * 86400:
            return None
        return str(payload["sub"])
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def current_user(
    db: Session, vaultdrop_session: str | None = Cookie(default=None)
) -> User:
    user_id = verify_session(vaultdrop_session or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user
