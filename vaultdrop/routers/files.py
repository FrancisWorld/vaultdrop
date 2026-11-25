import datetime as dt
import hashlib
import secrets

from fastapi import APIRouter, Cookie, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import hash_password, verify_password, verify_session
from ..database import session_scope
from ..models import FileRecord, ShareLink, SharePasswordAttempt, User
from ..repositories import find_file
from ..s3 import S3Service
from ..services import ShareService, audit

router = APIRouter(tags=["files"])
s3 = S3Service()
shares = ShareService(s3)


class ShareRequest(BaseModel):
    password: str | None = Field(default=None, max_length=256)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=30 * 86400)
    max_downloads: int | None = Field(default=None, ge=1, le=100000)


def actor(db: Session, session_cookie: str | None) -> User:
    user_id = verify_session(session_cookie or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.get("/v1/files")
def files(vaultdrop_session: str | None = Cookie(default=None)) -> list[dict[str, object]]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        rows = db.scalars(select(FileRecord).where(FileRecord.owner_id == user.id).order_by(FileRecord.created_at.desc()))
        return [{"id": r.id, "filename": r.filename, "size_bytes": r.size_bytes, "sha256": r.sha256, "created_at": r.created_at.isoformat()} for r in rows]


@router.post("/v1/files/{file_id}/shares")
def create_share(file_id: str, body: ShareRequest, vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, str]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        file_record = find_file(db, file_id, user.id)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        token = secrets.token_urlsafe(32)
        expires = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=body.expires_in_seconds) if body.expires_in_seconds else None
        share = ShareLink(
            file_id=file_id,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            password_hash=hash_password(body.password) if body.password else None,
            expires_at=expires,
            max_downloads=body.max_downloads,
        )
        db.add(share)
        db.flush()
        audit(db, user.id, "share.created", share.id, f"Created share for {file_id}")
        return {"token": token, "url": f"/s/{token}"}


@router.get("/v1/shares")
def share_list(vaultdrop_session: str | None = Cookie(default=None)) -> list[dict[str, object]]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        rows = db.scalars(select(ShareLink).join(FileRecord, ShareLink.file_id == FileRecord.id).where(FileRecord.owner_id == user.id).order_by(ShareLink.created_at.desc()))
        return [{"id": r.id, "file_id": r.file_id, "expires_at": r.expires_at.isoformat() if r.expires_at else None, "downloads": r.downloads, "max_downloads": r.max_downloads, "password_protected": r.password_hash is not None} for r in rows]


@router.get("/s/{token}")
def redeem(token: str, request: Request, password: str | None = Query(default=None)) -> dict[str, str]:
    with session_scope() as db:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        share = db.scalar(select(ShareLink).where(ShareLink.token_hash == token_hash))
        generic = "Share unavailable"
        if not share:
            raise HTTPException(status_code=404, detail=generic)
        now = dt.datetime.now(dt.UTC)
        expires = share.expires_at
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.UTC)
        if (expires and expires <= now) or (share.max_downloads is not None and share.downloads >= share.max_downloads):
            raise HTTPException(status_code=404, detail=generic)
        if share.password_hash:
            window_start = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=15)
            if window_start.tzinfo is None:
                window_start = window_start.replace(tzinfo=dt.UTC)
            source = hashlib.sha256((request.client.host if request.client else "unknown").encode()).hexdigest()
            recent = db.scalar(
                select(func.count(SharePasswordAttempt.id)).where(
                    SharePasswordAttempt.share_id == share.id,
                    SharePasswordAttempt.source_hash == source,
                    SharePasswordAttempt.attempted_at >= window_start,
                )
            )
            if int(recent or 0) >= 5:
                raise HTTPException(status_code=404, detail=generic)
            db.add(SharePasswordAttempt(share_id=share.id, source_hash=source))
            if not password or not verify_password(share.password_hash, password):
                raise HTTPException(status_code=404, detail=generic)
        try:
            url = shares.redeem(db, token, password, request.client.host if request.client else "unknown", 5)
        except (LookupError, PermissionError):
            raise HTTPException(status_code=404, detail=generic) from None
        return {"download_url": url}
