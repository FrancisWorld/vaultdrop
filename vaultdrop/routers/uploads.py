import datetime as dt
import secrets

from fastapi import APIRouter, Cookie, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..auth import verify_session
from ..config import get_settings
from ..database import session_scope
from ..models import MultipartPart, MultipartUpload, User
from ..planning import part_count
from ..repositories import find_upload, user_usage
from ..s3 import S3Service
from ..services import UploadService, audit

router = APIRouter(prefix="/v1/uploads", tags=["uploads"])
s3 = S3Service()
uploads = UploadService(s3)


class InitiateRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0, le=5 * 1024 * 1024 * 1024)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    part_size: int = Field(default=8 * 1024 * 1024, ge=5 * 1024 * 1024, le=100 * 1024 * 1024)


class CompleteRequest(BaseModel):
    parts: list[dict[str, int | str]] = Field(min_length=1)


class PartRequest(BaseModel):
    etag: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def actor(db: Session, session_cookie: str | None) -> User:
    user_id = verify_session(session_cookie or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


@router.post("")
def initiate(body: InitiateRequest, vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, object]:
    with session_scope() as db:
        if get_settings().database_url.startswith("sqlite"):
            db.execute(text("BEGIN IMMEDIATE"))
        user = actor(db, vaultdrop_session)
        db.execute(select(User).where(User.id == user.id).with_for_update())
        if user_usage(db, user.id) + body.size_bytes > user.quota_bytes:
            raise HTTPException(status_code=413, detail="Per-user quota exceeded")
        key = f"{user.id}/{secrets.token_hex(16)}-{body.filename}"
        upload_id = s3.create_multipart(key, body.filename)
        record = MultipartUpload(
            owner_id=user.id,
            upload_id=upload_id,
            s3_key=key,
            filename=body.filename,
            size_bytes=body.size_bytes,
            sha256=body.sha256,
            part_size=body.part_size,
            reserved_bytes=body.size_bytes,
            expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=24),
        )
        db.add(record)
        db.flush()
        count = part_count(body.size_bytes, body.part_size)
        urls = [{"part_number": number, "url": s3.presign_part(key, upload_id, number)} for number in range(1, count + 1)]
        audit(db, user.id, "upload.initiated", record.id, f"Created multipart upload {key}")
        return {"upload_id": record.id, "s3_key": key, "part_size": body.part_size, "part_count": count, "urls": urls}


@router.get("/{upload_id}")
def list_parts(upload_id: str, vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, object]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        record = find_upload(db, upload_id, user.id)
        if not record:
            raise HTTPException(status_code=404, detail="Upload not found")
        known = db.scalars(select(MultipartPart).where(MultipartPart.upload_id == record.id))
        return {
            "upload_id": record.id,
            "status": record.status,
            "parts": [{"part_number": p.part_number, "etag": p.etag, "size_bytes": p.size_bytes, "sha256": p.sha256} for p in known],
            "s3_parts": s3.list_parts(record.s3_key, record.upload_id),
        }


@router.post("/{upload_id}/parts/{part_number}")
def record_part(upload_id: str, part_number: int, body: PartRequest, vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, str]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        record = find_upload(db, upload_id, user.id)
        if not record or record.status != "active":
            raise HTTPException(status_code=404, detail="Upload not found")
        if part_number < 1 or (part_number - 1) * record.part_size >= record.size_bytes:
            raise HTTPException(status_code=422, detail="Invalid part number")
        existing = db.scalar(select(MultipartPart).where(MultipartPart.upload_id == record.id, MultipartPart.part_number == part_number))
        if existing:
            if existing.etag != body.etag.strip('"') or existing.sha256 != body.sha256:
                raise HTTPException(status_code=409, detail="Part already recorded differently")
            return {"status": "already-recorded"}
        db.add(MultipartPart(upload_id=record.id, part_number=part_number, etag=body.etag.strip('"'), size_bytes=body.size_bytes, sha256=body.sha256))
        audit(db, user.id, "upload.part_recorded", record.id, f"Recorded part {part_number}")
        return {"status": "recorded"}


@router.post("/{upload_id}/complete")
def complete(upload_id: str, body: CompleteRequest, vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, str]:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        try:
            file_record, _ = uploads.complete(db, user.id, upload_id, body.parts)
        except LookupError:
            raise HTTPException(status_code=404, detail="Upload not found") from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"file_id": file_record.id, "sha256": file_record.sha256}


@router.delete("/{upload_id}", status_code=204)
def abort(upload_id: str, vaultdrop_session: str | None = Cookie(default=None)) -> None:
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        try:
            uploads.abort(db, user.id, upload_id)
        except LookupError:
            raise HTTPException(status_code=404, detail="Upload not found") from None


@router.post("/stale/abort")
def abort_stale(vaultdrop_session: str | None = Cookie(default=None)) -> dict[str, int]:
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(hours=24)
    with session_scope() as db:
        user = actor(db, vaultdrop_session)
        return {"aborted": uploads.abort_stale(db, user.id, cutoff)}
