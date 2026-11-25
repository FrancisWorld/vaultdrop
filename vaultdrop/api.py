import datetime as dt
import hashlib
import secrets
from collections.abc import AsyncIterator

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .config import get_settings
from .database import create_all, session_scope
from .models import AuditEvent, FileRecord, MultipartUpload, ShareLink
from .s3 import S3Service

app = FastAPI(title="VaultDrop", version="0.1.0")
app.add_middleware(
    __import__("fastapi.middleware.cors", fromlist=["CORSMiddleware"]).CORSMiddleware,
    allow_origins=get_settings().cors_origins.split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

passwords = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=2)
s3 = S3Service()


def owner_id(x_user_id: str | None = Header(default=None, alias="X-User-ID")) -> str:
    return x_user_id or "local-user"


class InitiateRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0, le=10 * 1024 * 1024 * 1024)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    part_size: int = Field(default=8 * 1024 * 1024, ge=5 * 1024 * 1024, le=100 * 1024 * 1024)


class InitiateResponse(BaseModel):
    upload_id: str
    s3_key: str
    part_size: int
    part_count: int
    urls: list[dict[str, int | str]]


class CompleteRequest(BaseModel):
    parts: list[dict[str, int | str]] = Field(min_length=1)


class ShareRequest(BaseModel):
    password: str | None = Field(default=None, max_length=256)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=30 * 86400)
    max_downloads: int | None = Field(default=None, ge=1, le=100000)


class ShareResponse(BaseModel):
    token: str
    url: str


def audit(db: object, actor: str, action: str, resource: str, detail: str) -> None:
    from sqlalchemy.orm import Session

    assert isinstance(db, Session)
    db.add(AuditEvent(actor_id=actor, action=action, resource_id=resource, detail=detail))


@app.on_event("startup")
def startup() -> None:
    create_all()
    s3.ensure_bucket()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/uploads", response_model=InitiateResponse)
def initiate(body: InitiateRequest, actor: str = Depends(owner_id)) -> InitiateResponse:
    with session_scope() as db:
        used = db.scalar(
            select(func.coalesce(func.sum(FileRecord.size_bytes), 0)).where(FileRecord.owner_id == actor)
        )
        used = int(used or 0)
        if used + body.size_bytes > get_settings().default_quota_bytes:
            raise HTTPException(status_code=413, detail="Per-user quota exceeded")

        key = f"{actor}/{secrets.token_hex(16)}-{body.filename}"
        upload_id = s3.create_multipart(key, body.filename)
        expires = dt.datetime.now(dt.UTC) + dt.timedelta(hours=24)
        record = MultipartUpload(
            owner_id=actor,
            upload_id=upload_id,
            s3_key=key,
            filename=body.filename,
            size_bytes=body.size_bytes,
            sha256=body.sha256,
            expires_at=expires,
        )
        db.add(record)
        db.flush()

        count = max(1, (body.size_bytes + body.part_size - 1) // body.part_size)
        urls = [
            {"part_number": part, "url": s3.presign_part(key, upload_id, part)}
            for part in range(1, count + 1)
        ]
        audit(db, actor, "upload.initiated", record.id, f"Created multipart upload {key}")
        return InitiateResponse(
            upload_id=record.id,
            s3_key=key,
            part_size=body.part_size,
            part_count=count,
            urls=urls,
        )


@app.post("/v1/uploads/{upload_id}/complete")
def complete(upload_id: str, body: CompleteRequest, actor: str = Depends(owner_id)) -> dict[str, str]:
    with session_scope() as db:
        record = db.get(MultipartUpload, upload_id)
        if not record or record.owner_id != actor or record.status != "active":
            raise HTTPException(status_code=404, detail="Upload not found")
        parts: list[dict[str, int | str]] = [
            {"PartNumber": int(part["part_number"]), "ETag": str(part["etag"])}
            for part in body.parts
        ]
        s3.complete_multipart(record.s3_key, record.upload_id, parts)

        digest = hashlib.sha256()
        stream = s3.download_stream(record.s3_key)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        stream.close()
        actual = digest.hexdigest()
        if actual != record.sha256:
            s3.abort_multipart(record.s3_key, record.upload_id)
            record.status = "failed"
            audit(db, actor, "upload.checksum_failed", record.id, "SHA-256 mismatch")
            raise HTTPException(status_code=422, detail="SHA-256 checksum mismatch")

        head = s3.head(record.s3_key)
        size = int(head.get("ContentLength", record.size_bytes))
        file_record = FileRecord(
            owner_id=actor,
            s3_key=record.s3_key,
            filename=record.filename,
            size_bytes=size,
            sha256=actual,
        )
        db.add(file_record)
        record.status = "complete"
        db.flush()
        audit(db, actor, "upload.completed", file_record.id, f"Stored {record.filename}")
        return {"file_id": file_record.id, "sha256": actual}


@app.delete("/v1/uploads/{upload_id}", status_code=204)
def abort(upload_id: str, actor: str = Depends(owner_id)) -> Response:
    with session_scope() as db:
        record = db.get(MultipartUpload, upload_id)
        if not record or record.owner_id != actor or record.status != "active":
            raise HTTPException(status_code=404, detail="Upload not found")
        s3.abort_multipart(record.s3_key, record.upload_id)
        record.status = "aborted"
        audit(db, actor, "upload.aborted", record.id, "Multipart upload aborted")
    return Response(status_code=204)


@app.get("/v1/files")
def files(actor: str = Depends(owner_id)) -> list[dict[str, object]]:
    with session_scope() as db:
        rows = db.scalars(select(FileRecord).where(FileRecord.owner_id == actor).order_by(FileRecord.created_at.desc()))
        return [
            {
                "id": row.id,
                "filename": row.filename,
                "size_bytes": row.size_bytes,
                "sha256": row.sha256,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.post("/v1/files/{file_id}/shares", response_model=ShareResponse)
def create_share(
    file_id: str, body: ShareRequest, actor: str = Depends(owner_id)
) -> ShareResponse:
    with session_scope() as db:
        file_record = db.get(FileRecord, file_id)
        if not file_record or file_record.owner_id != actor:
            raise HTTPException(status_code=404, detail="File not found")
        token = secrets.token_urlsafe(32)
        password_hash = passwords.hash(body.password) if body.password else None
        expires = (
            dt.datetime.now(dt.UTC) + dt.timedelta(seconds=body.expires_in_seconds)
            if body.expires_in_seconds
            else None
        )
        share = ShareLink(
            file_id=file_id,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            password_hash=password_hash,
            expires_at=expires,
            max_downloads=body.max_downloads,
        )
        db.add(share)
        db.flush()
        audit(db, actor, "share.created", share.id, f"Created share for {file_id}")
    return ShareResponse(token=token, url=f"/s/{token}")


@app.get("/v1/shares")
def shares(actor: str = Depends(owner_id)) -> list[dict[str, object]]:
    with session_scope() as db:
        rows = db.scalars(
            select(ShareLink)
            .join(FileRecord, ShareLink.file_id == FileRecord.id)
            .where(FileRecord.owner_id == actor)
            .order_by(ShareLink.created_at.desc())
        )
        return [
            {
                "id": row.id,
                "file_id": row.file_id,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "downloads": row.downloads,
                "max_downloads": row.max_downloads,
                "password_protected": row.password_hash is not None,
            }
            for row in rows
        ]


@app.get("/s/{token}")
def redeem_share(token: str, password: str | None = Query(default=None)) -> dict[str, str]:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with session_scope() as db:
        candidates = db.scalars(select(ShareLink).where(ShareLink.token_hash == token_hash))
        share = next(candidates, None)
        if not share:
            raise HTTPException(status_code=404, detail="Share not found")
        now = dt.datetime.now(dt.UTC)
        if share.expires_at and share.expires_at <= now:
            raise HTTPException(status_code=410, detail="Share expired")
        if share.max_downloads is not None and share.downloads >= share.max_downloads:
            raise HTTPException(status_code=410, detail="Download limit reached")
        if share.password_hash:
            if not password:
                raise HTTPException(status_code=401, detail="Password required")
            try:
                passwords.verify(share.password_hash, password)
            except VerifyMismatchError as exc:
                raise HTTPException(status_code=401, detail="Invalid password") from exc
        file_record = db.get(FileRecord, share.file_id)
        if not file_record:
            raise HTTPException(status_code=404, detail="Shared file not found")
        share.downloads += 1
        audit(db, "anonymous", "share.downloaded", share.id, f"Redeemed share {share.id}")
        url = s3.presigned_download(file_record.s3_key, file_record.filename)
        return {"download_url": url}


@app.post("/v1/uploads/stale/abort")
def abort_stale(actor: str = Depends(owner_id)) -> dict[str, int]:
    count = 0
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(hours=24)
    with session_scope() as db:
        stale = db.scalars(
            select(MultipartUpload).where(
                MultipartUpload.owner_id == actor,
                MultipartUpload.status == "active",
                MultipartUpload.created_at < cutoff,
            )
        )
        for record in stale:
            s3.abort_multipart(record.s3_key, record.upload_id)
            record.status = "aborted"
            audit(db, actor, "upload.stale_aborted", record.id, "Aborted stale multipart upload")
            count += 1
    return {"aborted": count}


@app.get("/v1/audit")
def audit_list(actor: str = Depends(owner_id)) -> list[dict[str, object]]:
    with session_scope() as db:
        rows = db.scalars(
            select(AuditEvent).where(AuditEvent.actor_id.in_([actor, "anonymous"]))
            .order_by(AuditEvent.created_at.desc())
            .limit(500)
        )
        return [
            {
                "id": row.id,
                "action": row.action,
                "resource_id": row.resource_id,
                "detail": row.detail,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


@app.get("/v1/audit/events")
async def audit_events(actor: str = Depends(owner_id)) -> StreamingResponse:
    async def stream() -> AsyncIterator[str]:
        last_id = ""
        while True:
            with session_scope() as db:
                rows = db.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.actor_id.in_([actor, "anonymous"]))
                    .order_by(AuditEvent.created_at.desc())
                    .limit(20)
                )
                for row in rows:
                    if row.id != last_id:
                        yield f"data: {row.action} {row.resource_id}\n\n"
                        last_id = row.id
                        break
            import asyncio

            await asyncio.sleep(2)

    return StreamingResponse(stream(), media_type="text/event-stream")


app.mount("/", StaticFiles(directory="static", html=True), name="static")
