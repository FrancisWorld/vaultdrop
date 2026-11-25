import datetime as dt
import hashlib
from typing import cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from .models import (
    AuditEvent,
    FileRecord,
    MultipartPart,
    MultipartUpload,
    ShareLink,
)
from .repositories import find_upload
from .s3 import S3Service


def audit(db: Session, actor: str, action: str, resource: str, detail: str) -> None:
    db.add(AuditEvent(actor_id=actor, action=action, resource_id=resource, detail=detail))


class UploadService:
    def __init__(self, s3: S3Service) -> None:
        self.s3 = s3

    def complete(
        self,
        db: Session,
        owner_id: str,
        upload_id: str,
        parts: list[dict[str, int | str]],
    ) -> tuple[FileRecord, bool]:
        record = find_upload(db, upload_id, owner_id)
        if not record:
            raise LookupError("upload")
        if record.status == "complete":
            existing = db.scalar(
                select(FileRecord).where(FileRecord.s3_key == record.s3_key)
            )
            if existing:
                return existing, True
            raise LookupError("completed file")
        if record.status != "active":
            raise LookupError("upload")

        expected_numbers = range(1, record.size_bytes // record.part_size + 2)
        supplied = {int(part["part_number"]): str(part["etag"]) for part in parts}
        known = {
            part.part_number: part
            for part in db.scalars(
                select(MultipartPart).where(MultipartPart.upload_id == record.id)
            )
        }
        for number in expected_numbers:
            start = (number - 1) * record.part_size
            if start >= record.size_bytes:
                break
            if number not in supplied:
                raise ValueError("missing part")
            if number in known and supplied[number].strip('"') != known[number].etag:
                raise ValueError("part mismatch")

        s3_parts: list[dict[str, int | str]] = [
            {"PartNumber": number, "ETag": supplied[number]}
            for number in sorted(supplied)
        ]
        self.s3.complete_multipart(record.s3_key, record.upload_id, s3_parts)

        digest = hashlib.sha256()
        stream = self.s3.download_stream(record.s3_key)
        try:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        finally:
            stream.close()
        actual = digest.hexdigest()
        if actual != record.sha256:
            self.s3.delete_object(record.s3_key)
            record.status = "failed"
            record.reserved_bytes = 0
            audit(db, owner_id, "upload.checksum_failed", record.id, "SHA-256 mismatch")
            raise ValueError("checksum")

        head = self.s3.head(record.s3_key)
        content_length = head.get("ContentLength")
        size = int(content_length) if isinstance(content_length, (int, str)) else record.size_bytes
        file_record = FileRecord(
            owner_id=owner_id,
            s3_key=record.s3_key,
            filename=record.filename,
            size_bytes=size,
            sha256=actual,
        )
        db.add(file_record)
        record.status = "complete"
        record.reserved_bytes = 0
        db.flush()
        audit(db, owner_id, "upload.completed", file_record.id, f"Stored {record.filename}")
        return file_record, False

    def abort(self, db: Session, owner_id: str, upload_id: str) -> bool:
        record = find_upload(db, upload_id, owner_id)
        if not record:
            raise LookupError("upload")
        if record.status == "aborted":
            return True
        if record.status != "active":
            raise LookupError("upload")
        self.s3.abort_multipart(record.s3_key, record.upload_id)
        record.status = "aborted"
        record.reserved_bytes = 0
        audit(db, owner_id, "upload.aborted", record.id, "Multipart upload aborted")
        return True

    def abort_stale(self, db: Session, owner_id: str, cutoff: dt.datetime) -> int:
        count = 0
        stale = db.scalars(
            select(MultipartUpload).where(
                MultipartUpload.owner_id == owner_id,
                MultipartUpload.status == "active",
                MultipartUpload.created_at < cutoff,
            )
        )
        for record in stale:
            self.s3.abort_multipart(record.s3_key, record.upload_id)
            record.status = "aborted"
            record.reserved_bytes = 0
            audit(db, owner_id, "upload.stale_aborted", record.id, "Aborted stale multipart upload")
            count += 1
        return count


class ShareService:
    def __init__(self, s3: S3Service) -> None:
        self.s3 = s3

    def redeem(
        self,
        db: Session,
        token: str,
        password: str | None,
        password_attempt_key: str,
        attempt_limit: int,
    ) -> str:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        share = db.scalar(select(ShareLink).where(ShareLink.token_hash == token_hash))
        now = dt.datetime.now(dt.UTC)
        generic = "Share unavailable"
        if not share:
            raise LookupError(generic)
        expires = share.expires_at
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.UTC)
        if expires and expires <= now:
            raise LookupError(generic)
        if share.max_downloads is not None and share.downloads >= share.max_downloads:
            raise LookupError(generic)

        if share.password_hash:
            from .auth import verify_password

            if not password:
                raise PermissionError(generic)
            if not verify_password(share.password_hash, password):
                raise PermissionError(generic)

        file_record = db.get(FileRecord, share.file_id)
        if not file_record:
            raise LookupError(generic)
        claimed = cast(
            CursorResult[tuple[object, ...]],
            db.execute(
                update(ShareLink)
                .where(
                    ShareLink.id == share.id,
                    (ShareLink.max_downloads.is_(None))
                    | (ShareLink.downloads < ShareLink.max_downloads),
                )
                .values(downloads=ShareLink.downloads + 1)
            ),
        )
        if claimed.rowcount != 1:
            raise LookupError(generic)
        audit(db, "anonymous", "share.downloaded", share.id, f"Redeemed share {share.id}")
        return self.s3.presigned_download(file_record.s3_key, file_record.filename)
