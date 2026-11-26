import datetime as dt
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..database import Database
from ..errors import (
    Conflict,
    Gone,
    Invalid,
    NotFound,
    QuotaExceeded,
    StorageUnavailable,
    Unauthorized,
)
from ..integrity import hash_parts
from ..models import (
    FileRecord,
    MultipartPart,
    MultipartUpload,
    UploadStatus,
    as_utc,
    utcnow,
)
from ..planning import part_count, part_length
from ..repositories import find_upload, lock_user, user_usage
from ..s3 import S3Service, UploadGone
from .audit import audit

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PartRef:
    part_number: int
    etag: str


@dataclass
class UploadTicket:
    upload_id: str
    part_size: int
    part_count: int
    expires_at: dt.datetime
    urls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class UploadStatusView:
    upload_id: str
    status: str
    part_size: int
    part_count: int
    recorded: list[MultipartPart]
    stored: list[dict[str, Any]]
    pending_urls: list[dict[str, Any]]


def normalize_etag(etag: str) -> str:
    return etag.strip().strip('"')


class UploadService:
    def __init__(self, database: Database, s3: S3Service, settings: Settings) -> None:
        self.database = database
        self.s3 = s3
        self.settings = settings

    # -- initiation ---------------------------------------------------------------------

    def initiate(
        self,
        user_id: str,
        *,
        filename: str,
        size_bytes: int,
        sha256: str | None,
        part_size: int,
        idempotency_key: str | None = None,
    ) -> UploadTicket:
        try:
            part_count(size_bytes, part_size)
        except ValueError as error:
            raise Invalid(str(error)) from error

        with self.database.session() as db:
            user = lock_user(db, user_id)  # serialises quota checks per user
            if user is None:
                raise Unauthorized("Authentication required")
            if idempotency_key:
                existing = db.scalar(
                    select(MultipartUpload).where(
                        MultipartUpload.owner_id == user_id,
                        MultipartUpload.idempotency_key == idempotency_key,
                    )
                )
                if existing:
                    return self._replay(existing, filename, size_bytes, sha256, part_size)
            if user_usage(db, user_id) + size_bytes > user.quota_bytes:
                raise QuotaExceeded("Per-user quota exceeded")

            key = f"{user_id}/{secrets.token_hex(16)}"
            storage_upload_id = self.s3.create_multipart(key)
            record = MultipartUpload(
                owner_id=user_id,
                upload_id=storage_upload_id,
                s3_key=key,
                filename=filename,
                size_bytes=size_bytes,
                sha256=sha256,
                part_size=part_size,
                reserved_bytes=size_bytes,
                idempotency_key=idempotency_key,
                expires_at=utcnow() + dt.timedelta(hours=self.settings.upload_ttl_hours),
            )
            try:
                db.add(record)
                db.flush()
                audit(db, user_id, "upload.initiated", record.id, f"Reserved {size_bytes} bytes")
                db.commit()
            except Exception:
                self._abort_quietly(record)
                raise
            return self._ticket(record, range(1, part_count(size_bytes, part_size) + 1))

    def _replay(
        self,
        existing: MultipartUpload,
        filename: str,
        size_bytes: int,
        sha256: str | None,
        part_size: int,
    ) -> UploadTicket:
        same = (existing.filename, existing.size_bytes, existing.sha256, existing.part_size) == (
            filename,
            size_bytes,
            sha256,
            part_size,
        )
        if not same:
            raise Conflict("Idempotency key was used with different parameters")
        if existing.status != UploadStatus.ACTIVE or as_utc(existing.expires_at) <= utcnow():
            raise Conflict("Idempotency key belongs to an upload that is no longer active")
        return self._ticket(
            existing, range(1, part_count(existing.size_bytes, existing.part_size) + 1)
        )

    def _ticket(self, record: MultipartUpload, numbers: range | list[int]) -> UploadTicket:
        return UploadTicket(
            upload_id=record.id,
            part_size=record.part_size,
            part_count=part_count(record.size_bytes, record.part_size),
            expires_at=as_utc(record.expires_at),
            urls=self._urls(record, numbers),
        )

    def _urls(self, record: MultipartUpload, numbers: range | list[int]) -> list[dict[str, Any]]:
        return [
            {
                "part_number": number,
                "url": self.s3.presign_part(record.s3_key, record.upload_id, number),
            }
            for number in numbers
        ]

    def _abort_quietly(self, record: MultipartUpload) -> None:
        try:
            self.s3.abort_multipart(record.s3_key, record.upload_id)
        except StorageUnavailable:
            log.warning("could not abort orphaned multipart upload %s", record.s3_key)

    # -- resume -------------------------------------------------------------------------

    def status(self, user_id: str, upload_id: str) -> UploadStatusView:
        with self.database.session() as db:
            record = find_upload(db, upload_id, user_id)
            if record is None:
                raise NotFound("Upload not found")
            recorded = list(
                db.scalars(
                    select(MultipartPart)
                    .where(MultipartPart.upload_id == record.id)
                    .order_by(MultipartPart.part_number)
                )
            )
            count = part_count(record.size_bytes, record.part_size)
            stored: list[dict[str, Any]] = []
            pending: list[dict[str, Any]] = []
            live = record.status == UploadStatus.ACTIVE and as_utc(record.expires_at) > utcnow()
            if live:
                try:
                    stored = self.s3.list_parts(record.s3_key, record.upload_id)
                except UploadGone:
                    raise Gone("Upload no longer exists in storage") from None
                have = {
                    int(part["PartNumber"])
                    for part in stored
                    if int(part["Size"])
                    == part_length(record.size_bytes, record.part_size, int(part["PartNumber"]))
                }  # a part of the wrong size must be uploaded again
                pending = self._urls(record, [n for n in range(1, count + 1) if n not in have])
            return UploadStatusView(
                record.id, str(record.status), record.part_size, count, recorded, stored, pending
            )

    def record_part(
        self,
        user_id: str,
        upload_id: str,
        part_number: int,
        etag: str,
        size_bytes: int,
        sha256: str,
    ) -> bool:
        """Record a part's digest after verifying storage really holds it.

        Returns True if newly recorded, False if it was already recorded identically.
        """
        etag = normalize_etag(etag)
        with self.database.session() as db:
            record = self._active(db, user_id, upload_id)
            count = part_count(record.size_bytes, record.part_size)
            if not 1 <= part_number <= count:
                raise Invalid("Invalid part number")
            if size_bytes != part_length(record.size_bytes, record.part_size, part_number):
                raise Invalid("Part size does not match the upload plan")
            existing = db.scalar(
                select(MultipartPart).where(
                    MultipartPart.upload_id == record.id, MultipartPart.part_number == part_number
                )
            )
            if existing:
                if existing.etag != etag or existing.sha256 != sha256:
                    raise Conflict("Part already recorded differently")
                return False
            try:
                stored = self.s3.get_part(record.s3_key, record.upload_id, part_number)
            except UploadGone:
                raise Gone("Upload no longer exists in storage") from None
            if stored is None:
                raise Invalid("Part has not been uploaded to storage")
            if normalize_etag(str(stored["ETag"])) != etag or int(stored["Size"]) != size_bytes:
                raise Invalid("Part does not match what storage holds")
            db.add(
                MultipartPart(
                    upload_id=record.id,
                    part_number=part_number,
                    etag=etag,
                    size_bytes=size_bytes,
                    sha256=sha256,
                )
            )
            audit(db, user_id, "upload.part_recorded", record.id, f"Recorded part {part_number}")
            return True

    def _active(self, db: Session, user_id: str, upload_id: str) -> MultipartUpload:
        record = find_upload(db, upload_id, user_id, lock=True)
        if record is None:
            raise NotFound("Upload not found")
        if record.status != UploadStatus.ACTIVE:
            raise Conflict(f"Upload is {record.status}")
        if as_utc(record.expires_at) <= utcnow():
            raise Gone("Upload expired")
        return record

    # -- completion ---------------------------------------------------------------------

    def complete(self, user_id: str, upload_id: str, parts: list[PartRef]) -> FileRecord:
        with self.database.session() as db:
            record = find_upload(db, upload_id, user_id, lock=True)
            if record is None:
                raise NotFound("Upload not found")
            if record.status == UploadStatus.COMPLETE:
                finished = db.scalar(select(FileRecord).where(FileRecord.s3_key == record.s3_key))
                if finished is None:
                    raise NotFound("Completed file not found")
                return finished  # idempotent retry
            if record.status != UploadStatus.ACTIVE:
                raise Conflict(f"Upload is {record.status}")
            if as_utc(record.expires_at) <= utcnow():
                raise Gone("Upload expired")

            supplied = self._validate_parts(db, record, parts)
            assembled = self._assemble(db, record, supplied)
            if not assembled:
                raise Gone("Upload no longer exists in storage")
            return self._verify_and_publish(db, record)

    def _validate_parts(
        self, db: Session, record: MultipartUpload, parts: list[PartRef]
    ) -> dict[int, str]:
        count = part_count(record.size_bytes, record.part_size)
        if sorted(p.part_number for p in parts) != list(range(1, count + 1)):
            raise Invalid(f"Parts must be exactly 1..{count} with no duplicates")
        supplied = {p.part_number: normalize_etag(p.etag) for p in parts}
        recorded = {
            part.part_number: part
            for part in db.scalars(
                select(MultipartPart).where(MultipartPart.upload_id == record.id)
            )
        }
        if record.sha256 is None and len(recorded) != count:
            raise Invalid("No integrity data: record every part digest or declare sha256")
        for number, part in recorded.items():
            if supplied[number] != part.etag:
                raise Invalid(f"ETag for part {number} differs from the recorded one")
        return supplied

    def _assemble(self, db: Session, record: MultipartUpload, supplied: dict[int, str]) -> bool:
        """Ask storage to assemble the object. Returns False if the upload vanished."""
        try:
            stored = {
                int(p["PartNumber"]): p for p in self.s3.list_parts(record.s3_key, record.upload_id)
            }
            for number, etag in supplied.items():
                held = stored.get(number)
                if held is None:
                    raise Invalid(f"Part {number} has not been uploaded")
                expected = part_length(record.size_bytes, record.part_size, number)
                if int(held["Size"]) != expected or normalize_etag(str(held["ETag"])) != etag:
                    raise Invalid(f"Part {number} does not match the upload plan")
            self.s3.complete_multipart(
                record.s3_key,
                record.upload_id,
                [{"PartNumber": n, "ETag": f'"{e}"'} for n, e in sorted(supplied.items())],
            )
        except UploadGone:
            # A previous attempt may have assembled the object and died before committing.
            if self.s3.object_size(record.s3_key) is None:
                self._mark(db, record, UploadStatus.FAILED, "upload.vanished", "Upload vanished")
                db.commit()
                return False
        return True

    def _verify_and_publish(self, db: Session, record: MultipartUpload) -> FileRecord:
        whole, part_digests, total = hash_parts(
            self.s3.stream_object(record.s3_key), record.part_size
        )
        recorded = {
            p.part_number: p.sha256
            for p in db.scalars(select(MultipartPart).where(MultipartPart.upload_id == record.id))
        }
        problem: str | None = None
        if total != record.size_bytes:
            problem = f"size {total} != declared {record.size_bytes}"
        elif record.sha256 is not None and whole != record.sha256:
            problem = "SHA-256 mismatch"
        else:
            for number, digest in recorded.items():
                if part_digests[number - 1] != digest:
                    problem = f"SHA-256 mismatch in part {number}"
                    break
        if problem:
            try:
                self.s3.delete_object(record.s3_key)
            except StorageUnavailable:
                log.error("could not delete unverified object %s", record.s3_key)
            self._mark(db, record, UploadStatus.FAILED, "upload.verification_failed", problem)
            db.commit()  # persist the failure; the exception below would roll it back
            raise Invalid(f"Integrity check failed: {problem}")

        file_record = FileRecord(
            owner_id=record.owner_id,
            s3_key=record.s3_key,
            filename=record.filename,
            size_bytes=total,
            sha256=whole,
        )
        db.add(file_record)
        record.status = UploadStatus.COMPLETE
        record.reserved_bytes = 0
        db.flush()
        audit(db, record.owner_id, "upload.completed", file_record.id, f"Stored {record.filename}")
        return file_record

    @staticmethod
    def _mark(
        db: Session, record: MultipartUpload, status: UploadStatus, action: str, detail: str
    ) -> None:
        record.status = status
        record.reserved_bytes = 0
        audit(db, record.owner_id, action, record.id, detail)

    # -- abort / sweep ------------------------------------------------------------------

    def abort(self, user_id: str, upload_id: str) -> None:
        with self.database.session() as db:
            record = find_upload(db, upload_id, user_id, lock=True)
            if record is None:
                raise NotFound("Upload not found")
            if record.status == UploadStatus.COMPLETE:
                raise Conflict("Upload already completed")
            if record.status != UploadStatus.ACTIVE:
                return  # already aborted or failed: abort is idempotent
            self.s3.abort_multipart(record.s3_key, record.upload_id)
            self._mark(db, record, UploadStatus.ABORTED, "upload.aborted", "Aborted by owner")

    def sweep_expired(self, owner_id: str | None = None, batch: int = 100) -> int:
        """Abort uploads past their TTL and release their quota reservation."""
        swept = 0
        while True:
            with self.database.session() as db:
                stmt = (
                    select(MultipartUpload)
                    .where(
                        MultipartUpload.status == UploadStatus.ACTIVE,
                        MultipartUpload.expires_at <= utcnow(),
                    )
                    .limit(batch)
                    .with_for_update(skip_locked=True)
                )
                if owner_id:
                    stmt = stmt.where(MultipartUpload.owner_id == owner_id)
                expired = list(db.scalars(stmt))
                for record in expired:
                    self.s3.abort_multipart(record.s3_key, record.upload_id)
                    self._mark(
                        db, record, UploadStatus.ABORTED, "upload.expired", "Swept after TTL"
                    )
            swept += len(expired)
            if len(expired) < batch:
                return swept
