import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import FileRecord, MultipartUpload, UploadStatus, User, utcnow


def user_usage(db: Session, user_id: str, now: dt.datetime | None = None) -> int:
    """Bytes stored plus bytes reserved by live (unexpired) multipart uploads."""
    now = now or utcnow()
    completed = db.scalar(
        select(func.coalesce(func.sum(FileRecord.size_bytes), 0)).where(
            FileRecord.owner_id == user_id
        )
    )
    reserved = db.scalar(
        select(func.coalesce(func.sum(MultipartUpload.reserved_bytes), 0)).where(
            MultipartUpload.owner_id == user_id,
            MultipartUpload.status == UploadStatus.ACTIVE,
            MultipartUpload.expires_at > now,
        )
    )
    return int(completed or 0) + int(reserved or 0)


def lock_user(db: Session, user_id: str) -> User | None:
    return db.scalar(select(User).where(User.id == user_id).with_for_update())


def find_file(db: Session, file_id: str, owner_id: str) -> FileRecord | None:
    return db.scalar(
        select(FileRecord).where(FileRecord.id == file_id, FileRecord.owner_id == owner_id)
    )


def find_upload(
    db: Session, upload_id: str, owner_id: str, *, lock: bool = False
) -> MultipartUpload | None:
    stmt = select(MultipartUpload).where(
        MultipartUpload.id == upload_id, MultipartUpload.owner_id == owner_id
    )
    return db.scalar(stmt.with_for_update() if lock else stmt)
