from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import FileRecord, MultipartUpload, ShareLink


def user_usage(db: Session, user_id: str) -> int:
    completed = db.scalar(
        select(func.coalesce(func.sum(FileRecord.size_bytes), 0)).where(
            FileRecord.owner_id == user_id
        )
    )
    reserved = db.scalar(
        select(func.coalesce(func.sum(MultipartUpload.reserved_bytes), 0)).where(
            MultipartUpload.owner_id == user_id,
            MultipartUpload.status == "active",
        )
    )
    return int(completed or 0) + int(reserved or 0)


def find_file(db: Session, file_id: str, owner_id: str) -> FileRecord | None:
    return db.scalar(
        select(FileRecord).where(
            FileRecord.id == file_id, FileRecord.owner_id == owner_id
        )
    )


def find_upload(db: Session, upload_id: str, owner_id: str) -> MultipartUpload | None:
    return db.scalar(
        select(MultipartUpload).where(
            MultipartUpload.id == upload_id, MultipartUpload.owner_id == owner_id
        )
    )


def find_share(db: Session, token_hash: str) -> ShareLink | None:
    return db.scalar(select(ShareLink).where(ShareLink.token_hash == token_hash))
