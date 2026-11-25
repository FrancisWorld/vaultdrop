import datetime as dt
import uuid

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class MultipartUpload(Base):
    __tablename__ = "multipart_uploads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(String(128), index=True)
    upload_id: Mapped[str] = mapped_column(String(512), index=True)
    s3_key: Mapped[str] = mapped_column(String(512), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FileRecord(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(String(128), index=True)
    s3_key: Mapped[str] = mapped_column(String(512), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ShareLink(Base):
    __tablename__ = "share_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("files.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_downloads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    downloads: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_id: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(String(128), index=True)
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
