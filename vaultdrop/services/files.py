import logging

from sqlalchemy import select

from ..database import Database
from ..errors import NotFound, StorageUnavailable
from ..models import FileRecord
from ..repositories import find_file
from ..s3 import S3Service
from .audit import audit

log = logging.getLogger(__name__)


class FileService:
    def __init__(self, database: Database, s3: S3Service) -> None:
        self.database = database
        self.s3 = s3

    def list(self, user_id: str) -> list[FileRecord]:
        with self.database.session() as db:
            return list(
                db.scalars(
                    select(FileRecord)
                    .where(FileRecord.owner_id == user_id)
                    .order_by(FileRecord.created_at.desc())
                )
            )

    def delete(self, user_id: str, file_id: str) -> None:
        """Remove the file, its share links and its quota usage, then the stored object.

        Metadata goes first (and commits) so shares stop working immediately; if the
        object delete then fails the object is orphaned and logged, never reachable.
        """
        with self.database.session() as db:
            record = find_file(db, file_id, user_id)
            if record is None:
                raise NotFound("File not found")
            key = record.s3_key
            db.delete(record)  # share_links cascade in the database
            audit(db, user_id, "file.deleted", file_id, f"Deleted {record.filename}")
        try:
            self.s3.delete_object(key)
        except StorageUnavailable:
            log.error("object %s is orphaned: metadata deleted but storage delete failed", key)
