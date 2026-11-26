"""initial VaultDrop schema

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _id() -> sa.Column[str]:
    return sa.Column("id", sa.String(36), primary_key=True)


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "users",
        _id(),
        sa.Column("username", sa.String(128), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger, nullable=False),
        _ts("created_at"),
    )
    op.create_table(
        "sessions",
        _id(),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        _ts("created_at"),
        _ts("expires_at"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_table(
        "multipart_uploads",
        _id(),
        sa.Column(
            "owner_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("upload_id", sa.String(512), nullable=False),
        sa.Column("s3_key", sa.String(512), nullable=False, unique=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("part_size", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        _ts("created_at"),
        _ts("expires_at"),
        sa.Column("reserved_bytes", sa.BigInteger, nullable=False),
        sa.UniqueConstraint("owner_id", "idempotency_key", name="uq_upload_idempotency"),
    )
    op.create_index("ix_multipart_uploads_owner_id", "multipart_uploads", ["owner_id"])
    op.create_index("ix_upload_status_expiry", "multipart_uploads", ["status", "expires_at"])
    op.create_table(
        "multipart_parts",
        _id(),
        sa.Column(
            "upload_id",
            sa.String(36),
            sa.ForeignKey("multipart_uploads.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("part_number", sa.Integer, nullable=False),
        sa.Column("etag", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        _ts("uploaded_at"),
        sa.UniqueConstraint("upload_id", "part_number", name="uq_multipart_part"),
    )
    op.create_index("ix_multipart_parts_upload_id", "multipart_parts", ["upload_id"])
    op.create_table(
        "files",
        _id(),
        sa.Column(
            "owner_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("s3_key", sa.String(512), nullable=False, unique=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        _ts("created_at"),
    )
    op.create_index("ix_files_owner_id", "files", ["owner_id"])
    op.create_table(
        "share_links",
        _id(),
        sa.Column(
            "file_id", sa.String(36), sa.ForeignKey("files.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=True),
        _ts("expires_at", nullable=True),
        sa.Column("max_downloads", sa.Integer, nullable=True),
        sa.Column("downloads", sa.Integer, nullable=False),
        _ts("created_at"),
    )
    op.create_index("ix_share_links_file_id", "share_links", ["file_id"])
    op.create_table(
        "attempt_log",
        _id(),
        sa.Column("scope", sa.String(96), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        _ts("attempted_at"),
    )
    op.create_index("ix_attempt_lookup", "attempt_log", ["scope", "key_hash", "attempted_at"])
    op.create_table(
        "audit_events",
        _id(),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("detail", sa.Text, nullable=False),
        _ts("created_at"),
    )
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_resource_id", "audit_events", ["resource_id"])


def downgrade() -> None:
    for table in (
        "audit_events",
        "attempt_log",
        "share_links",
        "files",
        "multipart_parts",
        "multipart_uploads",
        "sessions",
        "users",
    ):
        op.drop_table(table)
