"""initial VaultDrop schema

Revision ID: 20261125
Revises:
"""
from alembic import op

revision = "20261125"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    from vaultdrop.database import Base
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    from vaultdrop.database import Base
    Base.metadata.drop_all(bind=bind)
