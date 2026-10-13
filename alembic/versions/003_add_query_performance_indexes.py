"""add query performance indexes

Revision ID: 003
Revises: 002
Create Date: 2026-10-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = [idx["name"] for idx in inspector.get_indexes("scan_jobs")]

    if "ix_scan_jobs_user_id_created_at" not in existing_indexes:
        op.create_index(
            "ix_scan_jobs_user_id_created_at",
            "scan_jobs",
            ["user_id", "created_at"],
        )
    if "ix_scan_jobs_created_at" not in existing_indexes:
        op.create_index(
            "ix_scan_jobs_created_at",
            "scan_jobs",
            ["created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = [idx["name"] for idx in inspector.get_indexes("scan_jobs")]

    if "ix_scan_jobs_user_id_created_at" in existing_indexes:
        op.drop_index("ix_scan_jobs_user_id_created_at", table_name="scan_jobs")
