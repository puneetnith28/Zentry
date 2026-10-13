"""add users and scan ownership

Revision ID: 002
Revises: 001
Create Date: 2026-10-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)
    else:
        existing_indexes = [idx["name"] for idx in inspector.get_indexes("users")]
        if "ix_users_email" not in existing_indexes:
            op.create_index("ix_users_email", "users", ["email"], unique=True)

    scan_columns = [col["name"] for col in inspector.get_columns("scan_jobs")]
    if "user_id" not in scan_columns:
        op.add_column(
            "scan_jobs",
            sa.Column(
                "user_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )

    scan_indexes = [idx["name"] for idx in inspector.get_indexes("scan_jobs")]
    if "ix_scan_jobs_user_id" not in scan_indexes:
        op.create_index("ix_scan_jobs_user_id", "scan_jobs", ["user_id"])
    if "ix_scan_jobs_status" not in scan_indexes:
        op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    if "ix_scan_jobs_created_at" not in scan_indexes:
        op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scan_jobs" in inspector.get_table_names():
        scan_indexes = [idx["name"] for idx in inspector.get_indexes("scan_jobs")]
        if "ix_scan_jobs_created_at" in scan_indexes:
            op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
        if "ix_scan_jobs_status" in scan_indexes:
            op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
        if "ix_scan_jobs_user_id" in scan_indexes:
            op.drop_index("ix_scan_jobs_user_id", table_name="scan_jobs")

        scan_columns = [col["name"] for col in inspector.get_columns("scan_jobs")]
        if "user_id" in scan_columns:
            op.drop_column("scan_jobs", "user_id")

    if "users" in inspector.get_table_names():
        op.drop_table("users")
