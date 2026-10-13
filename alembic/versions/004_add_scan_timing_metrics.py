"""add scan timing metrics

Revision ID: 004
Revises: 003
Create Date: 2026-10-13

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = [col["name"] for col in inspector.get_columns("scan_jobs")]

    if "started_at" not in existing_columns:
        op.add_column(
            "scan_jobs",
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "finished_at" not in existing_columns:
        op.add_column(
            "scan_jobs",
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        )
    if "duration_seconds" not in existing_columns:
        op.add_column(
            "scan_jobs",
            sa.Column("duration_seconds", sa.Float(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = [col["name"] for col in inspector.get_columns("scan_jobs")]

    if "duration_seconds" in existing_columns:
        op.drop_column("scan_jobs", "duration_seconds")
    if "finished_at" in existing_columns:
        op.drop_column("scan_jobs", "finished_at")
    if "started_at" in existing_columns:
        op.drop_column("scan_jobs", "started_at")
