"""add scan archival lifecycle

Revision ID: 9a7c2f6e8d41
Revises: 004cf58aecdb
Create Date: 2026-08-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "9a7c2f6e8d41"
down_revision: str | None = "004cf58aecdb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "archived_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_scans_archived_at"),
        "scans",
        ["archived_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_scans_archived_at"),
        table_name="scans",
    )
    op.drop_column(
        "scans",
        "archived_at",
    )
