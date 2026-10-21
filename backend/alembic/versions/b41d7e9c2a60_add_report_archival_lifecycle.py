"""add report archival lifecycle

Revision ID: b41d7e9c2a60
Revises: 9a7c2f6e8d41
Create Date: 2026-08-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b41d7e9c2a60"
down_revision: str | None = "9a7c2f6e8d41"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column(
            "archived_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_reports_archived_at"),
        "reports",
        ["archived_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_reports_archived_at"),
        table_name="reports",
    )
    op.drop_column(
        "reports",
        "archived_at",
    )
