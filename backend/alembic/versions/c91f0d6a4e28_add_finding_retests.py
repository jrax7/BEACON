"""add finding retests

Revision ID: c91f0d6a4e28
Revises: b7e4a91d2c63
Create Date: 2026-09-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c91f0d6a4e28"
down_revision: str | None = "b7e4a91d2c63"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_retests",
        sa.Column(
            "finding_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "requested_by_user_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default="REQUESTED",
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    for column in (
        "finding_id",
        "organization_id",
        "requested_by_user_id",
        "status",
        "scan_id",
    ):
        op.create_index(
            "ix_finding_retests_" + column,
            "finding_retests",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in (
        "scan_id",
        "status",
        "requested_by_user_id",
        "organization_id",
        "finding_id",
    ):
        op.drop_index(
            "ix_finding_retests_" + column,
            table_name="finding_retests",
        )

    op.drop_table(
        "finding_retests"
    )
