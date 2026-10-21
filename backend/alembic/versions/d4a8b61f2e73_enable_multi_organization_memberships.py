"""enable multi organization memberships

Revision ID: d4a8b61f2e73
Revises: c91f0d6a4e28
Create Date: 2026-09-10
"""

from collections.abc import Sequence

from alembic import op


revision: str = "d4a8b61f2e73"
down_revision: str | None = "c91f0d6a4e28"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_organization_memberships_user_id",
        "organization_memberships",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_organization_memberships_org_user",
        "organization_memberships",
        ["organization_id", "user_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_organization_memberships_org_user",
        "organization_memberships",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_organization_memberships_user_id",
        "organization_memberships",
        ["user_id"],
    )
