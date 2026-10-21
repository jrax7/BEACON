"""persist active organization in browser sessions

Revision ID: f6b1c2d3e4a5
Revises: d4a8b61f2e73
Create Date: 2026-09-10
"""
from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = "f6b1c2d3e4a5"
down_revision: str | None = "d4a8b61f2e73"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    op.add_column(
        "auth_sessions",
        sa.Column("active_organization_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_auth_sessions_active_organization_id_organizations",
        "auth_sessions", "organizations",
        ["active_organization_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index(
        "ix_auth_sessions_active_organization_id",
        "auth_sessions", ["active_organization_id"], unique=False,
    )

def downgrade() -> None:
    op.drop_index("ix_auth_sessions_active_organization_id", table_name="auth_sessions")
    op.drop_constraint(
        "fk_auth_sessions_active_organization_id_organizations",
        "auth_sessions", type_="foreignkey",
    )
    op.drop_column("auth_sessions", "active_organization_id")
