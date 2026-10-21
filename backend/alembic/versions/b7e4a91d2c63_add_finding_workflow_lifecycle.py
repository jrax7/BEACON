"""add finding workflow lifecycle

Revision ID: b7e4a91d2c63
Revises: 8f2c1d4a7b90
Create Date: 2026-09-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b7e4a91d2c63"
down_revision: str | None = "8f2c1d4a7b90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "lifecycle_state",
            sa.String(length=30),
            server_default="NEW",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_findings_lifecycle_state",
        "findings",
        ["lifecycle_state"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "observation_state",
            sa.String(length=30),
            server_default="NEW",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_findings_observation_state",
        "findings",
        ["observation_state"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "assignee_user_id",
            sa.Uuid(),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_findings_assignee_user_id_users",
        "findings",
        "users",
        ["assignee_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_assignee_user_id",
        "findings",
        ["assignee_user_id"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "remediation_owner_user_id",
            sa.Uuid(),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_findings_remediation_owner_user_id_users",
        "findings",
        "users",
        ["remediation_owner_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_remediation_owner_user_id",
        "findings",
        ["remediation_owner_user_id"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "disposition",
            sa.String(length=30),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_findings_disposition",
        "findings",
        ["disposition"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "disposition_reason",
            sa.Text(),
            nullable=True,
        ),
    )

    op.add_column(
        "findings",
        sa.Column(
            "disposition_set_by_user_id",
            sa.Uuid(),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_findings_disposition_set_by_user_id_users",
        "findings",
        "users",
        ["disposition_set_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_disposition_set_by_user_id",
        "findings",
        ["disposition_set_by_user_id"],
        unique=False,
    )

    op.add_column(
        "findings",
        sa.Column(
            "disposition_set_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.add_column(
        "findings",
        sa.Column(
            "duplicate_of_finding_id",
            sa.Uuid(),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_findings_duplicate_of_finding_id_findings",
        "findings",
        "findings",
        ["duplicate_of_finding_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_duplicate_of_finding_id",
        "findings",
        ["duplicate_of_finding_id"],
        unique=False,
    )

    op.create_table(
        "finding_workflow_events",
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
            "actor_user_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "event_type",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "previous_value",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "new_value",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "reason",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "related_scan_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
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
            ["actor_user_id"],
            ["users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["related_scan_id"],
            ["scans.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    for column in (
        "finding_id",
        "organization_id",
        "actor_user_id",
        "event_type",
        "related_scan_id",
    ):
        op.create_index(
            "ix_finding_workflow_events_" + column,
            "finding_workflow_events",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for column in (
        "related_scan_id",
        "event_type",
        "actor_user_id",
        "organization_id",
        "finding_id",
    ):
        op.drop_index(
            "ix_finding_workflow_events_" + column,
            table_name="finding_workflow_events",
        )

    op.drop_table(
        "finding_workflow_events"
    )

    op.drop_index(
        "ix_findings_duplicate_of_finding_id",
        table_name="findings",
    )
    op.drop_constraint(
        "fk_findings_duplicate_of_finding_id_findings",
        "findings",
        type_="foreignkey",
    )
    op.drop_column(
        "findings",
        "duplicate_of_finding_id",
    )

    op.drop_column(
        "findings",
        "disposition_set_at",
    )

    op.drop_index(
        "ix_findings_disposition_set_by_user_id",
        table_name="findings",
    )
    op.drop_constraint(
        "fk_findings_disposition_set_by_user_id_users",
        "findings",
        type_="foreignkey",
    )
    op.drop_column(
        "findings",
        "disposition_set_by_user_id",
    )

    op.drop_column(
        "findings",
        "disposition_reason",
    )

    op.drop_index(
        "ix_findings_disposition",
        table_name="findings",
    )
    op.drop_column(
        "findings",
        "disposition",
    )

    op.drop_index(
        "ix_findings_remediation_owner_user_id",
        table_name="findings",
    )
    op.drop_constraint(
        "fk_findings_remediation_owner_user_id_users",
        "findings",
        type_="foreignkey",
    )
    op.drop_column(
        "findings",
        "remediation_owner_user_id",
    )

    op.drop_index(
        "ix_findings_assignee_user_id",
        table_name="findings",
    )
    op.drop_constraint(
        "fk_findings_assignee_user_id_users",
        "findings",
        type_="foreignkey",
    )
    op.drop_column(
        "findings",
        "assignee_user_id",
    )

    op.drop_index(
        "ix_findings_observation_state",
        table_name="findings",
    )
    op.drop_column(
        "findings",
        "observation_state",
    )

    op.drop_index(
        "ix_findings_lifecycle_state",
        table_name="findings",
    )
    op.drop_column(
        "findings",
        "lifecycle_state",
    )
