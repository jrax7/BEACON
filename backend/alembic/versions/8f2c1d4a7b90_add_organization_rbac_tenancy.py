"""add organization RBAC tenancy

Revision ID: 8f2c1d4a7b90
Revises: 4fd8c3a1e972
Create Date: 2026-09-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "8f2c1d4a7b90"
down_revision: str | None = "4fd8c3a1e972"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Introduce organizations and safely backfill legacy ownership."""

    # -----------------------------------------------------------------
    # Organizations
    # -----------------------------------------------------------------

    op.create_table(
        "organizations",
        sa.Column(
            "name",
            sa.String(length=150),
            nullable=False,
        ),
        sa.Column(
            "slug",
            sa.String(length=160),
            nullable=False,
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_organizations_slug",
        "organizations",
        ["slug"],
        unique=True,
    )


    # -----------------------------------------------------------------
    # Memberships
    # -----------------------------------------------------------------

    op.create_table(
        "organization_memberships",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "role",
            sa.String(length=30),
            server_default="viewer",
            nullable=False,
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
        sa.UniqueConstraint(
            "user_id",
            name="uq_organization_memberships_user_id",
        ),
    )

    op.create_index(
        "ix_organization_memberships_organization_id",
        "organization_memberships",
        ["organization_id"],
        unique=False,
    )

    op.create_index(
        "ix_organization_memberships_user_id",
        "organization_memberships",
        ["user_id"],
        unique=False,
    )


    # -----------------------------------------------------------------
    # Invitations
    # -----------------------------------------------------------------

    op.create_table(
        "organization_invitations",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "email",
            sa.String(length=320),
            nullable=False,
        ),
        sa.Column(
            "role",
            sa.String(length=30),
            nullable=False,
        ),
        sa.Column(
            "invited_by_user_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "token_hash",
            sa.CHAR(length=64),
            nullable=True,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "accepted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(timezone=True),
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
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_organization_invitations_organization_id",
        "organization_invitations",
        ["organization_id"],
        unique=False,
    )

    op.create_index(
        "ix_organization_invitations_email",
        "organization_invitations",
        ["email"],
        unique=False,
    )

    op.create_index(
        "ix_organization_invitations_invited_by_user_id",
        "organization_invitations",
        ["invited_by_user_id"],
        unique=False,
    )

    op.create_index(
        "ix_organization_invitations_token_hash",
        "organization_invitations",
        ["token_hash"],
        unique=True,
    )

    op.create_index(
        "ix_organization_invitations_expires_at",
        "organization_invitations",
        ["expires_at"],
        unique=False,
    )


    # -----------------------------------------------------------------
    # Add tenant columns nullable FIRST.
    # -----------------------------------------------------------------

    op.add_column(
        "targets",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=True,
        ),
    )

    op.create_foreign_key(
        "fk_targets_organization_id_organizations",
        "targets",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.create_index(
        "ix_targets_organization_id",
        "targets",
        ["organization_id"],
        unique=False,
    )


    op.add_column(
        "scans",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=True,
        ),
    )

    op.create_foreign_key(
        "fk_scans_organization_id_organizations",
        "scans",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.create_index(
        "ix_scans_organization_id",
        "scans",
        ["organization_id"],
        unique=False,
    )


    op.add_column(
        "audit_logs",
        sa.Column(
            "organization_id",
            sa.Uuid(),
            nullable=True,
        ),
    )

    op.create_foreign_key(
        "fk_audit_logs_organization_id_organizations",
        "audit_logs",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_index(
        "ix_audit_logs_organization_id",
        "audit_logs",
        ["organization_id"],
        unique=False,
    )


    # -----------------------------------------------------------------
    # Create one isolated workspace per existing user.
    #
    # Reusing a user's UUID for its migration-created organization and
    # membership is safe because each table has an independent PK space.
    # -----------------------------------------------------------------

    op.execute(
        sa.text(
            """
            INSERT INTO organizations (
                id,
                name,
                slug,
                created_at,
                updated_at
            )
            SELECT
                u.id,
                LEFT(
                    CASE
                        WHEN BTRIM(u.full_name) = ''
                            THEN 'BEACON Workspace'
                        ELSE
                            BTRIM(u.full_name) ||
                            ' Workspace'
                    END,
                    150
                ),
                'workspace-' ||
                    SUBSTRING(
                        REPLACE(
                            CAST(u.id AS text),
                            '-',
                            ''
                        )
                        FROM 1 FOR 20
                    ),
                now(),
                now()
            FROM users AS u
            """
        )
    )


    op.execute(
        sa.text(
            """
            INSERT INTO organization_memberships (
                id,
                organization_id,
                user_id,
                role,
                created_at,
                updated_at
            )
            SELECT
                u.id,
                u.id,
                u.id,
                CASE
                    WHEN u.role = 'demo' THEN 'analyst'
                    ELSE 'admin'
                END,
                now(),
                now()
            FROM users AS u
            """
        )
    )


    # -----------------------------------------------------------------
    # Backfill top-level resources.
    # -----------------------------------------------------------------

    op.execute(
        sa.text(
            """
            UPDATE targets AS t
            SET organization_id = m.organization_id
            FROM organization_memberships AS m
            WHERE
                t.user_id = m.user_id
                AND t.organization_id IS NULL
            """
        )
    )


    op.execute(
        sa.text(
            """
            UPDATE scans AS s
            SET organization_id = t.organization_id
            FROM targets AS t
            WHERE
                s.target_id = t.id
                AND s.organization_id IS NULL
            """
        )
    )


    # -----------------------------------------------------------------
    # Audit organization is nullable, but derive it whenever trusted
    # persisted resource/actor linkage exists.
    # -----------------------------------------------------------------

    op.execute(
        sa.text(
            """
            UPDATE audit_logs AS a
            SET organization_id = s.organization_id
            FROM scans AS s
            WHERE
                a.scan_id = s.id
                AND a.organization_id IS NULL
            """
        )
    )


    op.execute(
        sa.text(
            """
            UPDATE audit_logs AS a
            SET organization_id = t.organization_id
            FROM targets AS t
            WHERE
                a.target_id = t.id
                AND a.organization_id IS NULL
            """
        )
    )


    op.execute(
        sa.text(
            """
            UPDATE audit_logs AS a
            SET organization_id = m.organization_id
            FROM organization_memberships AS m
            WHERE
                a.user_id = m.user_id
                AND a.organization_id IS NULL
            """
        )
    )


    # -----------------------------------------------------------------
    # Fail closed before making top-level tenancy NOT NULL.
    # -----------------------------------------------------------------

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1
                    FROM users AS u
                    LEFT JOIN organization_memberships AS m
                        ON m.user_id = u.id
                    WHERE m.id IS NULL
                ) THEN
                    RAISE EXCEPTION
                        'Phase 16C organization backfill: '
                        'user without membership';
                END IF;

                IF EXISTS (
                    SELECT 1
                    FROM targets
                    WHERE organization_id IS NULL
                ) THEN
                    RAISE EXCEPTION
                        'Phase 16C organization backfill: '
                        'target without organization';
                END IF;

                IF EXISTS (
                    SELECT 1
                    FROM scans
                    WHERE organization_id IS NULL
                ) THEN
                    RAISE EXCEPTION
                        'Phase 16C organization backfill: '
                        'scan without organization';
                END IF;

                IF EXISTS (
                    SELECT 1
                    FROM scans AS s
                    JOIN targets AS t
                        ON t.id = s.target_id
                    WHERE
                        s.organization_id
                        IS DISTINCT FROM
                        t.organization_id
                ) THEN
                    RAISE EXCEPTION
                        'Phase 16C organization backfill: '
                        'scan/target mismatch';
                END IF;
            END
            $$;
            """
        )
    )


    # -----------------------------------------------------------------
    # Final top-level tenant constraints.
    # -----------------------------------------------------------------

    op.alter_column(
        "targets",
        "organization_id",
        existing_type=sa.Uuid(),
        nullable=False,
    )

    op.alter_column(
        "scans",
        "organization_id",
        existing_type=sa.Uuid(),
        nullable=False,
    )


    # -----------------------------------------------------------------
    # Organization owns hostname uniqueness.
    # -----------------------------------------------------------------

    op.drop_constraint(
        "uq_targets_user_hostname",
        "targets",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_targets_organization_hostname",
        "targets",
        [
            "organization_id",
            "hostname",
        ],
    )


def downgrade() -> None:
    """Remove Phase 16C tenancy and restore legacy uniqueness."""

    op.drop_constraint(
        "uq_targets_organization_hostname",
        "targets",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_targets_user_hostname",
        "targets",
        [
            "user_id",
            "hostname",
        ],
    )


    op.drop_index(
        "ix_audit_logs_organization_id",
        table_name="audit_logs",
    )

    op.drop_constraint(
        "fk_audit_logs_organization_id_organizations",
        "audit_logs",
        type_="foreignkey",
    )

    op.drop_column(
        "audit_logs",
        "organization_id",
    )


    op.drop_index(
        "ix_scans_organization_id",
        table_name="scans",
    )

    op.drop_constraint(
        "fk_scans_organization_id_organizations",
        "scans",
        type_="foreignkey",
    )

    op.drop_column(
        "scans",
        "organization_id",
    )


    op.drop_index(
        "ix_targets_organization_id",
        table_name="targets",
    )

    op.drop_constraint(
        "fk_targets_organization_id_organizations",
        "targets",
        type_="foreignkey",
    )

    op.drop_column(
        "targets",
        "organization_id",
    )


    op.drop_index(
        "ix_organization_invitations_expires_at",
        table_name="organization_invitations",
    )

    op.drop_index(
        "ix_organization_invitations_token_hash",
        table_name="organization_invitations",
    )

    op.drop_index(
        "ix_organization_invitations_invited_by_user_id",
        table_name="organization_invitations",
    )

    op.drop_index(
        "ix_organization_invitations_email",
        table_name="organization_invitations",
    )

    op.drop_index(
        "ix_organization_invitations_organization_id",
        table_name="organization_invitations",
    )

    op.drop_table(
        "organization_invitations"
    )


    op.drop_index(
        "ix_organization_memberships_user_id",
        table_name="organization_memberships",
    )

    op.drop_index(
        "ix_organization_memberships_organization_id",
        table_name="organization_memberships",
    )

    op.drop_table(
        "organization_memberships"
    )


    op.drop_index(
        "ix_organizations_slug",
        table_name="organizations",
    )

    op.drop_table(
        "organizations"
    )
