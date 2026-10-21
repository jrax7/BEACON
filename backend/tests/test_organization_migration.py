from __future__ import annotations

from pathlib import Path


BACKEND_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

MIGRATION_PATH = (
    BACKEND_ROOT
    / "alembic"
    / "versions"
    / "8f2c1d4a7b90_add_organization_rbac_tenancy.py"
)


def _source() -> str:
    assert MIGRATION_PATH.exists(), (
        "Phase 16C organization migration does not exist yet"
    )

    return MIGRATION_PATH.read_text(
        encoding="utf-8",
    )


def test_revision_chain_is_exact() -> None:
    source = _source()

    assert (
        'revision: str = "8f2c1d4a7b90"'
        in source
    )
    assert (
        'down_revision: str | None = "4fd8c3a1e972"'
        in source
    )


def test_migration_creates_org_tenancy_tables() -> None:
    source = _source()

    for table in (
        "organizations",
        "organization_memberships",
        "organization_invitations",
    ):
        assert (
            f'op.create_table(\n        "{table}",'
            in source
        )

    assert "raw_token" not in source


def test_tenant_columns_are_added_nullable_before_backfill() -> None:
    source = _source()

    target_add = source.index(
        '"targets",\n        sa.Column(\n            "organization_id"'
    )
    target_backfill = source.index(
        "UPDATE targets"
    )
    target_not_null = source.index(
        'op.alter_column(\n        "targets",\n        "organization_id"'
    )

    assert (
        target_add
        < target_backfill
        < target_not_null
    )

    scan_add = source.index(
        '"scans",\n        sa.Column(\n            "organization_id"'
    )
    scan_backfill = source.index(
        "UPDATE scans"
    )
    scan_not_null = source.index(
        'op.alter_column(\n        "scans",\n        "organization_id"'
    )

    assert (
        scan_add
        < scan_backfill
        < scan_not_null
    )


def test_migration_backfills_one_org_and_membership_per_user() -> None:
    source = _source()

    assert "workspace-" in source
    assert "INSERT INTO organizations" in source
    assert "INSERT INTO organization_memberships" in source

    assert (
        "WHEN u.role = 'demo' THEN 'analyst'"
        in source
    )
    assert "ELSE 'admin'" in source


def test_migration_backfills_resource_organization_chain() -> None:
    source = _source()

    assert "UPDATE targets" in source
    assert "UPDATE scans" in source
    assert "UPDATE audit_logs" in source

    assert (
        "t.organization_id"
        in source
    )
    assert (
        "organization_memberships"
        in source
    )


def test_migration_validates_before_enforcing_not_null() -> None:
    source = _source()

    validation = source.index(
        "RAISE EXCEPTION"
    )
    not_null = source.index(
        'op.alter_column(\n        "targets",\n        "organization_id"'
    )

    assert validation < not_null
    assert "organization backfill" in source.lower()
    assert "IS DISTINCT FROM" in source


def test_target_uniqueness_moves_from_user_to_org() -> None:
    source = _source()

    assert "uq_targets_user_hostname" in source
    assert "uq_targets_organization_hostname" in source

    upgrade = source.split(
        "def downgrade",
        1,
    )[0]

    assert (
        'op.drop_constraint(\n'
        '        "uq_targets_user_hostname",'
        in upgrade
    )

    assert (
        'op.create_unique_constraint(\n'
        '        "uq_targets_organization_hostname",'
        in upgrade
    )


def test_audit_org_remains_nullable() -> None:
    source = _source()

    assert (
        'op.alter_column(\n'
        '        "audit_logs",\n'
        '        "organization_id"'
        not in source.split(
            "def downgrade",
            1,
        )[0]
    )
