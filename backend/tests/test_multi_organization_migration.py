from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]
MIGRATION = (
    BACKEND
    / "alembic"
    / "versions"
    / "d4a8b61f2e73_enable_multi_organization_memberships.py"
)


def test_multi_organization_membership_migration_replaces_user_uniqueness() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert 'down_revision: str | None = "c91f0d6a4e28"' in source
    assert '"uq_organization_memberships_user_id"' in source
    assert '"uq_organization_memberships_org_user"' in source
    assert '["organization_id", "user_id"]' in source
