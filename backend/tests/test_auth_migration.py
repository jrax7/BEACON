from __future__ import annotations

from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]

MIGRATION_PATH = (
    BACKEND_ROOT
    / "alembic"
    / "versions"
    / "4fd8c3a1e972_add_auth_session_lifecycle.py"
)

def _migration_source() -> str:
    assert MIGRATION_PATH.exists(), (
        "Phase 16B auth migration does not exist yet"
    )

    return MIGRATION_PATH.read_text(
        encoding="utf-8",
    )


def test_auth_migration_has_expected_revision_chain() -> None:
    source = _migration_source()

    assert 'revision: str = "4fd8c3a1e972"' in source
    assert 'down_revision: str | None = "e6a1c4b92f37"' in source


def test_auth_migration_creates_exact_auth_lifecycle_tables() -> None:
    source = _migration_source()

    for table in (
        "auth_sessions",
        "email_verification_tokens",
        "password_reset_tokens",
    ):
        assert f'op.create_table(\n        "{table}",' in source

    assert "raw_token" not in source


def test_auth_migration_grandfathers_existing_users_as_verified() -> None:
    source = _migration_source()

    assert "UPDATE users" in source
    assert "SET is_email_verified = true" in source
    assert "WHERE is_email_verified = false" in source


def test_auth_migration_downgrade_does_not_reverse_grandfathering() -> None:
    source = _migration_source()

    downgrade = source.split(
        "def downgrade",
        1,
    )[1]

    assert "is_email_verified" not in downgrade


def test_auth_migration_does_not_modify_phase16a_domain_tables() -> None:
    source = _migration_source()

    forbidden_operations = (
        'op.add_column("targets"',
        'op.add_column("scans"',
        'op.add_column("findings"',
        'op.drop_column("targets"',
        'op.drop_column("scans"',
        'op.drop_column("findings"',
    )

    assert not any(
        operation in source
        for operation in forbidden_operations
    )
