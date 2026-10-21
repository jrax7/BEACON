from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]

MIGRATION = (
    BACKEND
    / "alembic"
    / "versions"
    / "c91f0d6a4e28_add_finding_retests.py"
)


def test_finding_retest_migration_exists() -> None:
    assert MIGRATION.exists(), (
        "finding retest migration does not exist yet."
    )


def test_finding_retest_migration_contract() -> None:
    source = MIGRATION.read_text(
        encoding="utf-8",
    )

    assert (
        'revision: str = "c91f0d6a4e28"'
        in source
    )

    assert (
        'down_revision: str | None = "b7e4a91d2c63"'
        in source
    )

    assert '"finding_retests"' in source
    assert '"finding_id"' in source
    assert '"organization_id"' in source
    assert '"requested_by_user_id"' in source
    assert '"scan_id"' in source
    assert '"status"' in source
