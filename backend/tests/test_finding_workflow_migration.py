from __future__ import annotations

from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]

MIGRATION = (
    BACKEND
    / "alembic"
    / "versions"
    / "b7e4a91d2c63_add_finding_workflow_lifecycle.py"
)


def test_phase16e_workflow_migration_exists() -> None:
    assert MIGRATION.exists(), (
        "Phase 16E workflow migration does not exist yet."
    )


def test_phase16e_workflow_migration_contract() -> None:
    source = MIGRATION.read_text(
        encoding="utf-8",
    )

    assert 'revision: str = "b7e4a91d2c63"' in source
    assert (
        'down_revision: str | None = "8f2c1d4a7b90"'
        in source
    )

    for token in (
        '"lifecycle_state"',
        '"observation_state"',
        '"assignee_user_id"',
        '"remediation_owner_user_id"',
        '"disposition"',
        '"disposition_reason"',
        '"disposition_set_by_user_id"',
        '"disposition_set_at"',
        '"duplicate_of_finding_id"',
        '"finding_workflow_events"',
    ):
        assert token in source
