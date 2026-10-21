from __future__ import annotations

import importlib.util


def test_finding_retest_model_exists() -> None:
    assert importlib.util.find_spec(
        "app.models.finding_retest"
    ) is not None, (
        "finding_retest model does not exist yet."
    )


def test_finding_retest_model_contract() -> None:
    from app.models.finding_retest import (
        FindingRetest,
    )

    table = FindingRetest.__table__

    assert table.name == "finding_retests"

    assert {
        "id",
        "finding_id",
        "organization_id",
        "requested_by_user_id",
        "status",
        "scan_id",
        "requested_at",
        "completed_at",
    } <= set(
        table.c.keys()
    )

    assert table.c.finding_id.nullable is False
    assert table.c.organization_id.nullable is False
    assert (
        table.c.requested_by_user_id.nullable
        is False
    )
    assert table.c.status.nullable is False
    assert table.c.scan_id.nullable is True


def test_terminal_retest_semantics() -> None:
    from app.services.finding_retests import (
        terminal_retest_status,
    )

    assert terminal_retest_status(
        scan_status="cancelled",
        completed_with_warnings=False,
        finding_present=False,
        comparable=True,
    ) == "CANCELLED"

    assert terminal_retest_status(
        scan_status="failed",
        completed_with_warnings=False,
        finding_present=False,
        comparable=True,
    ) == "FAILED"

    assert terminal_retest_status(
        scan_status="completed",
        completed_with_warnings=True,
        finding_present=False,
        comparable=True,
    ) == "FAILED"

    assert terminal_retest_status(
        scan_status="completed",
        completed_with_warnings=False,
        finding_present=True,
        comparable=True,
    ) == "FAILED"

    assert terminal_retest_status(
        scan_status="completed",
        completed_with_warnings=False,
        finding_present=False,
        comparable=True,
    ) == "PASSED"

    assert terminal_retest_status(
        scan_status="completed",
        completed_with_warnings=False,
        finding_present=False,
        comparable=False,
    ) == "FAILED"


def test_retest_api_routes_exist() -> None:
    import app.main as main_module

    paths = main_module.app.openapi()[
        "paths"
    ]

    path = (
        "/api/v1/findings/"
        "{finding_id}/retests"
    )

    assert path in paths
    assert "get" in paths[path]
    assert "post" in paths[path]
