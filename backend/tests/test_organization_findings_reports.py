from __future__ import annotations

from pathlib import Path
import re


BACKEND = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def read(path: str) -> str:
    return (
        BACKEND
        / path
    ).read_text(
        encoding="utf-8",
    )


def compact(path: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        read(path),
    )


def test_findings_workspace_stops_using_user_as_tenant_boundary() -> None:
    source = compact(
        "app/services/findings_workspace.py"
    )

    assert (
        "Scan.user_id == user_id"
        not in source
    )

    assert (
        "Target.user_id == user_id"
        not in source
    )


def test_findings_workspace_uses_organization_scope() -> None:
    source = read(
        "app/services/findings_workspace.py"
    )

    assert (
        "organization_id"
        in source
    )

    assert (
        "Scan.organization_id"
        in source
        or
        "Target.organization_id"
        in source
    )


def test_findings_router_uses_server_org_context() -> None:
    source = read(
        "app/routers/findings.py"
    )

    assert (
        "resolve_organization_context"
        in source
    )

    assert (
        "context.organization.id"
        in source
    )


def test_findings_router_uses_central_permission() -> None:
    source = read(
        "app/routers/findings.py"
    )

    assert (
        "Permission.FINDING_READ"
        in source
    )

    assert (
        "require_permission"
        in source
    )


def test_reports_stop_using_user_as_tenant_boundary() -> None:
    source = compact(
        "app/routers/reports.py"
    )

    assert (
        "Scan.user_id == current_user.id"
        not in source
    )

    assert (
        "Target.user_id == current_user.id"
        not in source
    )


def test_reports_use_organization_scope() -> None:
    source = read(
        "app/routers/reports.py"
    )

    assert (
        "Scan.organization_id"
        in source
        or
        "Target.organization_id"
        in source
    )


def test_reports_use_central_permissions() -> None:
    source = read(
        "app/routers/reports.py"
    )

    for permission in (
        "Permission.REPORT_READ",
        "Permission.REPORT_GENERATE",
        "Permission.REPORT_LIFECYCLE",
        "Permission.REPORT_DELETE",
    ):
        assert permission in source


def test_report_audits_are_organization_aware() -> None:
    source = compact(
        "app/routers/reports.py"
    )

    assert (
        "organization_id="
        in source
    )
