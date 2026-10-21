from __future__ import annotations

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers import assessments
from app.routers import findings
from app.routers import reports
from app.routers import scans
from app.routers import targets


def make_database() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:"
    )

    User.__table__.create(
        engine
    )
    Organization.__table__.create(
        engine
    )
    OrganizationMembership.__table__.create(
        engine
    )
    Target.__table__.create(
        engine
    )
    Scan.__table__.create(
        engine
    )
    Report.__table__.create(
        engine
    )

    return Session(
        engine,
        expire_on_commit=False,
    )


def seed_two_organizations():
    database = make_database()

    admin_a = User(
        email="task7-admin-a@example.test",
        full_name="Admin A",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    analyst_a = User(
        email="task7-analyst-a@example.test",
        full_name="Analyst A",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    viewer_a = User(
        email="task7-viewer-a@example.test",
        full_name="Viewer A",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    admin_b = User(
        email="task7-admin-b@example.test",
        full_name="Admin B",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    database.add_all(
        [
            admin_a,
            analyst_a,
            viewer_a,
            admin_b,
        ]
    )
    database.flush()

    organization_a = Organization(
        name="Organization A",
        slug="task7-organization-a",
    )

    organization_b = Organization(
        name="Organization B",
        slug="task7-organization-b",
    )

    database.add_all(
        [
            organization_a,
            organization_b,
        ]
    )
    database.flush()

    database.add_all(
        [
            OrganizationMembership(
                organization_id=organization_a.id,
                user_id=admin_a.id,
                role="admin",
            ),
            OrganizationMembership(
                organization_id=organization_a.id,
                user_id=analyst_a.id,
                role="analyst",
            ),
            OrganizationMembership(
                organization_id=organization_a.id,
                user_id=viewer_a.id,
                role="viewer",
            ),
            OrganizationMembership(
                organization_id=organization_b.id,
                user_id=admin_b.id,
                role="admin",
            ),
        ]
    )

    target_a = Target(
        organization_id=organization_a.id,
        user_id=admin_a.id,
        original_url="https://task7-a.example.test",
        normalized_url="https://task7-a.example.test/",
        hostname="task7-a.example.test",
        verification_method="file",
        verification_status="verified",
    )

    target_b = Target(
        organization_id=organization_b.id,
        user_id=admin_b.id,
        original_url="https://task7-b.example.test",
        normalized_url="https://task7-b.example.test/",
        hostname="task7-b.example.test",
        verification_method="file",
        verification_status="verified",
    )

    database.add_all(
        [
            target_a,
            target_b,
        ]
    )
    database.flush()

    scan_a = Scan(
        organization_id=organization_a.id,
        user_id=admin_a.id,
        target_id=target_a.id,
        scan_level="basic",
        status="completed",
        progress=100,
    )

    scan_b = Scan(
        organization_id=organization_b.id,
        user_id=admin_b.id,
        target_id=target_b.id,
        scan_level="basic",
        status="completed",
        progress=100,
    )

    assessment_a = Scan(
        organization_id=organization_a.id,
        user_id=admin_a.id,
        target_id=target_a.id,
        scan_level="basic",
        status="completed",
        progress=100,
        profile="quick",
    )

    database.add_all(
        [
            scan_a,
            scan_b,
            assessment_a,
        ]
    )
    database.flush()

    report_a = Report(
        scan_id=scan_a.id,
        format="html",
        file_path=(
            "/tmp/"
            "task7-organization-a-report.html"
        ),
        checksum_sha256="a" * 64,
    )

    database.add(
        report_a
    )
    database.flush()

    finding_a = (
        "task7-finding-a"
    )

    return {
        "database": database,
        "organization_a": organization_a,
        "organization_b": organization_b,
        "admin_a": admin_a,
        "analyst_a": analyst_a,
        "viewer_a": viewer_a,
        "admin_b": admin_b,
        "target_a": target_a,
        "target_b": target_b,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "assessment_a": assessment_a,
        "finding_a": finding_a,
        "report_a": report_a,
    }


@pytest.mark.parametrize(
    "actor_key",
    [
        "admin_a",
        "analyst_a",
        "viewer_a",
    ],
)
def test_same_tenant_users_can_read_admin_created_target(
    actor_key: str,
) -> None:
    state = seed_two_organizations()

    try:
        result = targets.get_owned_target(
            target_id=state["target_a"].id,
            current_user=state[actor_key],
            database=state["database"],
        )

        assert result.id == state["target_a"].id

        assert (
            result.organization_id
            == state["organization_a"].id
        )
    finally:
        state["database"].close()


def test_cross_tenant_target_is_hidden() -> None:
    state = seed_two_organizations()

    try:
        with pytest.raises(
            HTTPException
        ) as exc:
            targets.get_owned_target(
                target_id=state["target_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )

        assert exc.value.status_code == 404
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "actor_key",
    [
        "admin_a",
        "analyst_a",
        "viewer_a",
    ],
)
def test_same_tenant_users_can_read_admin_created_scan(
    actor_key: str,
) -> None:
    state = seed_two_organizations()

    try:
        result = scans.get_owned_scan(
            scan_id=state["scan_a"].id,
            current_user=state[actor_key],
            database=state["database"],
        )

        assert result.id == state["scan_a"].id

        assert (
            result.organization_id
            == state["organization_a"].id
        )
    finally:
        state["database"].close()


def test_cross_tenant_scan_is_hidden() -> None:
    state = seed_two_organizations()

    try:
        with pytest.raises(
            HTTPException
        ) as exc:
            scans.get_owned_scan(
                scan_id=state["scan_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )

        assert exc.value.status_code == 404
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "actor_key",
    [
        "admin_a",
        "analyst_a",
        "viewer_a",
    ],
)
def test_same_tenant_users_can_read_admin_created_assessment(
    actor_key: str,
) -> None:
    state = seed_two_organizations()

    try:
        result = assessments._get_owned_assessment(
            assessment_id=(
                state["assessment_a"].id
            ),
            current_user=state[actor_key],
            database=state["database"],
        )

        assert (
            result.id
            == state["assessment_a"].id
        )

        assert (
            result.organization_id
            == state["organization_a"].id
        )
    finally:
        state["database"].close()


def test_cross_tenant_assessment_is_hidden() -> None:
    state = seed_two_organizations()

    try:
        with pytest.raises(
            HTTPException
        ) as exc:
            assessments._get_owned_assessment(
                assessment_id=(
                    state["assessment_a"].id
                ),
                current_user=state["admin_b"],
                database=state["database"],
            )

        assert exc.value.status_code == 404
    finally:
        state["database"].close()


def test_resource_creator_is_not_the_tenant_boundary() -> None:
    state = seed_two_organizations()

    try:
        target = targets.get_owned_target(
            target_id=state["target_a"].id,
            current_user=state["analyst_a"],
            database=state["database"],
        )

        scan = scans.get_owned_scan(
            scan_id=state["scan_a"].id,
            current_user=state["viewer_a"],
            database=state["database"],
        )

        assert target.user_id == state["admin_a"].id
        assert scan.user_id == state["admin_a"].id

        assert (
            state["analyst_a"].id
            != state["admin_a"].id
        )

        assert (
            state["viewer_a"].id
            != state["admin_a"].id
        )
    finally:
        state["database"].close()


def assert_hidden_as_404(
    operation,
) -> None:
    with pytest.raises(
        HTTPException
    ) as exc:
        operation()

    assert (
        exc.value.status_code
        == 404
    )


@pytest.mark.parametrize(
    "operation_name",
    [
        "delete_target",
        "regenerate_verification_token",
        "verify_target_file",
        "verify_target_dns",
    ],
)
def test_cross_tenant_target_mutations_are_hidden(
    operation_name: str,
) -> None:
    state = seed_two_organizations()

    try:
        operation = getattr(
            targets,
            operation_name,
        )

        assert_hidden_as_404(
            lambda: operation(
                target_id=state["target_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        )
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "operation_name",
    [
        "read_scan",
        "read_scan_summary",
        "list_grouped_issues",
        "list_raw_scan_findings",
        "read_scan_telemetry",
    ],
)
def test_cross_tenant_scan_read_surfaces_are_hidden(
    operation_name: str,
) -> None:
    state = seed_two_organizations()

    try:
        operation = getattr(
            scans,
            operation_name,
        )

        assert_hidden_as_404(
            lambda: operation(
                scan_id=state["scan_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        )
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "operation_name",
    [
        "archive_scan",
        "restore_scan",
        "delete_scan",
    ],
)
def test_cross_tenant_scan_lifecycle_is_hidden(
    operation_name: str,
) -> None:
    state = seed_two_organizations()

    try:
        operation = getattr(
            scans,
            operation_name,
        )

        assert_hidden_as_404(
            lambda: operation(
                scan_id=state["scan_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        )
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "operation_name",
    [
        "read_assessment",
        "cancel_assessment",
    ],
)
def test_cross_tenant_assessment_surfaces_are_hidden(
    operation_name: str,
) -> None:
    state = seed_two_organizations()

    try:
        operation = getattr(
            assessments,
            operation_name,
        )

        assert_hidden_as_404(
            lambda: operation(
                assessment_id=(
                    state["assessment_a"].id
                ),
                current_user=state["admin_b"],
                database=state["database"],
            )
        )
    finally:
        state["database"].close()


def test_cross_tenant_finding_detail_is_hidden(
    monkeypatch,
) -> None:
    state = seed_two_organizations()

    calls = []

    def fake_build_workspace_detail(
        database,
        organization_id,
        finding_id,
    ):
        calls.append(
            (
                database,
                organization_id,
                finding_id,
            )
        )

        # Finding A belongs to Organization A.
        # Organization B's scoped lookup therefore cannot see it.
        assert (
            organization_id
            == state["organization_b"].id
        )

        assert (
            finding_id
            == state["finding_a"]
        )

        return None

    monkeypatch.setattr(
        findings,
        "build_workspace_detail",
        fake_build_workspace_detail,
    )

    try:
        assert_hidden_as_404(
            lambda: findings.get_finding(
                finding_id=state["finding_a"],
                current_user=state["admin_b"],
                database=state["database"],
            )
        )

        assert len(calls) == 1
    finally:
        state["database"].close()


@pytest.mark.parametrize(
    "operation_name",
    [
        "read_report",
        "download_report",
        "archive_report",
        "restore_report",
        "delete_report",
    ],
)
def test_cross_tenant_report_surfaces_are_hidden(
    operation_name: str,
) -> None:
    state = seed_two_organizations()

    try:
        operation = getattr(
            reports,
            operation_name,
        )

        assert_hidden_as_404(
            lambda: operation(
                report_id=state["report_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        )
    finally:
        state["database"].close()


def test_same_tenant_analyst_can_mutate_admin_created_target(
    monkeypatch,
) -> None:
    state = seed_two_organizations()

    monkeypatch.setattr(
        targets,
        "record_audit_event",
        lambda *args, **kwargs:
            None,
    )

    try:
        response = (
            targets
            .regenerate_verification_token(
                target_id=state["target_a"].id,
                current_user=state["analyst_a"],
                database=state["database"],
            )
        )

        assert (
            response.target_id
            == state["target_a"].id
        )

        assert (
            state["target_a"].user_id
            == state["admin_a"].id
        )

        assert (
            state["analyst_a"].id
            != state["admin_a"].id
        )
    finally:
        state["database"].close()


def test_same_tenant_viewer_cannot_mutate_admin_created_target() -> None:
    state = seed_two_organizations()

    try:
        with pytest.raises(
            HTTPException
        ) as exc:
            targets.regenerate_verification_token(
                target_id=state["target_a"].id,
                current_user=state["viewer_a"],
                database=state["database"],
            )

        assert (
            exc.value.status_code
            == 403
        )
    finally:
        state["database"].close()


def test_same_tenant_analyst_cannot_permanently_delete_admin_scan() -> None:
    state = seed_two_organizations()

    try:
        with pytest.raises(
            HTTPException
        ) as exc:
            scans.delete_scan(
                scan_id=state["scan_a"].id,
                current_user=state["analyst_a"],
                database=state["database"],
            )

        assert (
            exc.value.status_code
            == 403
        )
    finally:
        state["database"].close()


def test_same_tenant_viewer_can_read_admin_report() -> None:
    state = seed_two_organizations()

    try:
        response = reports.read_report(
            report_id=state["report_a"].id,
            current_user=state["viewer_a"],
            database=state["database"],
        )

        assert (
            response.id
            == state["report_a"].id
        )
    finally:
        state["database"].close()
