from __future__ import annotations

import inspect
import re

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.routers import assessments as assessments
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

    return Session(
        engine,
        expire_on_commit=False,
    )


def seed():
    database = make_database()

    admin_a = User(
        email="admin-a@example.test",
        full_name="Admin A",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    analyst_a = User(
        email="analyst-a@example.test",
        full_name="Analyst A",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    admin_b = User(
        email="admin-b@example.test",
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
            admin_b,
        ]
    )
    database.flush()

    org_a = Organization(
        name="Organization A",
        slug="organization-a",
    )

    org_b = Organization(
        name="Organization B",
        slug="organization-b",
    )

    database.add_all(
        [
            org_a,
            org_b,
        ]
    )
    database.flush()

    database.add_all(
        [
            OrganizationMembership(
                organization_id=org_a.id,
                user_id=admin_a.id,
                role="admin",
            ),
            OrganizationMembership(
                organization_id=org_a.id,
                user_id=analyst_a.id,
                role="analyst",
            ),
            OrganizationMembership(
                organization_id=org_b.id,
                user_id=admin_b.id,
                role="admin",
            ),
        ]
    )

    target_a = Target(
        organization_id=org_a.id,
        user_id=admin_a.id,
        original_url="https://a.example.test",
        normalized_url="https://a.example.test/",
        hostname="a.example.test",
        verification_method="file",
        verification_status="verified",
    )

    target_b = Target(
        organization_id=org_b.id,
        user_id=admin_b.id,
        original_url="https://b.example.test",
        normalized_url="https://b.example.test/",
        hostname="b.example.test",
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
        organization_id=org_a.id,
        user_id=admin_a.id,
        target_id=target_a.id,
        scan_level="basic",
        status="completed",
        progress=100,
    )

    assessment_a = Scan(
        organization_id=org_a.id,
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
            assessment_a,
        ]
    )
    database.flush()

    return {
        "database": database,
        "admin_a": admin_a,
        "analyst_a": analyst_a,
        "admin_b": admin_b,
        "target_a": target_a,
        "target_b": target_b,
        "scan_a": scan_a,
        "assessment_a": assessment_a,
    }


def test_same_org_analyst_can_read_target_created_by_admin() -> None:
    state = seed()

    try:
        result = targets.get_owned_target(
            target_id=state["target_a"].id,
            current_user=state["analyst_a"],
            database=state["database"],
        )

        assert result.id == state["target_a"].id

    finally:
        state["database"].close()


def test_cross_org_target_is_hidden_as_404() -> None:
    state = seed()

    try:
        try:
            targets.get_owned_target(
                target_id=state["target_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        except HTTPException as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError(
                "Cross-org target must be hidden."
            )

    finally:
        state["database"].close()


def test_same_org_analyst_can_read_scan_created_by_admin() -> None:
    state = seed()

    try:
        result = scans.get_owned_scan(
            scan_id=state["scan_a"].id,
            current_user=state["analyst_a"],
            database=state["database"],
        )

        assert result.id == state["scan_a"].id

    finally:
        state["database"].close()


def test_cross_org_scan_is_hidden_as_404() -> None:
    state = seed()

    try:
        try:
            scans.get_owned_scan(
                scan_id=state["scan_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        except HTTPException as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError(
                "Cross-org scan must be hidden."
            )

    finally:
        state["database"].close()


def test_same_org_analyst_can_read_assessment_created_by_admin() -> None:
    state = seed()

    try:
        result = assessments._get_owned_assessment(
            assessment_id=state["assessment_a"].id,
            current_user=state["analyst_a"],
            database=state["database"],
        )

        assert (
            result.id
            == state["assessment_a"].id
        )

    finally:
        state["database"].close()


def test_cross_org_assessment_is_hidden_as_404() -> None:
    state = seed()

    try:
        try:
            assessments._get_owned_assessment(
                assessment_id=state["assessment_a"].id,
                current_user=state["admin_b"],
                database=state["database"],
            )
        except HTTPException as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError(
                "Cross-org assessment must be hidden."
            )

    finally:
        state["database"].close()


def compact_source(module) -> str:
    return re.sub(
        r"\s+",
        " ",
        inspect.getsource(module),
    )


def test_operational_routers_no_longer_use_user_as_tenant_boundary() -> None:
    for module in (
        targets,
        scans,
        assessments,
    ):
        source = compact_source(
            module
        )

        assert (
            "Target.user_id == current_user.id"
            not in source
        )

        assert (
            "Scan.user_id == current_user.id"
            not in source
        )


def test_operational_routers_reference_central_permissions() -> None:
    target_source = compact_source(
        targets
    )
    scan_source = compact_source(
        scans
    )
    assessment_source = compact_source(
        assessments
    )

    for permission in (
        "Permission.TARGET_READ",
        "Permission.TARGET_CREATE",
        "Permission.TARGET_VERIFY",
        "Permission.TARGET_DELETE",
    ):
        assert permission in target_source

    for permission in (
        "Permission.ASSESSMENT_READ",
        "Permission.ASSESSMENT_CREATE",
        "Permission.ASSESSMENT_LIFECYCLE",
        "Permission.ASSESSMENT_DELETE",
    ):
        assert permission in scan_source

    for permission in (
        "Permission.ASSESSMENT_READ",
        "Permission.ASSESSMENT_CREATE",
        "Permission.ASSESSMENT_CANCEL",
    ):
        assert permission in assessment_source


def test_new_operational_resources_persist_org_and_actor() -> None:
    target_source = compact_source(
        targets
    )
    scan_source = compact_source(
        scans
    )
    assessment_source = compact_source(
        assessments
    )

    assert (
        "organization_id=context.organization.id"
        in target_source
    )
    assert (
        "user_id=current_user.id"
        in target_source
    )

    assert (
        "organization_id=context.organization.id"
        in scan_source
    )

    assert (
        "organization_id=context.organization.id"
        in assessment_source
    )
