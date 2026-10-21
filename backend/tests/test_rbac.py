from __future__ import annotations

from fastapi import HTTPException


def test_viewer_permission_matrix() -> None:
    from app.organizations.rbac import (
        OrganizationRole,
        Permission,
        role_has_permission,
    )

    allowed = {
        Permission.ORGANIZATION_READ,
        Permission.TARGET_READ,
        Permission.ASSESSMENT_READ,
        Permission.FINDING_READ,
        Permission.REPORT_READ,
    }

    for permission in Permission:
        assert (
            role_has_permission(
                OrganizationRole.VIEWER,
                permission,
            )
            is (permission in allowed)
        )


def test_analyst_permission_matrix() -> None:
    from app.organizations.rbac import (
        OrganizationRole,
        Permission,
        role_has_permission,
    )

    allowed = {
        Permission.ORGANIZATION_READ,
        Permission.TARGET_READ,
        Permission.TARGET_CREATE,
        Permission.TARGET_VERIFY,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_CANCEL,
        Permission.ASSESSMENT_LIFECYCLE,
        Permission.FINDING_READ,
        Permission.FINDING_MANAGE,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
        Permission.REPORT_LIFECYCLE,
    }

    for permission in Permission:
        assert (
            role_has_permission(
                OrganizationRole.ANALYST,
                permission,
            )
            is (permission in allowed)
        )


def test_admin_receives_every_permission() -> None:
    from app.organizations.rbac import (
        OrganizationRole,
        Permission,
        role_has_permission,
    )

    for permission in Permission:
        assert role_has_permission(
            OrganizationRole.ADMIN,
            permission,
        )


def test_unknown_role_fails_closed() -> None:
    from app.organizations.rbac import (
        Permission,
        permissions_for_role,
        role_has_permission,
    )

    assert permissions_for_role(
        "owner"
    ) == frozenset()

    assert not role_has_permission(
        "owner",
        Permission.TARGET_READ,
    )


def test_require_permission_returns_403() -> None:
    from app.organizations.rbac import (
        OrganizationRole,
        Permission,
        require_permission,
    )

    class Context:
        role = OrganizationRole.VIEWER

    try:
        require_permission(
            Context(),
            Permission.TARGET_CREATE,
        )
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError(
            "Viewer mutation must fail closed."
        )
