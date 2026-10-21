from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from fastapi import (
    HTTPException,
    status,
)


class OrganizationRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(StrEnum):
    ORGANIZATION_READ = "organization:read"
    ORGANIZATION_MANAGE = "organization:manage"
    MEMBER_MANAGE = "member:manage"

    TARGET_READ = "target:read"
    TARGET_CREATE = "target:create"
    TARGET_VERIFY = "target:verify"
    TARGET_DELETE = "target:delete"

    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_CANCEL = "assessment:cancel"
    ASSESSMENT_LIFECYCLE = "assessment:lifecycle"
    ASSESSMENT_DELETE = "assessment:delete"

    FINDING_READ = "finding:read"
    FINDING_MANAGE = "finding:manage"

    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    REPORT_LIFECYCLE = "report:lifecycle"
    REPORT_DELETE = "report:delete"


VIEWER_PERMISSIONS = frozenset(
    {
        Permission.ORGANIZATION_READ,
        Permission.TARGET_READ,
        Permission.ASSESSMENT_READ,
        Permission.FINDING_READ,
        Permission.REPORT_READ,
    }
)


ANALYST_PERMISSIONS = (
    VIEWER_PERMISSIONS
    | frozenset(
        {
            Permission.TARGET_CREATE,
            Permission.TARGET_VERIFY,
            Permission.ASSESSMENT_CREATE,
            Permission.ASSESSMENT_CANCEL,
            Permission.ASSESSMENT_LIFECYCLE,
            Permission.FINDING_MANAGE,
            Permission.REPORT_GENERATE,
            Permission.REPORT_LIFECYCLE,
        }
    )
)


ADMIN_PERMISSIONS = frozenset(
    Permission
)


ROLE_PERMISSIONS = {
    OrganizationRole.VIEWER:
        VIEWER_PERMISSIONS,
    OrganizationRole.ANALYST:
        ANALYST_PERMISSIONS,
    OrganizationRole.ADMIN:
        ADMIN_PERMISSIONS,
}


class RoleContext(Protocol):
    role: OrganizationRole


def permissions_for_role(
    role: OrganizationRole | str,
) -> frozenset[Permission]:
    try:
        normalized = OrganizationRole(
            role
        )
    except (
        TypeError,
        ValueError,
    ):
        return frozenset()

    return ROLE_PERMISSIONS.get(
        normalized,
        frozenset(),
    )


def role_has_permission(
    role: OrganizationRole | str,
    permission: Permission,
) -> bool:
    return (
        permission
        in permissions_for_role(
            role
        )
    )


def require_permission(
    context: RoleContext,
    permission: Permission,
) -> None:
    if role_has_permission(
        context.role,
        permission,
    ):
        return

    raise HTTPException(
        status_code=(
            status.HTTP_403_FORBIDDEN
        ),
        detail=(
            "You do not have permission "
            "to perform this action."
        ),
    )
