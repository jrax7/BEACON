from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import (
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    get_user_membership,
)


@dataclass(frozen=True)
class OrganizationContext:
    user: User
    organization: Organization
    membership: OrganizationMembership
    role: OrganizationRole


def resolve_organization_context(
    database: Session,
    user: User,
) -> OrganizationContext:
    requested_organization_id = getattr(
        user,
        "_beacon_organization_id",
        None,
    )

    membership = get_user_membership(
        database,
        user.id,
        requested_organization_id,
    )

    if membership is None and requested_organization_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ORGANIZATION_CONTEXT_INVALID",
                "message": "Selected organization is unavailable.",
            },
        )

    if membership is None:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Organization membership "
                "is required."
            ),
        )

    organization = database.get(
        Organization,
        membership.organization_id,
    )

    if organization is None:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Organization membership "
                "is invalid."
            ),
        )

    try:
        role = OrganizationRole(
            membership.role
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Organization membership "
                "role is invalid."
            ),
        ) from exc

    return OrganizationContext(
        user=user,
        organization=organization,
        membership=membership,
        role=role,
    )


DatabaseSession = Annotated[
    Session,
    Depends(
        get_database_session
    ),
]


def get_current_organization_context(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> OrganizationContext:
    return resolve_organization_context(
        database,
        current_user,
    )


CurrentOrganization = Annotated[
    OrganizationContext,
    Depends(
        get_current_organization_context
    ),
]
