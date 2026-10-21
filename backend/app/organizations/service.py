from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.user import User
from app.organizations.rbac import OrganizationRole


def list_user_memberships(
    database: Session,
    user_id: UUID,
) -> list[OrganizationMembership]:
    return list(
        database.scalars(
            select(OrganizationMembership)
            .where(OrganizationMembership.user_id == user_id)
            .order_by(
                OrganizationMembership.created_at.asc(),
                OrganizationMembership.id.asc(),
            )
        )
    )


def get_user_membership(
    database: Session,
    user_id: UUID,
    organization_id: UUID | None = None,
) -> OrganizationMembership | None:
    statement = select(OrganizationMembership).where(
        OrganizationMembership.user_id == user_id
    )

    if organization_id is not None:
        statement = statement.where(
            OrganizationMembership.organization_id == organization_id
        )
    else:
        statement = statement.order_by(
            OrganizationMembership.created_at.asc(),
            OrganizationMembership.id.asc(),
        )

    return database.scalar(statement.limit(1))


def personal_workspace_slug(user_id: UUID) -> str:
    return "workspace-" f"{user_id.hex[:20]}"


def create_personal_organization(
    database: Session,
    user: User,
    *,
    role: OrganizationRole | str,
    name: str | None = None,
) -> tuple[Organization, OrganizationMembership]:
    existing = get_user_membership(database, user.id)

    if existing is not None:
        raise ValueError(
            "User already belongs to an organization."
        )

    normalized_role = OrganizationRole(role)
    requested_name = (
        name if name is not None else f"{user.full_name} Workspace"
    )
    normalized_name = (
        " ".join(requested_name.strip().split())
        or "BEACON Workspace"
    )[:150]

    organization = Organization(
        name=normalized_name,
        slug=personal_workspace_slug(user.id),
    )
    database.add(organization)
    database.flush()

    membership = OrganizationMembership(
        organization_id=organization.id,
        user_id=user.id,
        role=normalized_role.value,
    )
    database.add(membership)
    database.flush()

    return organization, membership
