from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
)
from sqlalchemy import (
    func,
    select,
    update,
)
from sqlalchemy.orm import Session

from app.auth.mail_tasks import (
    send_organization_invitation_email,
)
from app.database import (
    get_database_session,
)
from app.dependencies.auth import (
    CurrentPrincipal,
    CurrentUser,
)
from app.models.audit_log import (
    AuditLog,
)
from app.models.auth_session import AuthSession
from app.models.organization import (
    Organization,
)
from app.models.organization_invitation import (
    OrganizationInvitation,
)
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.context import (
    resolve_organization_context,
)
from app.organizations.invitations import (
    InvitationError,
    accept_invitation,
    create_invitation as create_invitation_row,
    resolve_invitation,
    revoke_invitation,
)
from app.organizations.rbac import (
    OrganizationRole,
    Permission,
    require_permission,
)
from app.schemas.organizations import (
    ActiveOrganizationRequest,
    InvitationAcceptRequest,
    InvitationCreateRequest,
    InvitationResolveResponse,
    InvitationResponse,
    MemberResponse,
    MemberRoleUpdateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
)
from app.organizations.service import (
    get_user_membership,
)
from app.security.demo import (
    is_demo_user,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["Organizations"],
)


DatabaseSession = Annotated[
    Session,
    Depends(
        get_database_session
    ),
]


def _forbid_demo_admin(
    current_user: User,
) -> None:
    if is_demo_user(
        current_user
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Demo organization administration "
                "is disabled."
            ),
        )


def _record_audit(
    database: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    action: str,
    details: dict | None = None,
) -> None:
    database.add(
        AuditLog(
            organization_id=(
                organization_id
            ),
            user_id=user_id,
            target_id=None,
            scan_id=None,
            action=action,
            details=details,
        )
    )


def _organization_response(
    context,
) -> OrganizationResponse:
    return OrganizationResponse(
        id=context.organization.id,
        name=context.organization.name,
        slug=context.organization.slug,
        role=context.role.value,
        created_at=(
            context.organization
            .created_at
        ),
        updated_at=(
            context.organization
            .updated_at
        ),
    )


def _organization_membership_response(
    organization: Organization,
    membership: OrganizationMembership,
) -> OrganizationResponse:
    return OrganizationResponse(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        role=membership.role,
        created_at=organization.created_at,
        updated_at=organization.updated_at,
    )


def _member_response(
    membership: OrganizationMembership,
    user: User,
) -> MemberResponse:
    return MemberResponse(
        membership_id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        created_at=membership.created_at,
    )


def _invitation_response(
    invitation: OrganizationInvitation,
) -> InvitationResponse:
    return InvitationResponse(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        expires_at=invitation.expires_at,
        accepted_at=invitation.accepted_at,
        revoked_at=invitation.revoked_at,
        created_at=invitation.created_at,
    )


def _get_membership(
    database: Session,
    *,
    organization_id: UUID,
    membership_id: UUID,
) -> OrganizationMembership:
    membership = database.scalar(
        select(
            OrganizationMembership
        ).where(
            OrganizationMembership.id
            == membership_id,
            OrganizationMembership.organization_id
            == organization_id,
        )
    )

    if membership is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Member not found.",
        )

    return membership


def _get_invitation(
    database: Session,
    *,
    organization_id: UUID,
    invitation_id: UUID,
) -> OrganizationInvitation:
    invitation = database.scalar(
        select(
            OrganizationInvitation
        ).where(
            OrganizationInvitation.id
            == invitation_id,
            OrganizationInvitation.organization_id
            == organization_id,
        )
    )

    if invitation is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Invitation not found.",
        )

    return invitation


def _admin_count(
    database: Session,
    organization_id: UUID,
) -> int:
    return int(
        database.scalar(
            select(
                func.count()
            ).select_from(
                OrganizationMembership
            ).where(
                OrganizationMembership.organization_id
                == organization_id,
                OrganizationMembership.role
                == OrganizationRole.ADMIN.value,
            )
        )
        or 0
    )


def _protect_final_admin(
    database: Session,
    membership: OrganizationMembership,
    *,
    replacement_role: OrganizationRole | None,
) -> None:
    if (
        membership.role
        != OrganizationRole.ADMIN.value
    ):
        return

    if (
        replacement_role
        is OrganizationRole.ADMIN
    ):
        return

    if (
        _admin_count(
            database,
            membership.organization_id,
        )
        <= 1
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "The final Admin cannot be "
                "removed or demoted."
            ),
        )


@router.get(
    "/organizations",
    response_model=list[OrganizationResponse],
)
def list_organizations(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> list[OrganizationResponse]:
    rows = database.execute(
        select(
            OrganizationMembership,
            Organization,
        )
        .join(
            Organization,
            OrganizationMembership.organization_id
            == Organization.id,
        )
        .where(
            OrganizationMembership.user_id
            == current_user.id
        )
        .order_by(
            Organization.name.asc(),
            Organization.id.asc(),
        )
    ).all()

    return [
        _organization_membership_response(
            organization,
            membership,
        )
        for membership, organization in rows
    ]


@router.post(
    "/organization/active",
    response_model=OrganizationResponse,
)
def set_active_organization(
    request: ActiveOrganizationRequest,
    principal: CurrentPrincipal,
    database: DatabaseSession,
) -> OrganizationResponse:
    if principal.mechanism != "session" or principal.session_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active organization persistence requires a browser session.",
        )

    membership = get_user_membership(
        database,
        principal.user.id,
        request.organization_id,
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership is required.",
        )

    organization = database.get(Organization, request.organization_id)
    session_row = database.get(AuthSession, principal.session_id)
    if organization is None or session_row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership is invalid.",
        )

    session_row.active_organization_id = organization.id
    _record_audit(
        database,
        organization_id=organization.id,
        user_id=principal.user.id,
        action="organization.context.selected",
        details={"session_id": str(session_row.id)},
    )
    database.commit()
    database.refresh(session_row)
    return _organization_membership_response(organization, membership)


@router.get(
    "/organization",
    response_model=OrganizationResponse,
)
def read_organization(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> OrganizationResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ORGANIZATION_READ,
    )

    return _organization_response(
        context
    )


@router.patch(
    "/organization",
    response_model=OrganizationResponse,
)
def update_organization(
    request: OrganizationUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> OrganizationResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ORGANIZATION_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    context.organization.name = (
        request.name
    )

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.settings.updated"
        ),
        details=None,
    )

    database.commit()

    database.refresh(
        context.organization
    )

    return _organization_response(
        context
    )


@router.get(
    "/organization/members",
    response_model=list[MemberResponse],
)
def list_members(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> list[MemberResponse]:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ORGANIZATION_READ,
    )

    rows = database.execute(
        select(
            OrganizationMembership,
            User,
        )
        .join(
            User,
            OrganizationMembership.user_id
            == User.id,
        )
        .where(
            OrganizationMembership.organization_id
            == context.organization.id,
        )
        .order_by(
            User.email.asc()
        )
    ).all()

    return [
        _member_response(
            membership,
            user,
        )
        for membership, user in rows
    ]


@router.patch(
    "/organization/members/{membership_id}",
    response_model=MemberResponse,
)
def update_member(
    membership_id: UUID,
    request: MemberRoleUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> MemberResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    membership = _get_membership(
        database,
        organization_id=(
            context.organization.id
        ),
        membership_id=membership_id,
    )

    _protect_final_admin(
        database,
        membership,
        replacement_role=request.role,
    )

    membership.role = (
        request.role.value
    )

    user = database.get(
        User,
        membership.user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Member not found.",
        )

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.member.role_changed"
        ),
        details={
            "membership_id":
                str(
                    membership.id
                ),
            "role":
                membership.role,
        },
    )

    database.commit()

    database.refresh(
        membership
    )

    return _member_response(
        membership,
        user,
    )


@router.delete(
    "/organization/members/{membership_id}",
    status_code=(
        status.HTTP_204_NO_CONTENT
    ),
)
def delete_member(
    membership_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Response:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    membership = _get_membership(
        database,
        organization_id=(
            context.organization.id
        ),
        membership_id=membership_id,
    )

    _protect_final_admin(
        database,
        membership,
        replacement_role=None,
    )

    removed_user_id = (
        membership.user_id
    )

    database.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == removed_user_id,
            AuthSession.active_organization_id == context.organization.id,
        )
        .values(active_organization_id=None)
    )

    database.delete(
        membership
    )

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.member.removed"
        ),
        details={
            "membership_id":
                str(
                    membership_id
                ),
            "removed_user_id":
                str(
                    removed_user_id
                ),
        },
    )

    database.commit()

    return Response(
        status_code=(
            status.HTTP_204_NO_CONTENT
        )
    )


@router.get(
    "/organization/invitations",
    response_model=list[InvitationResponse],
)
def list_invitations(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> list[InvitationResponse]:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    rows = list(
        database.scalars(
            select(
                OrganizationInvitation
            )
            .where(
                OrganizationInvitation.organization_id
                == context.organization.id,
                OrganizationInvitation.accepted_at
                .is_(None),
                OrganizationInvitation.revoked_at
                .is_(None),
                OrganizationInvitation.expires_at
                > func.now(),
            )
            .order_by(
                OrganizationInvitation
                .created_at
                .desc()
            )
        )
    )

    member_emails = {
        str(email).strip().lower()
        for email in database.scalars(
            select(User.email)
            .join(
                OrganizationMembership,
                OrganizationMembership.user_id
                == User.id,
            )
            .where(
                OrganizationMembership.organization_id
                == context.organization.id
            )
        )
    }

    return [
        _invitation_response(row)
        for row in rows
        if row.email.strip().lower()
        not in member_emails
    ]


@router.post(
    "/organization/invitations",
    response_model=InvitationResponse,
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def create_invitation(
    request: InvitationCreateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> InvitationResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    existing_user = database.scalar(
        select(User).where(
            User.email
            == str(request.email).strip().lower()
        )
    )

    if (
        existing_user is not None
        and get_user_membership(
            database,
            existing_user.id,
            context.organization.id,
        )
        is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That account is already a member of this organization.",
        )

    invitation = (
        create_invitation_row(
            database,
            organization_id=(
                context.organization.id
            ),
            email=str(
                request.email
            ),
            role=request.role,
            invited_by_user_id=(
                current_user.id
            ),
        )
    )

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.invitation.issued"
        ),
        details={
            "invitation_id":
                str(
                    invitation.id
                ),
            "role":
                invitation.role,
        },
    )

    database.commit()

    database.refresh(
        invitation
    )

    try:
        send_organization_invitation_email.delay(
            str(
                invitation.id
            )
        )
    except Exception:
        # Invitation remains available for explicit resend.
        pass

    return _invitation_response(
        invitation
    )


@router.post(
    "/organization/invitations/accept",
    response_model=OrganizationResponse,
)
def accept_invitation_route(
    request: InvitationAcceptRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> OrganizationResponse:
    try:
        organization, membership, invitation = accept_invitation(
            database,
            request.token,
            current_user,
            current_user.email,
        )
    except InvitationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    _record_audit(
        database,
        organization_id=organization.id,
        user_id=current_user.id,
        action="organization.invitation.accepted",
        details={
            "invitation_id": str(invitation.id),
            "membership_id": str(membership.id),
        },
    )

    database.commit()
    database.refresh(membership)

    return _organization_membership_response(
        organization,
        membership,
    )


@router.post(
    "/organization/invitations/{invitation_id}/resend",
    response_model=InvitationResponse,
)
def resend_invitation(
    invitation_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> InvitationResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    invitation = _get_invitation(
        database,
        organization_id=(
            context.organization.id
        ),
        invitation_id=invitation_id,
    )

    if (
        invitation.accepted_at
        is not None
        or invitation.revoked_at
        is not None
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "Invitation is no longer active."
            ),
        )

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.invitation.resent"
        ),
        details={
            "invitation_id":
                str(
                    invitation.id
                )
        },
    )

    database.commit()

    try:
        send_organization_invitation_email.delay(
            str(
                invitation.id
            )
        )
    except Exception:
        pass

    return _invitation_response(
        invitation
    )


@router.delete(
    "/organization/invitations/{invitation_id}",
    status_code=(
        status.HTTP_204_NO_CONTENT
    ),
)
def delete_invitation(
    invitation_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Response:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.MEMBER_MANAGE,
    )

    _forbid_demo_admin(
        current_user
    )

    invitation = _get_invitation(
        database,
        organization_id=(
            context.organization.id
        ),
        invitation_id=invitation_id,
    )

    try:
        revoke_invitation(
            database,
            invitation,
        )
    except InvitationError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(
                exc
            ),
        ) from exc

    _record_audit(
        database,
        organization_id=(
            context.organization.id
        ),
        user_id=current_user.id,
        action=(
            "organization.invitation.revoked"
        ),
        details={
            "invitation_id":
                str(
                    invitation.id
                )
        },
    )

    database.commit()

    return Response(
        status_code=(
            status.HTTP_204_NO_CONTENT
        )
    )


@router.get(
    "/organization/invitations/resolve",
    response_model=InvitationResolveResponse,
)
def resolve_invitation_route(
    token: str,
    database: DatabaseSession,
) -> InvitationResolveResponse:
    try:
        invitation = resolve_invitation(
            database,
            token,
        )
    except InvitationError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=(
                "Invalid or expired invitation."
            ),
        ) from exc

    organization = database.get(
        Organization,
        invitation.organization_id,
    )

    if organization is None:
        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=(
                "Invalid or expired invitation."
            ),
        )

    return InvitationResolveResponse(
        invitation_id=(
            invitation.id
        ),
        organization_id=(
            organization.id
        ),
        organization_name=(
            organization.name
        ),
        email=invitation.email,
        role=invitation.role,
        expires_at=(
            invitation.expires_at
        ),
    )
