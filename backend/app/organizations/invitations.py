from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from hashlib import sha256
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import (
    generate_opaque_token,
)
from app.models.organization import Organization
from app.models.organization_invitation import (
    OrganizationInvitation,
)
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.rbac import (
    OrganizationRole,
)
from app.organizations.service import (
    get_user_membership,
)


INVITATION_LIFETIME = timedelta(
    hours=72
)


class InvitationError(ValueError):
    """Raised for unusable organization invitations."""


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _aware(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def canonical_email(
    value: object,
) -> str:
    return str(
        value
    ).strip().lower()


def invitation_token_hash(
    raw_token: str,
) -> str:
    # Only the sha256 digest is persisted.
    return sha256(
        raw_token.encode(
            "utf-8"
        )
    ).hexdigest()


def create_invitation(
    database: Session,
    *,
    organization_id: UUID,
    email: str,
    role: OrganizationRole | str,
    invited_by_user_id: UUID,
    now: datetime | None = None,
) -> OrganizationInvitation:
    issued_at = (
        now
        if now is not None
        else _utc_now()
    )

    normalized_email = canonical_email(
        email
    )

    normalized_role = OrganizationRole(
        role
    )

    existing = list(
        database.scalars(
            select(
                OrganizationInvitation
            ).where(
                OrganizationInvitation.organization_id
                == organization_id,
                OrganizationInvitation.email
                == normalized_email,
                OrganizationInvitation.accepted_at
                .is_(None),
                OrganizationInvitation.revoked_at
                .is_(None),
            )
        )
    )

    for row in existing:
        row.revoked_at = issued_at
        row.token_hash = None

    invitation = OrganizationInvitation(
        organization_id=organization_id,
        email=normalized_email,
        role=normalized_role.value,
        invited_by_user_id=(
            invited_by_user_id
        ),
        token_hash=None,
        expires_at=(
            issued_at
            + INVITATION_LIFETIME
        ),
        accepted_at=None,
        revoked_at=None,
    )

    database.add(
        invitation
    )

    database.flush()

    return invitation


def issue_invitation_token(
    database: Session,
    invitation: OrganizationInvitation,
    *,
    now: datetime | None = None,
) -> str:
    issued_at = (
        now
        if now is not None
        else _utc_now()
    )

    if (
        invitation.accepted_at
        is not None
        or invitation.revoked_at
        is not None
    ):
        raise InvitationError(
            "Invitation is no longer active."
        )

    raw_token = (
        generate_opaque_token()
    )

    invitation.token_hash = (
        invitation_token_hash(
            raw_token
        )
    )

    invitation.expires_at = (
        issued_at
        + INVITATION_LIFETIME
    )

    database.flush()

    return raw_token


def resolve_invitation(
    database: Session,
    raw_token: str,
    *,
    now: datetime | None = None,
) -> OrganizationInvitation:
    checked_at = (
        now
        if now is not None
        else _utc_now()
    )

    normalized_token = str(
        raw_token
    ).strip()

    if not normalized_token:
        raise InvitationError(
            "Invalid or expired invitation."
        )

    row = database.scalar(
        select(
            OrganizationInvitation
        ).where(
            OrganizationInvitation.token_hash
            == invitation_token_hash(
                normalized_token
            )
        )
    )

    if (
        row is None
        or row.token_hash is None
        or row.accepted_at
        is not None
        or row.revoked_at
        is not None
        or _aware(
            row.expires_at
        )
        <= _aware(
            checked_at
        )
    ):
        raise InvitationError(
            "Invalid or expired invitation."
        )

    return row


def accept_invitation(
    database: Session,
    raw_token: str,
    user: User,
    email: str,
    *,
    now: datetime | None = None,
) -> tuple[
    Organization,
    OrganizationMembership,
    OrganizationInvitation,
]:
    accepted_at = (
        now
        if now is not None
        else _utc_now()
    )

    invitation = resolve_invitation(
        database,
        raw_token,
        now=accepted_at,
    )

    if (
        canonical_email(
            email
        )
        != invitation.email
    ):
        raise InvitationError(
            "Invitation email does not match registration."
        )

    if (
        get_user_membership(
            database,
            user.id,
            invitation.organization_id,
        )
        is not None
    ):
        raise InvitationError(
            "User already belongs to this organization."
        )

    organization = database.get(
        Organization,
        invitation.organization_id,
    )

    if organization is None:
        raise InvitationError(
            "Invitation organization no longer exists."
        )

    role = OrganizationRole(
        invitation.role
    )

    membership = OrganizationMembership(
        organization_id=(
            organization.id
        ),
        user_id=user.id,
        role=role.value,
    )

    database.add(
        membership
    )

    invitation.accepted_at = (
        accepted_at
    )

    # Removing the digest makes replay impossible.
    invitation.token_hash = None

    database.flush()

    return (
        organization,
        membership,
        invitation,
    )


def revoke_invitation(
    database: Session,
    invitation: OrganizationInvitation,
    *,
    now: datetime | None = None,
) -> OrganizationInvitation:
    revoked_at = (
        now
        if now is not None
        else _utc_now()
    )

    if invitation.accepted_at is not None:
        raise InvitationError(
            "Accepted invitation cannot be revoked."
        )

    invitation.revoked_at = (
        revoked_at
    )

    invitation.token_hash = None

    database.flush()

    return invitation
