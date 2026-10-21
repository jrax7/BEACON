from __future__ import annotations

from uuid import UUID

from app.auth.mailer import (
    MailDeliveryError,
    email_verification_url,
    organization_invitation_url,
    password_reset_url,
    send_auth_email_message,
)
from app.auth.tokens import (
    issue_password_reset_token,
    issue_verification_token,
)
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models.organization import Organization
from app.models.organization_invitation import (
    OrganizationInvitation,
)
from app.models.user import User
from app.organizations.invitations import (
    InvitationError,
    issue_invitation_token,
)


@celery_app.task(
    name="beacon.send_auth_email",
    queue="control",
)
def send_auth_lifecycle_email(
    user_id: str,
    purpose: str,
) -> dict[str, str]:
    """Generate the raw token only after the task is dequeued."""

    try:
        user_uuid = UUID(
            user_id
        )
    except (
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ValueError(
            "Authentication mail user_id must be a UUID."
        ) from exc

    if purpose not in {
        "verify_email",
        "reset_password",
    }:
        raise ValueError(
            "Unsupported authentication email purpose."
        )

    with SessionLocal() as database:
        user = database.get(
            User,
            user_uuid,
        )

        if (
            user is None
            or not user.is_active
        ):
            return {
                "status": "skipped",
                "purpose": purpose,
            }

        if purpose == "verify_email":
            _, raw_token = issue_verification_token(
                database,
                user.id,
            )

            link = email_verification_url(
                raw_token
            )
        else:
            _, raw_token = issue_password_reset_token(
                database,
                user.id,
            )

            link = password_reset_url(
                raw_token
            )

        # Persist only the hash before outbound delivery.
        database.commit()

        try:
            send_auth_email_message(
                to_address=user.email,
                purpose=purpose,
                link=link,
                context={
                    "recipient_name": (
                        user.full_name
                        or user.email
                    ),
                },
            )
        except MailDeliveryError:
            return {
                "status": "failed",
                "purpose": purpose,
            }

        return {
            "status": "sent",
            "purpose": purpose,
        }


@celery_app.task(
    name="beacon.send_organization_invitation_email",
    queue="control",
)
def send_organization_invitation_email(
    invitation_id: str,
) -> dict[str, str]:
    try:
        invitation_uuid = UUID(
            invitation_id
        )
    except (
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ValueError(
            "Invitation id must be a UUID."
        ) from exc

    with SessionLocal() as database:
        invitation = database.get(
            OrganizationInvitation,
            invitation_uuid,
        )

        if (
            invitation is None
            or invitation.accepted_at
            is not None
            or invitation.revoked_at
            is not None
        ):
            return {
                "status": "skipped",
                "purpose":
                    "organization_invitation",
            }

        try:
            raw_token = (
                issue_invitation_token(
                    database,
                    invitation,
                )
            )
        except InvitationError:
            return {
                "status": "skipped",
                "purpose":
                    "organization_invitation",
            }

        database.commit()

        link = (
            organization_invitation_url(
                raw_token
            )
        )

        organization = database.get(
            Organization,
            invitation.organization_id,
        )

        inviter = (
            database.get(
                User,
                invitation.invited_by_user_id,
            )
            if invitation.invited_by_user_id
            else None
        )

        try:
            send_auth_email_message(
                to_address=(
                    invitation.email
                ),
                purpose=(
                    "organization_invitation"
                ),
                link=link,
                context={
                    "organization_name": (
                        organization.name
                        if organization
                        else ""
                    ),
                    "workspace_role": (
                        invitation.role
                    ),
                    "inviter_name": (
                        inviter.full_name
                        if inviter
                        else ""
                    ),
                },
            )
        except MailDeliveryError:
            return {
                "status": "failed",
                "purpose":
                    "organization_invitation",
            }

        return {
            "status": "sent",
            "purpose":
                "organization_invitation",
        }
