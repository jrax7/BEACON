from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization
from app.models.organization_invitation import (
    OrganizationInvitation,
)
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.rbac import OrganizationRole


BACKEND = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def read(
    relative: str,
) -> str:
    path = (
        BACKEND
        / relative
    )

    if not path.exists():
        return ""

    return path.read_text(
        encoding="utf-8",
    )


def invitation_source() -> str:
    return (
        read(
            "app/organizations/invitations.py"
        )
        + read(
            "app/routers/organizations.py"
        )
    )


def test_invitation_service_exists() -> None:
    assert (
        BACKEND
        / "app"
        / "organizations"
        / "invitations.py"
    ).exists()


def test_registration_accepts_optional_invitation_token() -> None:
    assert (
        "invitation_token"
        in read(
            "app/schemas/auth.py"
        )
    )


def test_registration_integrates_invitation_acceptance() -> None:
    source = read(
        "app/routers/auth.py"
    )

    assert (
        "invitation_token"
        in source
    )

    assert (
        "accept_invitation"
        in source
    )


def test_raw_invitation_token_is_not_persisted() -> None:
    source = (
        invitation_source()
        .lower()
    )

    assert (
        "token_hash"
        in source
    )

    assert (
        "sha256"
        in source
    )


def test_invitation_has_expiry_and_one_time_acceptance() -> None:
    source = (
        invitation_source()
        .lower()
    )

    assert "expires_at" in source
    assert "accepted_at" in source


def test_invitation_can_be_revoked() -> None:
    assert (
        "revoked_at"
        in invitation_source().lower()
    )


def test_invitation_routes_support_resolve_resend_and_revoke() -> None:
    source = read(
        "app/routers/organizations.py"
    ).lower()

    assert "resolve" in source
    assert "resend" in source
    assert "@router.delete" in source


def make_database() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={
            "check_same_thread":
                False,
        },
        poolclass=StaticPool,
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

    OrganizationInvitation.__table__.create(
        engine
    )

    return Session(
        engine,
        expire_on_commit=False,
    )


def make_invitation(
    database: Session,
    *,
    now: datetime,
):
    from app.organizations.invitations import (
        create_invitation,
        issue_invitation_token,
    )

    owner = User(
        id=uuid4(),
        email="owner@example.com",
        full_name="Owner",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    organization = Organization(
        id=uuid4(),
        name="Example",
        slug=(
            "example-"
            + uuid4().hex[:16]
        ),
    )

    database.add_all(
        [
            owner,
            organization,
        ]
    )

    database.flush()

    database.add(
        OrganizationMembership(
            id=uuid4(),
            organization_id=(
                organization.id
            ),
            user_id=owner.id,
            role=(
                OrganizationRole.ADMIN.value
            ),
        )
    )

    database.flush()

    invitation = create_invitation(
        database,
        organization_id=(
            organization.id
        ),
        email="invitee@example.com",
        role=OrganizationRole.ANALYST,
        invited_by_user_id=owner.id,
        now=now,
    )

    raw = issue_invitation_token(
        database,
        invitation,
        now=now,
    )

    database.flush()

    return (
        owner,
        organization,
        invitation,
        raw,
    )


def test_valid_invitation_resolves() -> None:
    from app.organizations.invitations import (
        resolve_invitation,
    )

    now = datetime.now(
        timezone.utc
    )

    database = make_database()

    try:
        _, _, invitation, raw = (
            make_invitation(
                database,
                now=now,
            )
        )

        resolved = resolve_invitation(
            database,
            raw,
            now=now,
        )

        assert (
            resolved.id
            == invitation.id
        )

    finally:
        database.close()


def test_wrong_invitation_token_fails() -> None:
    from app.organizations.invitations import (
        InvitationError,
        resolve_invitation,
    )

    database = make_database()

    try:
        with pytest.raises(
            InvitationError
        ):
            resolve_invitation(
                database,
                "wrong-token-value",
            )

    finally:
        database.close()


def test_expired_invitation_fails() -> None:
    from app.organizations.invitations import (
        InvitationError,
        resolve_invitation,
    )

    now = datetime.now(
        timezone.utc
    )

    database = make_database()

    try:
        _, _, _, raw = (
            make_invitation(
                database,
                now=now,
            )
        )

        with pytest.raises(
            InvitationError
        ):
            resolve_invitation(
                database,
                raw,
                now=(
                    now
                    + timedelta(
                        days=10
                    )
                ),
            )

    finally:
        database.close()


def test_revoked_invitation_fails() -> None:
    from app.organizations.invitations import (
        InvitationError,
        resolve_invitation,
        revoke_invitation,
    )

    now = datetime.now(
        timezone.utc
    )

    database = make_database()

    try:
        _, _, invitation, raw = (
            make_invitation(
                database,
                now=now,
            )
        )

        revoke_invitation(
            database,
            invitation,
            now=now,
        )

        with pytest.raises(
            InvitationError
        ):
            resolve_invitation(
                database,
                raw,
                now=now,
            )

    finally:
        database.close()


def test_wrong_email_cannot_accept_invitation() -> None:
    from app.organizations.invitations import (
        InvitationError,
        accept_invitation,
    )

    now = datetime.now(
        timezone.utc
    )

    database = make_database()

    try:
        _, _, _, raw = (
            make_invitation(
                database,
                now=now,
            )
        )

        user = User(
            id=uuid4(),
            email="wrong@example.com",
            full_name="Wrong",
            password_hash="unused",
            role="user",
            is_active=True,
            is_email_verified=False,
        )

        database.add(
            user
        )

        database.flush()

        with pytest.raises(
            InvitationError
        ):
            accept_invitation(
                database,
                raw,
                user,
                user.email,
                now=now,
            )

    finally:
        database.close()


def test_invitation_is_one_time() -> None:
    from app.organizations.invitations import (
        InvitationError,
        accept_invitation,
        resolve_invitation,
    )

    now = datetime.now(
        timezone.utc
    )

    database = make_database()

    try:
        _, organization, _, raw = (
            make_invitation(
                database,
                now=now,
            )
        )

        user = User(
            id=uuid4(),
            email="invitee@example.com",
            full_name="Invitee",
            password_hash="unused",
            role="user",
            is_active=True,
            is_email_verified=False,
        )

        database.add(
            user
        )

        database.flush()

        org, membership, invitation = (
            accept_invitation(
                database,
                raw,
                user,
                user.email,
                now=now,
            )
        )

        assert (
            org.id
            == organization.id
        )

        assert (
            membership.role
            == OrganizationRole.ANALYST.value
        )

        assert (
            invitation.accepted_at
            is not None
        )

        assert (
            invitation.token_hash
            is None
        )

        with pytest.raises(
            InvitationError
        ):
            resolve_invitation(
                database,
                raw,
                now=now,
            )

    finally:
        database.close()



def test_existing_account_can_accept_invitation_to_additional_organization() -> None:
    from sqlalchemy import select

    from app.organizations.invitations import accept_invitation

    now = datetime.now(timezone.utc)
    database = make_database()

    try:
        _, invited_organization, _, raw = make_invitation(
            database,
            now=now,
        )

        user = User(
            id=uuid4(),
            email="invitee@example.com",
            full_name="Existing Invitee",
            password_hash="unused",
            role="user",
            is_active=True,
            is_email_verified=True,
        )
        existing_organization = Organization(
            id=uuid4(),
            name="Existing Workspace",
            slug="existing-" + uuid4().hex[:16],
        )
        database.add_all([user, existing_organization])
        database.flush()
        database.add(
            OrganizationMembership(
                id=uuid4(),
                organization_id=existing_organization.id,
                user_id=user.id,
                role=OrganizationRole.ADMIN.value,
            )
        )
        database.flush()

        organization, membership, _ = accept_invitation(
            database,
            raw,
            user,
            user.email,
            now=now,
        )

        memberships = list(
            database.scalars(
                select(OrganizationMembership).where(
                    OrganizationMembership.user_id == user.id
                )
            )
        )

        assert organization.id == invited_organization.id
        assert membership.organization_id == invited_organization.id
        assert len(memberships) == 2
        assert {row.organization_id for row in memberships} == {
            existing_organization.id,
            invited_organization.id,
        }
    finally:
        database.close()

def test_invitation_mail_uses_existing_mail_stack() -> None:
    mailer = read(
        "app/auth/mailer.py"
    )

    tasks = read(
        "app/auth/mail_tasks.py"
    )

    celery = read(
        "app/celery_app.py"
    )

    assert (
        "organization_invitation_url"
        in mailer
    )

    assert (
        "send_auth_email_message"
        in tasks
    )

    assert (
        "send_organization_invitation_email"
        in tasks
    )

    assert (
        "beacon.send_organization_invitation_email"
        in celery
    )
