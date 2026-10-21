from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
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


def make_user(
    database: Session,
    email: str,
    *,
    role: str = "user",
) -> User:
    user = User(
        id=uuid4(),
        email=email,
        full_name=email.split("@")[0],
        password_hash="not-used",
        role=role,
        is_active=True,
        is_email_verified=True,
    )

    database.add(
        user
    )

    database.flush()

    return user


def make_org(
    database: Session,
    name: str = "Example Organization",
) -> Organization:
    org = Organization(
        id=uuid4(),
        name=name,
        slug=(
            "org-"
            + uuid4().hex[:20]
        ),
    )

    database.add(
        org
    )

    database.flush()

    return org


def add_member(
    database: Session,
    organization: Organization,
    user: User,
    role: OrganizationRole,
) -> OrganizationMembership:
    membership = OrganizationMembership(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        role=role.value,
    )

    database.add(
        membership
    )

    database.flush()

    return membership


@pytest.fixture
def organization_module(monkeypatch):
    from app.routers import organizations

    monkeypatch.setattr(
        organizations,
        "_record_audit",
        lambda *args, **kwargs:
            None,
    )

    monkeypatch.setattr(
        organizations
        .send_organization_invitation_email,
        "delay",
        lambda *args, **kwargs:
            SimpleNamespace(
                id="invite-mail-task"
            ),
    )

    return organizations


@pytest.mark.parametrize(
    "role",
    [
        OrganizationRole.VIEWER,
        OrganizationRole.ANALYST,
    ],
)
def test_viewer_and_analyst_can_read_org_and_members(
    organization_module,
    role,
):
    database = make_database()

    try:
        org = make_org(
            database
        )

        user = make_user(
            database,
            f"{role.value}@example.com",
        )

        add_member(
            database,
            org,
            user,
            role,
        )

        organization = (
            organization_module
            .read_organization(
                current_user=user,
                database=database,
            )
        )

        members = (
            organization_module
            .list_members(
                current_user=user,
                database=database,
            )
        )

        assert (
            organization.id
            == org.id
        )

        assert (
            organization.role
            == role.value
        )

        assert len(
            members
        ) == 1

        assert (
            members[0].user_id
            == user.id
        )

    finally:
        database.close()


def test_only_admin_can_rename_org(
    organization_module,
):
    from app.schemas.organizations import (
        OrganizationUpdateRequest,
    )

    database = make_database()

    try:
        org = make_org(
            database
        )

        analyst = make_user(
            database,
            "analyst@example.com",
        )

        add_member(
            database,
            org,
            analyst,
            OrganizationRole.ANALYST,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.update_organization(
                request=(
                    OrganizationUpdateRequest(
                        name="Renamed"
                    )
                ),
                current_user=analyst,
                database=database,
            )

        assert (
            exc.value.status_code
            == 403
        )

    finally:
        database.close()


def test_admin_can_rename_org(
    organization_module,
):
    from app.schemas.organizations import (
        OrganizationUpdateRequest,
    )

    database = make_database()

    try:
        org = make_org(
            database
        )

        admin = make_user(
            database,
            "admin@example.com",
        )

        add_member(
            database,
            org,
            admin,
            OrganizationRole.ADMIN,
        )

        response = (
            organization_module
            .update_organization(
                request=(
                    OrganizationUpdateRequest(
                        name="Renamed Organization"
                    )
                ),
                current_user=admin,
                database=database,
            )
        )

        assert (
            response.name
            == "Renamed Organization"
        )

    finally:
        database.close()


def test_only_admin_can_invite(
    organization_module,
):
    from app.schemas.organizations import (
        InvitationCreateRequest,
    )

    database = make_database()

    try:
        org = make_org(
            database
        )

        viewer = make_user(
            database,
            "viewer@example.com",
        )

        add_member(
            database,
            org,
            viewer,
            OrganizationRole.VIEWER,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.create_invitation(
                request=(
                    InvitationCreateRequest(
                        email="new@example.com",
                        role=(
                            OrganizationRole.ANALYST
                        ),
                    )
                ),
                current_user=viewer,
                database=database,
            )

        assert (
            exc.value.status_code
            == 403
        )

    finally:
        database.close()


def test_final_admin_cannot_be_demoted(
    organization_module,
):
    from app.schemas.organizations import (
        MemberRoleUpdateRequest,
    )

    database = make_database()

    try:
        org = make_org(
            database
        )

        admin = make_user(
            database,
            "admin@example.com",
        )

        membership = add_member(
            database,
            org,
            admin,
            OrganizationRole.ADMIN,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.update_member(
                membership_id=(
                    membership.id
                ),
                request=(
                    MemberRoleUpdateRequest(
                        role=(
                            OrganizationRole.VIEWER
                        )
                    )
                ),
                current_user=admin,
                database=database,
            )

        assert (
            exc.value.status_code
            == 409
        )

    finally:
        database.close()


def test_final_admin_cannot_be_removed(
    organization_module,
):
    database = make_database()

    try:
        org = make_org(
            database
        )

        admin = make_user(
            database,
            "admin@example.com",
        )

        membership = add_member(
            database,
            org,
            admin,
            OrganizationRole.ADMIN,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.delete_member(
                membership_id=(
                    membership.id
                ),
                current_user=admin,
                database=database,
            )

        assert (
            exc.value.status_code
            == 409
        )

    finally:
        database.close()


def test_cross_org_member_id_is_not_found(
    organization_module,
):
    from app.schemas.organizations import (
        MemberRoleUpdateRequest,
    )

    database = make_database()

    try:
        org_a = make_org(
            database,
            "Org A",
        )

        org_b = make_org(
            database,
            "Org B",
        )

        admin = make_user(
            database,
            "admin@example.com",
        )

        other = make_user(
            database,
            "other@example.com",
        )

        add_member(
            database,
            org_a,
            admin,
            OrganizationRole.ADMIN,
        )

        other_membership = add_member(
            database,
            org_b,
            other,
            OrganizationRole.VIEWER,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.update_member(
                membership_id=(
                    other_membership.id
                ),
                request=(
                    MemberRoleUpdateRequest(
                        role=(
                            OrganizationRole.ANALYST
                        )
                    )
                ),
                current_user=admin,
                database=database,
            )

        assert (
            exc.value.status_code
            == 404
        )

    finally:
        database.close()


def test_demo_cannot_administer_org(
    organization_module,
):
    from app.schemas.organizations import (
        OrganizationUpdateRequest,
    )

    database = make_database()

    try:
        org = make_org(
            database
        )

        demo = make_user(
            database,
            "demo@example.com",
            role="demo",
        )

        add_member(
            database,
            org,
            demo,
            OrganizationRole.ADMIN,
        )

        with pytest.raises(
            HTTPException
        ) as exc:
            organization_module.update_organization(
                request=(
                    OrganizationUpdateRequest(
                        name="Nope"
                    )
                ),
                current_user=demo,
                database=database,
            )

        assert (
            exc.value.status_code
            == 403
        )

    finally:
        database.close()


def test_active_organization_is_saved_only_for_members(organization_module):
    from app.auth.sessions import SessionService
    from app.models.auth_session import AuthSession
    from app.schemas.organizations import ActiveOrganizationRequest

    database = make_database()
    try:
        AuthSession.__table__.create(database.get_bind())
        user = make_user(database, "switcher@example.com")
        first = make_org(database, "First")
        second = make_org(database, "Second")
        outsider = make_org(database, "Outsider")
        add_member(database, first, user, OrganizationRole.ADMIN)
        add_member(database, second, user, OrganizationRole.VIEWER)
        runtime = SimpleNamespace(
            session_idle_minutes=60,
            session_absolute_hours=12,
        )
        session_row, _ = SessionService(
            database, runtime_settings=runtime,
        ).create_session(user.id, active_organization_id=first.id)
        principal = SimpleNamespace(
            user=user, mechanism="session", session_id=session_row.id,
        )

        response = organization_module.set_active_organization(
            ActiveOrganizationRequest(organization_id=second.id),
            principal=principal,
            database=database,
        )
        assert response.id == second.id
        assert session_row.active_organization_id == second.id

        with pytest.raises(HTTPException) as exc:
            organization_module.set_active_organization(
                ActiveOrganizationRequest(organization_id=outsider.id),
                principal=principal,
                database=database,
            )
        assert exc.value.status_code == 403
        assert session_row.active_organization_id == second.id
    finally:
        database.close()


def test_removing_member_clears_matching_session_workspace(organization_module):
    from app.auth.sessions import SessionService
    from app.models.auth_session import AuthSession

    database = make_database()
    try:
        AuthSession.__table__.create(database.get_bind())
        org = make_org(database, "Removal")
        admin = make_user(database, "admin-removal@example.com")
        member = make_user(database, "member-removal@example.com")
        add_member(database, org, admin, OrganizationRole.ADMIN)
        member_row = add_member(database, org, member, OrganizationRole.VIEWER)
        runtime = SimpleNamespace(
            session_idle_minutes=60,
            session_absolute_hours=12,
        )
        session_row, _ = SessionService(
            database, runtime_settings=runtime,
        ).create_session(member.id, active_organization_id=org.id)

        organization_module.delete_member(
            membership_id=member_row.id,
            current_user=admin,
            database=database,
        )
        database.refresh(session_row)
        assert session_row.active_organization_id is None
    finally:
        database.close()


def test_pending_invitation_list_excludes_finished_expired_and_existing_members(
    organization_module,
):
    database = make_database()

    try:
        now = datetime.now(timezone.utc)
        org = make_org(database, "Pending Invitations")
        admin = make_user(database, "pending-admin@example.com")
        member = make_user(database, "already-member@example.com")
        add_member(database, org, admin, OrganizationRole.ADMIN)
        add_member(database, org, member, OrganizationRole.VIEWER)

        def invitation(email, *, expires_at, accepted_at=None, revoked_at=None):
            return OrganizationInvitation(
                id=uuid4(),
                organization_id=org.id,
                email=email,
                role=OrganizationRole.VIEWER.value,
                invited_by_user_id=admin.id,
                token_hash=None,
                expires_at=expires_at,
                accepted_at=accepted_at,
                revoked_at=revoked_at,
            )

        database.add_all([
            invitation(
                "pending@example.com",
                expires_at=now + timedelta(hours=1),
            ),
            invitation(
                "accepted@example.com",
                expires_at=now + timedelta(hours=1),
                accepted_at=now,
            ),
            invitation(
                "revoked@example.com",
                expires_at=now + timedelta(hours=1),
                revoked_at=now,
            ),
            invitation(
                "expired@example.com",
                expires_at=now - timedelta(minutes=1),
            ),
            invitation(
                member.email,
                expires_at=now + timedelta(hours=1),
            ),
        ])
        database.flush()

        rows = organization_module.list_invitations(
            current_user=admin,
            database=database,
        )

        assert len(rows) == 1
        assert rows[0].email == "pending@example.com"
    finally:
        database.close()
