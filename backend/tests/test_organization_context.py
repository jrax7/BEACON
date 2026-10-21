from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def database_session() -> Session:
    from app.models.organization import Organization
    from app.models.organization_membership import (
        OrganizationMembership,
    )
    from app.models.user import User

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

    return Session(
        engine,
        expire_on_commit=False,
    )


def make_user(
    database: Session,
    email: str,
):
    from app.models.user import User

    user = User(
        email=email,
        full_name="Phase 16C User",
        password_hash="unused",
        role="user",
        is_active=True,
        is_email_verified=True,
    )

    database.add(
        user
    )
    database.flush()

    return user


def test_create_personal_organization_is_deterministic() -> None:
    from app.organizations.rbac import OrganizationRole
    from app.organizations.service import (
        create_personal_organization,
    )

    database = database_session()

    try:
        user = make_user(
            database,
            "admin@example.test",
        )

        organization, membership = (
            create_personal_organization(
                database,
                user,
                role=OrganizationRole.ADMIN,
            )
        )

        assert (
            organization.slug
            == f"workspace-{user.id.hex[:20]}"
        )

        assert (
            membership.organization_id
            == organization.id
        )

        assert (
            membership.user_id
            == user.id
        )

        assert membership.role == "admin"

    finally:
        database.close()


def test_valid_membership_resolves_server_context() -> None:
    from app.organizations.context import (
        resolve_organization_context,
    )
    from app.organizations.rbac import OrganizationRole
    from app.organizations.service import (
        create_personal_organization,
    )

    database = database_session()

    try:
        user = make_user(
            database,
            "analyst@example.test",
        )

        organization, membership = (
            create_personal_organization(
                database,
                user,
                role=OrganizationRole.ANALYST,
            )
        )

        context = resolve_organization_context(
            database,
            user,
        )

        assert context.user.id == user.id

        assert (
            context.organization.id
            == organization.id
        )

        assert (
            context.membership.id
            == membership.id
        )

        assert (
            context.role
            == OrganizationRole.ANALYST
        )

    finally:
        database.close()


def test_missing_membership_fails_closed() -> None:
    from app.organizations.context import (
        resolve_organization_context,
    )

    database = database_session()

    try:
        user = make_user(
            database,
            "orphan@example.test",
        )

        try:
            resolve_organization_context(
                database,
                user,
            )
        except HTTPException as exc:
            assert exc.status_code == 403
        else:
            raise AssertionError(
                "Missing membership must fail closed."
            )

    finally:
        database.close()


def test_invalid_membership_role_fails_closed() -> None:
    from app.models.organization_membership import (
        OrganizationMembership,
    )
    from app.organizations.context import (
        resolve_organization_context,
    )
    from app.organizations.rbac import OrganizationRole
    from app.organizations.service import (
        create_personal_organization,
    )

    database = database_session()

    try:
        user = make_user(
            database,
            "invalid-role@example.test",
        )

        _, membership = (
            create_personal_organization(
                database,
                user,
                role=OrganizationRole.VIEWER,
            )
        )

        assert isinstance(
            membership,
            OrganizationMembership,
        )

        membership.role = "owner"

        database.flush()

        try:
            resolve_organization_context(
                database,
                user,
            )
        except HTTPException as exc:
            assert exc.status_code == 403
        else:
            raise AssertionError(
                "Unknown organization role "
                "must fail closed."
            )

    finally:
        database.close()


def test_request_selected_membership_resolves_exact_organization() -> None:
    from app.models.organization import Organization
    from app.models.organization_membership import OrganizationMembership
    from app.organizations.context import resolve_organization_context
    from app.organizations.rbac import OrganizationRole
    from app.organizations.service import create_personal_organization

    database = database_session()

    try:
        user = make_user(database, "multi-org@example.test")
        first_organization, _ = create_personal_organization(
            database,
            user,
            role=OrganizationRole.ADMIN,
        )

        second_organization = Organization(
            name="Second Workspace",
            slug="second-workspace",
        )
        database.add(second_organization)
        database.flush()

        second_membership = OrganizationMembership(
            organization_id=second_organization.id,
            user_id=user.id,
            role=OrganizationRole.ANALYST.value,
        )
        database.add(second_membership)
        database.flush()

        setattr(
            user,
            "_beacon_organization_id",
            second_organization.id,
        )

        context = resolve_organization_context(database, user)

        assert context.organization.id == second_organization.id
        assert context.organization.id != first_organization.id
        assert context.membership.id == second_membership.id
        assert context.role == OrganizationRole.ANALYST
    finally:
        database.close()
