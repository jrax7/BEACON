from __future__ import annotations

from importlib import import_module
import importlib.util

from sqlalchemy import UniqueConstraint


def _model(
    module_name: str,
    class_name: str,
):
    try:
        spec = importlib.util.find_spec(
            module_name
        )
    except ModuleNotFoundError:
        spec = None

    assert spec is not None, (
        f"{module_name} does not exist yet"
    )

    module = import_module(
        module_name
    )

    assert hasattr(
        module,
        class_name,
    ), (
        f"{class_name} does not exist yet"
    )

    return getattr(
        module,
        class_name,
    )


def _one_fk(column):
    foreign_keys = list(
        column.foreign_keys
    )

    assert len(foreign_keys) == 1

    return foreign_keys[0]


def test_organization_model_contract() -> None:
    Organization = _model(
        "app.models.organization",
        "Organization",
    )

    table = Organization.__table__

    assert table.name == "organizations"

    assert {
        "id",
        "name",
        "slug",
        "created_at",
        "updated_at",
    } <= set(table.c.keys())

    assert table.c.name.nullable is False
    assert table.c.name.type.length == 150

    assert table.c.slug.nullable is False
    assert table.c.slug.type.length == 160
    assert table.c.slug.unique is True
    assert table.c.slug.index is True


def test_membership_allows_multiple_organizations_per_user() -> None:
    Membership = _model(
        "app.models.organization_membership",
        "OrganizationMembership",
    )

    table = Membership.__table__

    assert table.name == "organization_memberships"

    organization_id = table.c.organization_id
    user_id = table.c.user_id

    assert organization_id.nullable is False
    assert organization_id.index is True
    assert (
        _one_fk(
            organization_id
        ).target_fullname
        == "organizations.id"
    )
    assert (
        _one_fk(
            organization_id
        ).ondelete
        == "CASCADE"
    )

    assert user_id.nullable is False
    assert user_id.index is True
    assert (
        _one_fk(
            user_id
        ).target_fullname
        == "users.id"
    )
    assert (
        _one_fk(
            user_id
        ).ondelete
        == "CASCADE"
    )

    constraints = [
        constraint
        for constraint
        in table.constraints
        if isinstance(
            constraint,
            UniqueConstraint,
        )
    ]

    assert any(
        constraint.name
        == "uq_organization_memberships_org_user"
        and {
            column.name
            for column
            in constraint.columns
        }
        == {
            "organization_id",
            "user_id",
        }
        for constraint
        in constraints
    )

    assert table.c.role.nullable is False
    assert table.c.role.type.length == 30


def test_invitation_stores_only_hashed_secret_material() -> None:
    Invitation = _model(
        "app.models.organization_invitation",
        "OrganizationInvitation",
    )

    table = Invitation.__table__

    assert table.name == "organization_invitations"

    assert {
        "organization_id",
        "email",
        "role",
        "invited_by_user_id",
        "token_hash",
        "expires_at",
        "accepted_at",
        "revoked_at",
    } <= set(table.c.keys())

    assert table.c.email.type.length == 320
    assert table.c.role.type.length == 30

    assert table.c.token_hash.type.length == 64
    assert table.c.token_hash.unique is True
    assert table.c.token_hash.index is True

    assert "raw_token" not in table.c
    assert "token" not in table.c

    assert table.c.accepted_at.nullable is True
    assert table.c.revoked_at.nullable is True

    organization_fk = _one_fk(
        table.c.organization_id
    )
    inviter_fk = _one_fk(
        table.c.invited_by_user_id
    )

    assert (
        organization_fk.target_fullname
        == "organizations.id"
    )
    assert organization_fk.ondelete == "CASCADE"

    assert (
        inviter_fk.target_fullname
        == "users.id"
    )
    assert inviter_fk.ondelete == "SET NULL"


def test_target_and_scan_use_organization_security_boundary() -> None:
    Target = _model(
        "app.models.target",
        "Target",
    )
    Scan = _model(
        "app.models.scan",
        "Scan",
    )

    for model in (
        Target,
        Scan,
    ):
        column = model.__table__.c.organization_id

        assert column.nullable is False
        assert column.index is True

        foreign_key = _one_fk(
            column
        )

        assert (
            foreign_key.target_fullname
            == "organizations.id"
        )
        assert foreign_key.ondelete == "RESTRICT"

    constraints = [
        constraint
        for constraint
        in Target.__table__.constraints
        if isinstance(
            constraint,
            UniqueConstraint,
        )
    ]

    assert any(
        constraint.name
        == "uq_targets_organization_hostname"
        and {
            column.name
            for column
            in constraint.columns
        }
        == {
            "organization_id",
            "hostname",
        }
        for constraint
        in constraints
    )

    assert not any(
        constraint.name
        == "uq_targets_user_hostname"
        for constraint
        in constraints
    )

    # user_id remains provenance rather than the authorization boundary.
    assert "user_id" in Target.__table__.c
    assert "user_id" in Scan.__table__.c


def test_audit_log_allows_anonymous_events_but_can_record_org() -> None:
    AuditLog = _model(
        "app.models.audit_log",
        "AuditLog",
    )

    table = AuditLog.__table__

    assert table.c.user_id.nullable is True

    organization_id = table.c.organization_id

    assert organization_id.nullable is True
    assert organization_id.index is True

    foreign_key = _one_fk(
        organization_id
    )

    assert (
        foreign_key.target_fullname
        == "organizations.id"
    )
    assert foreign_key.ondelete == "SET NULL"
