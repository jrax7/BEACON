from __future__ import annotations

from uuid import uuid4

import pytest


class FakeDatabase:
    def __init__(self):
        self.rows = []

    def add(
        self,
        row,
    ):
        self.rows.append(
            row
        )


def test_anonymous_auth_event_is_supported() -> None:
    from app.auth.audit import write_auth_audit

    database = FakeDatabase()

    write_auth_audit(
        database,
        action="auth.login.failure",
        user_id=None,
        ip_address="203.0.113.50",
        details={
            "mechanism":
                "session",
            "reason_code":
                "invalid_credentials",
        },
    )

    assert len(
        database.rows
    ) == 1

    assert (
        database.rows[0].user_id
        is None
    )


def test_known_user_auth_event_is_supported() -> None:
    from app.auth.audit import write_auth_audit

    database = FakeDatabase()
    user_id = uuid4()

    write_auth_audit(
        database,
        action="auth.password.changed",
        user_id=user_id,
        ip_address="203.0.113.51",
        details={
            "mechanism":
                "session",
        },
    )

    assert (
        database.rows[0].user_id
        == user_id
    )


def test_unknown_identity_is_hashed() -> None:
    from app.auth.audit import identity_hash

    first = identity_hash(
        " User@Example.COM "
    )

    second = identity_hash(
        "user@example.com"
    )

    assert first == second

    assert (
        "user@example.com"
        not in first
    )


def test_unapproved_details_are_not_persisted() -> None:
    from app.auth.audit import write_auth_audit

    database = FakeDatabase()

    write_auth_audit(
        database,
        action="auth.login.failure",
        user_id=None,
        ip_address=None,
        details={
            "reason_code":
                "invalid_credentials",
            "attacker_supplied":
                "do-not-store",
        },
    )

    assert (
        database.rows[0].details
        == {
            "reason_code":
                "invalid_credentials",
        }
    )


def test_unknown_auth_action_is_rejected() -> None:
    from app.auth.audit import write_auth_audit

    with pytest.raises(
        ValueError
    ):
        write_auth_audit(
            FakeDatabase(),
            action="auth.unapproved.event",
            user_id=None,
            ip_address=None,
            details=None,
        )
