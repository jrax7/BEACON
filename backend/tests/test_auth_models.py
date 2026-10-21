from __future__ import annotations

from app.models.audit_log import AuditLog
from app.models.auth_session import AuthSession
from app.models.email_verification_token import EmailVerificationToken
from app.models.password_reset_token import PasswordResetToken


def test_auth_session_contains_only_hashed_credential_material() -> None:
    columns = AuthSession.__table__.columns

    assert "token_hash" in columns
    assert columns["token_hash"].type.length == 64
    assert columns["token_hash"].unique is True
    assert columns["token_hash"].index is True

    assert "raw_token" not in columns
    assert "session_token" not in columns
    assert "csrf_secret" not in columns


def test_auth_session_allows_multiple_rows_per_user() -> None:
    user_column = AuthSession.__table__.columns["user_id"]

    assert user_column.nullable is False
    assert user_column.index is True
    assert user_column.unique is not True


def test_auth_session_tracks_optional_active_organization() -> None:
    column = AuthSession.__table__.columns["active_organization_id"]
    assert column.nullable is True
    assert column.index is True
    foreign_keys = list(column.foreign_keys)
    assert len(foreign_keys) == 1
    assert foreign_keys[0].target_fullname == "organizations.id"
    assert foreign_keys[0].ondelete == "SET NULL"


def test_auth_session_has_revocation_and_bounded_context() -> None:
    columns = AuthSession.__table__.columns

    assert columns["revoked_at"].nullable is True
    assert columns["revoked_reason"].type.length == 100
    assert columns["created_ip"].type.length == 64
    assert columns["user_agent"].type.length == 512

    assert columns["idle_expires_at"].index is True
    assert columns["absolute_expires_at"].index is True


def test_email_verification_token_stores_only_hash() -> None:
    columns = EmailVerificationToken.__table__.columns

    assert columns["token_hash"].type.length == 64
    assert columns["token_hash"].unique is True
    assert columns["token_hash"].index is True
    assert columns["expires_at"].index is True
    assert columns["consumed_at"].nullable is True

    assert "raw_token" not in columns
    assert "token" not in columns


def test_password_reset_token_stores_only_hash() -> None:
    columns = PasswordResetToken.__table__.columns

    assert columns["token_hash"].type.length == 64
    assert columns["token_hash"].unique is True
    assert columns["token_hash"].index is True
    assert columns["expires_at"].index is True
    assert columns["consumed_at"].nullable is True

    assert "raw_token" not in columns
    assert "token" not in columns


def test_auth_token_rows_reference_users_with_cascade_delete() -> None:
    for model in (
        AuthSession,
        EmailVerificationToken,
        PasswordResetToken,
    ):
        user_id = model.__table__.columns["user_id"]

        foreign_keys = list(user_id.foreign_keys)

        assert len(foreign_keys) == 1
        assert foreign_keys[0].target_fullname == "users.id"
        assert foreign_keys[0].ondelete == "CASCADE"


def test_existing_audit_log_supports_anonymous_pre_auth_events() -> None:
    assert AuditLog.__table__.columns["user_id"].nullable is True
