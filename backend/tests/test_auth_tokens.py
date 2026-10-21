from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.auth_session import AuthSession
from app.models.email_verification_token import (
    EmailVerificationToken,
)
from app.models.password_reset_token import (
    PasswordResetToken,
)
from app.models.user import User
from app.security.auth import (
    hash_password,
    verify_password,
)


NOW = datetime(
    2026,
    9,
    3,
    18,
    0,
    tzinfo=timezone.utc,
)

OLD_PASSWORD = "OriginalPassword-2026"
NEW_PASSWORD = "ResetPassword-2026"


@pytest.fixture
def database():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
    )

    User.__table__.create(engine)
    AuthSession.__table__.create(engine)
    EmailVerificationToken.__table__.create(engine)
    PasswordResetToken.__table__.create(engine)

    with Session(engine) as session:
        yield session

    engine.dispose()


def _user(
    database: Session,
    *,
    verified=False,
) -> User:
    user = User(
        id=uuid4(),
        email=(
            f"{uuid4().hex}"
            "@example.com"
        ),
        full_name="Token User",
        password_hash=hash_password(
            OLD_PASSWORD
        ),
        role="user",
        is_active=True,
        is_email_verified=verified,
    )

    database.add(user)
    database.flush()

    return user


def test_verification_token_is_hash_only_and_24_hours(
    database,
) -> None:
    from app.auth.crypto import hash_opaque_token
    from app.auth.tokens import issue_verification_token

    user = _user(database)

    row, raw = issue_verification_token(
        database,
        user.id,
        now=NOW,
    )

    assert row.token_hash == hash_opaque_token(raw)
    assert row.token_hash != raw

    assert row.expires_at == (
        NOW + timedelta(hours=24)
    )


def test_new_verification_token_invalidates_old_outstanding_token(
    database,
) -> None:
    from app.auth.tokens import issue_verification_token

    user = _user(database)

    first, _ = issue_verification_token(
        database,
        user.id,
        now=NOW,
    )

    second, _ = issue_verification_token(
        database,
        user.id,
        now=NOW + timedelta(minutes=1),
    )

    assert first.consumed_at is not None
    assert second.consumed_at is None


def test_verification_consumption_verifies_user_once(
    database,
) -> None:
    from app.auth.tokens import (
        consume_verification_token,
        issue_verification_token,
    )

    user = _user(database)

    _, raw = issue_verification_token(
        database,
        user.id,
        now=NOW,
    )

    verified = consume_verification_token(
        database,
        raw,
        now=NOW,
    )

    assert verified.id == user.id
    assert verified.is_email_verified

    with pytest.raises(ValueError):
        consume_verification_token(
            database,
            raw,
            now=NOW,
        )


def test_reset_token_is_hash_only_and_30_minutes(
    database,
) -> None:
    from app.auth.crypto import hash_opaque_token
    from app.auth.tokens import issue_password_reset_token

    user = _user(
        database,
        verified=True,
    )

    row, raw = issue_password_reset_token(
        database,
        user.id,
        now=NOW,
    )

    assert row.token_hash == hash_opaque_token(raw)
    assert row.token_hash != raw

    assert row.expires_at == (
        NOW + timedelta(minutes=30)
    )


def test_new_reset_token_invalidates_old_outstanding_token(
    database,
) -> None:
    from app.auth.tokens import issue_password_reset_token

    user = _user(
        database,
        verified=True,
    )

    first, _ = issue_password_reset_token(
        database,
        user.id,
        now=NOW,
    )

    second, _ = issue_password_reset_token(
        database,
        user.id,
        now=NOW + timedelta(minutes=1),
    )

    assert first.consumed_at is not None
    assert second.consumed_at is None


def test_password_reset_updates_hash_consumes_token_and_revokes_sessions(
    database,
) -> None:
    from app.auth.sessions import SessionService
    from app.auth.tokens import (
        consume_password_reset_token,
        issue_password_reset_token,
    )

    user = _user(
        database,
        verified=True,
    )

    service = SessionService(
        database
    )

    first_session, _ = service.create_session(
        user.id
    )

    second_session, _ = service.create_session(
        user.id
    )

    _, raw = issue_password_reset_token(
        database,
        user.id,
        now=NOW,
    )

    reset_user = consume_password_reset_token(
        database,
        raw,
        NEW_PASSWORD,
        now=NOW,
    )

    assert reset_user.id == user.id

    assert verify_password(
        NEW_PASSWORD,
        reset_user.password_hash,
    )

    assert not verify_password(
        OLD_PASSWORD,
        reset_user.password_hash,
    )

    # revoke_all_for_user() intentionally performs a bulk UPDATE
    # with synchronize_session=False. Refresh the already-loaded
    # ORM instances before asserting persisted revocation state.
    database.refresh(
        first_session
    )

    database.refresh(
        second_session
    )

    assert first_session.revoked_at is not None
    assert second_session.revoked_at is not None

    with pytest.raises(ValueError):
        consume_password_reset_token(
            database,
            raw,
            NEW_PASSWORD,
            now=NOW,
        )


def test_expired_reset_token_rejected(
    database,
) -> None:
    from app.auth.tokens import (
        consume_password_reset_token,
        issue_password_reset_token,
    )

    user = _user(
        database,
        verified=True,
    )

    _, raw = issue_password_reset_token(
        database,
        user.id,
        now=NOW,
    )

    with pytest.raises(ValueError):
        consume_password_reset_token(
            database,
            raw,
            NEW_PASSWORD,
            now=NOW + timedelta(minutes=31),
        )


def test_verification_consumption_invalidates_other_outstanding_tokens(
    database,
) -> None:
    from app.auth.crypto import hash_opaque_token
    from app.auth.tokens import (
        consume_verification_token,
        issue_verification_token,
    )

    user = _user(database)

    _, raw = issue_verification_token(
        database,
        user.id,
        now=NOW,
    )

    competing = EmailVerificationToken(
        user_id=user.id,
        token_hash=hash_opaque_token(
            "competing-verification-token"
        ),
        expires_at=(
            NOW + timedelta(hours=1)
        ),
        consumed_at=None,
    )

    database.add(competing)
    database.flush()

    assert competing.consumed_at is None

    consume_verification_token(
        database,
        raw,
        now=NOW,
    )

    assert competing.consumed_at == NOW


def test_reset_consumption_invalidates_other_outstanding_tokens(
    database,
) -> None:
    from app.auth.crypto import hash_opaque_token
    from app.auth.tokens import (
        consume_password_reset_token,
        issue_password_reset_token,
    )

    user = _user(
        database,
        verified=True,
    )

    _, raw = issue_password_reset_token(
        database,
        user.id,
        now=NOW,
    )

    competing = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_opaque_token(
            "competing-reset-token"
        ),
        expires_at=(
            NOW + timedelta(minutes=20)
        ),
        consumed_at=None,
    )

    database.add(competing)
    database.flush()

    assert competing.consumed_at is None

    consume_password_reset_token(
        database,
        raw,
        NEW_PASSWORD,
        now=NOW,
    )

    assert competing.consumed_at == NOW

def test_password_reset_rejects_current_password_without_consuming_token_or_revoking_session(
    database,
) -> None:
    from app.auth.sessions import SessionService
    from app.auth.tokens import (
        consume_password_reset_token,
        issue_password_reset_token,
    )

    user = _user(
        database,
        verified=True,
    )

    original_password_hash = (
        user.password_hash
    )

    session_service = SessionService(
        database
    )

    session_row, _ = (
        session_service.create_session(
            user.id
        )
    )

    reset_row, raw_token = (
        issue_password_reset_token(
            database,
            user.id,
            now=NOW,
        )
    )

    with pytest.raises(
        ValueError,
        match="must differ",
    ):
        consume_password_reset_token(
            database,
            raw_token,
            OLD_PASSWORD,
            now=NOW,
        )

    database.refresh(user)
    database.refresh(session_row)
    database.refresh(reset_row)

    assert (
        user.password_hash
        == original_password_hash
    )

    assert verify_password(
        OLD_PASSWORD,
        user.password_hash,
    )

    assert reset_row.consumed_at is None
    assert session_row.revoked_at is None
