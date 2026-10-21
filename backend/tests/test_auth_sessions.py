from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import (
    create_engine,
    select,
)
from sqlalchemy.orm import Session

from app.auth.crypto import hash_opaque_token
from app.auth.errors import (
    InvalidSessionError,
    SessionExpiredError,
    SessionInactiveUserError,
    SessionRevokedError,
)
from app.auth.sessions import SessionService
from app.models.auth_session import AuthSession
from app.models.user import User


NOW = datetime(
    2026,
    9,
    3,
    18,
    0,
    tzinfo=timezone.utc,
)


@pytest.fixture
def database():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
    )

    User.__table__.create(
        engine,
    )
    AuthSession.__table__.create(
        engine,
    )

    with Session(engine) as session:
        yield session

    engine.dispose()


def _settings():
    return SimpleNamespace(
        session_idle_minutes=60,
        session_absolute_hours=12,
    )


def _user(
    database: Session,
    *,
    active: bool = True,
) -> User:
    user = User(
        id=uuid4(),
        email=f"{uuid4()}@example.test",
        full_name="Session Test",
        password_hash="test-password-hash",
        role="user",
        is_active=active,
        is_email_verified=True,
    )

    database.add(
        user
    )
    database.flush()

    return user


def _service(
    database: Session,
) -> SessionService:
    return SessionService(
        database,
        runtime_settings=_settings(),
    )


def test_session_creation_stores_only_hash(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    session_row, raw_cookie = service.create_session(
        user.id,
        created_ip="203.0.113.9",
        user_agent="pytest",
        now=NOW,
    )

    assert raw_cookie
    assert session_row.token_hash == hash_opaque_token(
        raw_cookie
    )
    assert session_row.token_hash != raw_cookie

    assert not hasattr(
        session_row,
        "raw_token",
    )

    stored = database.scalar(
        select(AuthSession).where(
            AuthSession.id == session_row.id,
        )
    )

    assert stored is session_row
    assert stored.token_hash != raw_cookie


def test_session_creation_can_seed_active_organization(
    database: Session,
) -> None:
    user = _user(database)
    organization_id = uuid4()
    session_row, _ = _service(database).create_session(
        user.id,
        active_organization_id=organization_id,
        now=NOW,
    )
    assert session_row.active_organization_id == organization_id


def test_new_logins_create_distinct_sessions(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    first, first_raw = service.create_session(
        user.id,
        now=NOW,
    )
    second, second_raw = service.create_session(
        user.id,
        now=NOW,
    )

    assert first.id != second.id
    assert first_raw != second_raw
    assert first.token_hash != second.token_hash


def test_idle_expiry_rejects_session(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    session_row, raw_cookie = service.create_session(
        user.id,
        now=NOW,
    )

    session_row.idle_expires_at = (
        NOW - timedelta(seconds=1)
    )
    database.flush()

    with pytest.raises(
        SessionExpiredError,
    ):
        service.resolve_session(
            raw_cookie,
            now=NOW,
        )


def test_absolute_expiry_rejects_session_even_after_activity(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    session_row, raw_cookie = service.create_session(
        user.id,
        now=NOW,
    )

    session_row.idle_expires_at = (
        NOW + timedelta(hours=1)
    )
    session_row.absolute_expires_at = (
        NOW - timedelta(seconds=1)
    )
    database.flush()

    with pytest.raises(
        SessionExpiredError,
    ):
        service.resolve_session(
            raw_cookie,
            now=NOW,
        )


def test_revoked_session_is_rejected(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    session_row, raw_cookie = service.create_session(
        user.id,
        now=NOW,
    )

    service.revoke_session(
        session_row,
        "logout",
        now=NOW,
    )
    database.flush()

    with pytest.raises(
        SessionRevokedError,
    ):
        service.resolve_session(
            raw_cookie,
            now=NOW,
        )


def test_unknown_session_is_rejected(
    database: Session,
) -> None:
    service = _service(
        database
    )

    with pytest.raises(
        InvalidSessionError,
    ):
        service.resolve_session(
            "not-a-real-cookie",
            now=NOW,
        )


def test_inactive_user_cannot_use_valid_session(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    _, raw_cookie = service.create_session(
        user.id,
        now=NOW,
    )

    user.is_active = False
    database.flush()

    with pytest.raises(
        SessionInactiveUserError,
    ):
        service.resolve_session(
            raw_cookie,
            now=NOW,
        )


def test_inactive_user_cannot_receive_new_session(
    database: Session,
) -> None:
    user = _user(
        database,
        active=False,
    )
    service = _service(
        database
    )

    with pytest.raises(
        SessionInactiveUserError,
    ):
        service.create_session(
            user.id,
            now=NOW,
        )


def test_touch_extends_idle_but_never_past_absolute_deadline(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    session_row, _ = service.create_session(
        user.id,
        now=NOW,
    )

    session_row.absolute_expires_at = (
        NOW + timedelta(minutes=90)
    )

    service.touch_session(
        session_row,
        now=NOW + timedelta(minutes=60),
    )

    assert session_row.last_seen_at == (
        NOW + timedelta(minutes=60)
    )

    assert session_row.idle_expires_at == (
        NOW + timedelta(minutes=90)
    )


def test_revoke_all_revokes_multiple_sessions(
    database: Session,
) -> None:
    user = _user(
        database
    )
    service = _service(
        database
    )

    service.create_session(
        user.id,
        now=NOW,
    )
    service.create_session(
        user.id,
        now=NOW,
    )

    count = service.revoke_all_for_user(
        user.id,
        "password_changed",
        now=NOW,
    )

    assert count == 2

    database.expire_all()

    rows = list(
        database.scalars(
            select(AuthSession).where(
                AuthSession.user_id == user.id,
            )
        )
    )

    assert len(rows) == 2

    assert all(
        row.revoked_at is not None
        for row in rows
    )

    assert {
        row.revoked_reason
        for row in rows
    } == {
        "password_changed",
    }
