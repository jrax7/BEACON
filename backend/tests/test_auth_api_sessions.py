from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import (
    create_engine,
    select,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.sessions import SessionService
from app.config import settings
from app.database import get_database_session
from app.models.auth_session import AuthSession
from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
)
from app.routers.auth import router
from app.security.auth import hash_password


BACKEND = Path(__file__).resolve().parents[1]

ROUTER_PATH = (
    BACKEND
    / "app"
    / "routers"
    / "auth.py"
)

SCHEMA_PATH = (
    BACKEND
    / "app"
    / "schemas"
    / "auth.py"
)

PASSWORD = "OriginalPassword-2026"
NEW_PASSWORD = "ChangedPassword-2026"


class AllowAllRateLimiter:
    def check(
        self,
        policy_name,
        value,
    ):
        class Decision:
            allowed = True
            retry_after = 0
            count = 1

        return Decision()

    def login_cooldown_retry_after(
        self,
        identity,
    ):
        return 0

    def record_login_failure(
        self,
        identity,
    ):
        return 0

    def clear_login_failures(
        self,
        identity,
    ):
        return None


def _router_source() -> str:
    return ROUTER_PATH.read_text(
        encoding="utf-8",
    )


def _schema_source() -> str:
    return SCHEMA_PATH.read_text(
        encoding="utf-8",
    )


@pytest.fixture
def auth_api(monkeypatch):
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    User.__table__.create(engine)
    Organization.__table__.create(engine)
    OrganizationMembership.__table__.create(engine)
    AuthSession.__table__.create(engine)

    SessionFactory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    monkeypatch.setattr(
        settings,
        "session_cookie_name",
        "beacon_session",
    )
    monkeypatch.setattr(
        settings,
        "session_cookie_secure",
        False,
    )
    monkeypatch.setattr(
        settings,
        "session_idle_minutes",
        60,
    )
    monkeypatch.setattr(
        settings,
        "session_absolute_hours",
        12,
    )
    monkeypatch.setattr(
        settings,
        "csrf_secret",
        "c" * 64,
    )
    monkeypatch.setattr(
        settings,
        "browser_origins",
        "http://testserver",
    )
    monkeypatch.setattr(
        settings,
        "trusted_proxy_cidrs",
        "",
    )

    monkeypatch.setattr(
        "app.routers.auth.RedisRateLimiter",
        AllowAllRateLimiter,
    )

    monkeypatch.setattr(
        "app.routers.auth.write_auth_audit",
        lambda *args, **kwargs: None,
    )

    app = FastAPI()
    app.include_router(router)

    def override_database():
        database = SessionFactory()

        try:
            yield database
        finally:
            database.close()

    app.dependency_overrides[
        get_database_session
    ] = override_database

    def create_user(
        email: str,
        *,
        verified: bool = True,
        active: bool = True,
        password: str = PASSWORD,
    ):
        with SessionFactory() as database:
            user = User(
                id=uuid4(),
                email=email,
                full_name="Auth API User",
                password_hash=hash_password(password),
                role="user",
                is_active=active,
                is_email_verified=verified,
            )

            database.add(user)
            database.flush()

            create_personal_organization(
                database,
                user,
                role=OrganizationRole.ADMIN,
            )

            database.commit()

            return user.id

    with TestClient(app) as client:
        client.headers.update(
            {
                "Origin":
                    "http://testserver",
            }
        )

        yield {
            "client": client,
            "factory": SessionFactory,
            "create_user": create_user,
        }

    engine.dispose()


def test_browser_and_programmatic_login_routes_are_split() -> None:
    source = _router_source()

    assert '"/login"' in source
    assert '"/token"' in source


def test_browser_login_uses_server_session_contract() -> None:
    router_source = _router_source()
    schema_source = _schema_source()

    assert "BrowserLoginRequest" in schema_source
    assert "BrowserLoginRequest" in router_source
    assert "SessionService" in router_source
    assert "set_cookie" in router_source
    assert "X-CSRF-Token" in router_source


def test_logout_and_password_change_contracts_exist() -> None:
    router_source = _router_source()
    schema_source = _schema_source()

    assert '"/logout"' in router_source
    assert '"/password/change"' in router_source
    assert "PasswordChangeRequest" in schema_source


def test_auth_error_contracts_exist() -> None:
    source = _router_source()

    assert "AUTH_INVALID_CREDENTIALS" in source
    assert "EMAIL_VERIFICATION_REQUIRED" in source
    assert "Invalid email or password." in source


def test_browser_login_sets_cookie_and_csrf(
    auth_api,
) -> None:
    auth_api["create_user"](
        "browser@example.com"
    )

    response = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "browser@example.com",
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200

    assert (
        response.json()["email"]
        == "browser@example.com"
    )

    assert "access_token" not in response.json()

    csrf = response.headers.get(
        "X-CSRF-Token"
    )

    assert csrf

    cookie = response.headers["set-cookie"]

    assert "beacon_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=43200" in cookie
    assert "Domain=" not in cookie

    me = auth_api["client"].get(
        "/api/v1/auth/me"
    )

    assert me.status_code == 200


def test_programmatic_token_preserves_bearer_jwt(
    auth_api,
) -> None:
    auth_api["create_user"](
        "token@example.com"
    )

    response = auth_api["client"].post(
        "/api/v1/auth/token",
        data={
            "username": "token@example.com",
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600

    auth_api["client"].cookies.clear()

    me = auth_api["client"].get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                "Bearer "
                + body["access_token"]
            ),
        },
    )

    assert me.status_code == 200


@pytest.mark.parametrize(
    "kind",
    [
        "session",
        "bearer",
    ],
)
def test_unverified_user_is_rejected(
    auth_api,
    kind,
) -> None:
    auth_api["create_user"](
        "unverified@example.com",
        verified=False,
    )

    if kind == "session":
        response = auth_api["client"].post(
            "/api/v1/auth/login",
            json={
                "email": "unverified@example.com",
                "password": PASSWORD,
            },
        )
    else:
        response = auth_api["client"].post(
            "/api/v1/auth/token",
            data={
                "username": "unverified@example.com",
                "password": PASSWORD,
            },
        )

    assert response.status_code == 403

    assert (
        response.json()["detail"]["code"]
        == "EMAIL_VERIFICATION_REQUIRED"
    )


def test_invalid_credentials_are_generic(
    auth_api,
) -> None:
    response = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "missing@example.com",
            "password": PASSWORD,
        },
    )

    assert response.status_code == 401

    assert response.json()["detail"] == {
        "code": "AUTH_INVALID_CREDENTIALS",
        "message": "Invalid email or password.",
    }


def test_logout_requires_csrf_and_revokes_session(
    auth_api,
) -> None:
    auth_api["create_user"](
        "logout@example.com"
    )

    login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "logout@example.com",
            "password": PASSWORD,
        },
    )

    assert login.status_code == 200

    csrf = login.headers["X-CSRF-Token"]

    rejected = auth_api["client"].post(
        "/api/v1/auth/logout",
        headers={
            "Origin": "",
        },
    )

    assert rejected.status_code == 403

    assert (
        rejected.json()["detail"]["code"]
        == "ORIGIN_INVALID"
    )

    response = auth_api["client"].post(
        "/api/v1/auth/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    me = auth_api["client"].get(
        "/api/v1/auth/me"
    )

    assert me.status_code == 401


def test_mixed_cookie_and_bearer_are_rejected(
    auth_api,
) -> None:
    auth_api["create_user"](
        "mixed@example.com"
    )

    login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "mixed@example.com",
            "password": PASSWORD,
        },
    )

    assert login.status_code == 200

    token = auth_api["client"].post(
        "/api/v1/auth/token",
        data={
            "username": "mixed@example.com",
            "password": PASSWORD,
        },
    )

    assert token.status_code == 200

    response = auth_api["client"].get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                "Bearer "
                + token.json()["access_token"]
            ),
        },
    )

    assert response.status_code == 400

    assert (
        response.json()["detail"]["code"]
        == "AUTH_MIXED_CREDENTIALS"
    )


def test_password_change_revokes_every_browser_session(
    auth_api,
) -> None:
    user_id = auth_api["create_user"](
        "password@example.com"
    )

    login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "password@example.com",
            "password": PASSWORD,
        },
    )

    assert login.status_code == 200

    csrf = login.headers["X-CSRF-Token"]

    with auth_api["factory"]() as database:
        service = SessionService(database)

        service.create_session(
            user_id,
            created_ip="203.0.113.44",
            user_agent="second-session",
        )

        database.commit()

    response = auth_api["client"].post(
        "/api/v1/auth/password/change",
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
        },
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf,
        },
    )

    assert response.status_code == 200

    with auth_api["factory"]() as database:
        sessions = list(
            database.scalars(
                select(AuthSession).where(
                    AuthSession.user_id
                    == user_id
                )
            )
        )

        assert len(sessions) == 2

        assert all(
            row.revoked_at is not None
            for row in sessions
        )

    old_login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "password@example.com",
            "password": PASSWORD,
        },
    )

    assert old_login.status_code == 401

    new_login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email": "password@example.com",
            "password": NEW_PASSWORD,
        },
    )

    assert new_login.status_code == 200


def test_session_me_bootstrap_returns_csrf_header(
    auth_api,
) -> None:
    auth_api["create_user"](
        "bootstrap@example.com"
    )

    login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email":
                "bootstrap@example.com",
            "password":
                PASSWORD,
        },
    )

    assert login.status_code == 200

    csrf = login.headers[
        "X-CSRF-Token"
    ]

    me = auth_api["client"].get(
        "/api/v1/auth/me"
    )

    assert me.status_code == 200

    assert (
        me.headers.get(
            "X-CSRF-Token"
        )
        == csrf
    )


def test_browser_login_rejects_missing_same_origin(
    auth_api,
) -> None:
    auth_api["create_user"](
        "origin@example.com"
    )

    response = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email":
                "origin@example.com",
            "password":
                PASSWORD,
        },
        headers={
            "Origin": "",
        },
    )

    assert response.status_code == 403

    assert (
        response.json()[
            "detail"
        ]["code"]
        == "ORIGIN_INVALID"
    )


def test_logout_is_idempotent_for_already_revoked_session(
    auth_api,
) -> None:
    auth_api["create_user"](
        "logout-idempotent@example.com"
    )

    login = auth_api["client"].post(
        "/api/v1/auth/login",
        json={
            "email":
                "logout-idempotent@example.com",
            "password":
                PASSWORD,
        },
    )

    assert login.status_code == 200

    csrf = login.headers[
        "X-CSRF-Token"
    ]

    raw_cookie = (
        auth_api[
            "client"
        ].cookies.get(
            "beacon_session"
        )
    )

    assert raw_cookie

    first = auth_api["client"].post(
        "/api/v1/auth/logout",
        headers={
            "X-CSRF-Token":
                csrf,
        },
    )

    assert first.status_code == 200

    # Re-present the same now-revoked browser credential to model
    # a stale tab/browser request racing after successful logout.
    auth_api[
        "client"
    ].cookies.set(
        "beacon_session",
        raw_cookie,
    )

    second = auth_api["client"].post(
        "/api/v1/auth/logout",
        headers={
            "X-CSRF-Token":
                csrf,
        },
    )

    assert second.status_code == 200

    assert (
        second.json()[
            "message"
        ]
        == "Signed out."
    )
