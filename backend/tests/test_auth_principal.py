from __future__ import annotations

from dataclasses import fields
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import uuid4

import pytest
from fastapi import (
    FastAPI,
)
from fastapi.testclient import TestClient
from sqlalchemy import (
    create_engine,
    select,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.dependencies.auth import CurrentPrincipal


PASSWORD = "ValidPassword-2026"


def test_authenticated_principal_contract_exists() -> None:
    from app.auth.principal import AuthenticatedPrincipal

    assert [
        field.name
        for field in fields(
            AuthenticatedPrincipal
        )
    ] == [
        "user",
        "mechanism",
        "session_id",
        "organization_id",
    ]


def test_current_principal_dependency_exists() -> None:
    from app.auth.principal import get_current_principal

    assert callable(
        get_current_principal
    )


def test_bearer_dependency_is_optional_and_uses_token_endpoint() -> None:
    from app.dependencies.auth import oauth2_scheme

    assert oauth2_scheme.auto_error is False

    assert (
        oauth2_scheme.model.flows.password.tokenUrl
        == "/api/v1/auth/token"
    )


def test_existing_current_user_contract_remains_available() -> None:
    from app.dependencies.auth import (
        CurrentUser,
        get_current_user,
    )

    assert CurrentUser is not None
    assert callable(
        get_current_user
    )


@pytest.fixture
def principal_probe(monkeypatch):
    from app.auth.csrf import derive_csrf_token
    from app.auth.sessions import SessionService
    from app.config import settings
    from app.database import get_database_session
    from app.models.auth_session import AuthSession
    from app.models.user import User
    from app.security.auth import (
        create_access_token,
        hash_password,
    )

    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    User.__table__.create(
        engine
    )
    AuthSession.__table__.create(
        engine
    )

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

    app = FastAPI()

    def override_database():
        database = SessionFactory()

        try:
            yield database
        finally:
            database.close()

    app.dependency_overrides[
        get_database_session
    ] = override_database

    @app.api_route(
        "/probe",
        methods=[
            "GET",
            "POST",
        ],
    )
    def probe(
        principal: CurrentPrincipal,
    ):
        return {
            "email": principal.user.email,
            "mechanism": principal.mechanism,
            "session_id": (
                str(principal.session_id)
                if principal.session_id
                else None
            ),
            "organization_id": (
                str(principal.organization_id)
                if principal.organization_id
                else None
            ),
            "organization_id": (
                str(principal.organization_id)
                if principal.organization_id
                else None
            ),
        }

    with SessionFactory() as database:
        user = User(
            id=uuid4(),
            email="principal@example.test",
            full_name="Principal User",
            password_hash=hash_password(
                PASSWORD
            ),
            role="user",
            is_active=True,
            is_email_verified=True,
        )

        database.add(
            user
        )
        database.commit()

        user_id = user.id

    def issue_session():
        with SessionFactory() as database:
            service = SessionService(
                database
            )

            session_row, raw_cookie = service.create_session(
                user_id,
                created_ip="203.0.113.10",
                user_agent="pytest",
            )

            database.commit()

            csrf_token = derive_csrf_token(
                session_row.id,
                settings.csrf_secret,
            )

            return (
                session_row.id,
                raw_cookie,
                csrf_token,
            )

    bearer_token, _ = create_access_token(
        subject=str(user_id)
    )

    with TestClient(app) as client:
        yield {
            "client": client,
            "factory": SessionFactory,
            "user_id": user_id,
            "bearer": bearer_token,
            "issue_session": issue_session,
            "AuthSession": AuthSession,
        }

    engine.dispose()


def test_bearer_auth_resolves_principal_without_csrf(
    principal_probe,
) -> None:
    client = principal_probe["client"]

    response = client.post(
        "/probe",
        headers={
            "Authorization": (
                "Bearer "
                + principal_probe["bearer"]
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["mechanism"] == "bearer"
    assert response.json()["session_id"] is None


def test_organization_selector_is_parsed_into_principal(
    principal_probe,
) -> None:
    organization_id = uuid4()
    response = principal_probe["client"].get(
        "/probe",
        headers={
            "Authorization": "Bearer " + principal_probe["bearer"],
            "X-Organization-ID": str(organization_id),
        },
    )

    assert response.status_code == 200
    assert response.json()["organization_id"] == str(organization_id)


def test_invalid_organization_selector_fails_closed(
    principal_probe,
) -> None:
    response = principal_probe["client"].get(
        "/probe",
        headers={
            "Authorization": "Bearer " + principal_probe["bearer"],
            "X-Organization-ID": "not-a-uuid",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "ORGANIZATION_CONTEXT_INVALID"


def test_session_auth_resolves_principal(
    principal_probe,
) -> None:
    (
        session_id,
        raw_cookie,
        _,
    ) = principal_probe["issue_session"]()

    response = principal_probe["client"].get(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["mechanism"] == "session"
    assert body["session_id"] == str(
        session_id
    )


def test_session_uses_saved_organization_when_header_is_absent(
    principal_probe,
) -> None:
    organization_id = uuid4()
    _, raw_cookie, _ = principal_probe["issue_session"]()
    factory = principal_probe["factory"]
    AuthSession = principal_probe["AuthSession"]
    with factory() as database:
        row = database.scalar(select(AuthSession))
        row.active_organization_id = organization_id
        database.commit()
    response = principal_probe["client"].get(
        "/probe",
        cookies={"beacon_session": raw_cookie},
    )
    assert response.status_code == 200
    assert response.json()["organization_id"] == str(organization_id)


def test_mixed_session_and_bearer_credentials_are_rejected(
    principal_probe,
) -> None:
    _, raw_cookie, _ = principal_probe[
        "issue_session"
    ]()

    response = principal_probe["client"].get(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
            "Authorization": (
                "Bearer "
                + principal_probe["bearer"]
            ),
        },
    )

    assert response.status_code == 400

    assert (
        response.json()["detail"]["code"]
        == "AUTH_MIXED_CREDENTIALS"
    )


def test_session_unsafe_request_requires_origin(
    principal_probe,
) -> None:
    _, raw_cookie, _ = principal_probe[
        "issue_session"
    ]()

    response = principal_probe["client"].post(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
        },
    )

    assert response.status_code == 403

    assert (
        response.json()["detail"]["code"]
        == "ORIGIN_INVALID"
    )


def test_session_unsafe_request_requires_csrf(
    principal_probe,
) -> None:
    _, raw_cookie, _ = principal_probe[
        "issue_session"
    ]()

    response = principal_probe["client"].post(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
            "Origin": "http://testserver",
        },
    )

    assert response.status_code == 403

    assert (
        response.json()["detail"]["code"]
        == "CSRF_INVALID"
    )


def test_session_unsafe_request_accepts_origin_and_csrf(
    principal_probe,
) -> None:
    _, raw_cookie, csrf_token = principal_probe[
        "issue_session"
    ]()

    response = principal_probe["client"].post(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
            "Origin": "http://testserver",
            "X-CSRF-Token": csrf_token,
        },
    )

    assert response.status_code == 200
    assert response.json()["mechanism"] == "session"


def test_referer_is_accepted_as_same_origin_fallback(
    principal_probe,
) -> None:
    _, raw_cookie, csrf_token = principal_probe[
        "issue_session"
    ]()

    response = principal_probe["client"].post(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
            "Referer": (
                "http://testserver/settings"
            ),
            "X-CSRF-Token": csrf_token,
        },
    )

    assert response.status_code == 200


def test_session_auth_persists_idle_touch(
    principal_probe,
) -> None:
    (
        session_id,
        raw_cookie,
        _,
    ) = principal_probe["issue_session"]()

    factory = principal_probe["factory"]
    AuthSession = principal_probe[
        "AuthSession"
    ]

    before = (
        datetime.now(timezone.utc)
        - timedelta(minutes=20)
    )

    with factory() as database:
        row = database.get(
            AuthSession,
            session_id,
        )

        row.last_seen_at = before
        database.commit()

    response = principal_probe["client"].get(
        "/probe",
        headers={
            "Cookie": (
                "beacon_session="
                + raw_cookie
            ),
        },
    )

    assert response.status_code == 200

    with factory() as database:
        row = database.scalar(
            select(AuthSession).where(
                AuthSession.id == session_id
            )
        )

        assert row.last_seen_at != before
