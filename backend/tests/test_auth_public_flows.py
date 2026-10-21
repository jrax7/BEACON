from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import (
    create_engine,
    select,
)
from sqlalchemy.orm import sessionmaker

import app.routers.auth as auth_router

from app.auth.sessions import SessionService
from app.auth.tokens import (
    issue_password_reset_token,
    issue_verification_token,
)
from app.config import settings
from app.database import get_database_session
from app.models.auth_session import AuthSession
from app.models.email_verification_token import (
    EmailVerificationToken,
)
from app.models.password_reset_token import (
    PasswordResetToken,
)
from app.models.organization import Organization
from app.models.organization_invitation import (
    OrganizationInvitation,
)
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.user import User
from app.organizations.invitations import (
    create_invitation,
    issue_invitation_token,
)
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
    get_user_membership,
)
from app.security.auth import (
    hash_password,
    verify_password,
)


PASSWORD = "OriginalPassword-2026"
NEW_PASSWORD = "RecoveredPassword-2026"


class AllowRateLimiter:
    def check(
        self,
        policy_name,
        value,
    ):
        class Decision:
            allowed = True
            count = 1
            retry_after = 0

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


class DenyRateLimiter(
    AllowRateLimiter
):
    def check(
        self,
        policy_name,
        value,
    ):
        class Decision:
            allowed = False
            count = 99
            retry_after = 60

        return Decision()


class FakeMailTask:
    def __init__(
        self,
        calls,
        session_factory,
    ):
        self.calls = calls
        self.session_factory = (
            session_factory
        )

    def delay(
        self,
        user_id,
        purpose,
    ):
        user_uuid = UUID(
            str(
                user_id
            )
        )

        # Opens an independent DB session against a file-backed
        # SQLite DB. This proves the registration transaction
        # committed before the task was queued.
        with self.session_factory() as database:
            visible = (
                database.get(
                    User,
                    user_uuid,
                )
                is not None
            )

        self.calls.append(
            {
                "user_id":
                    str(
                        user_id
                    ),
                "purpose":
                    purpose,
                "user_visible":
                    visible,
            }
        )


@pytest.fixture
def public_api(
    monkeypatch,
    tmp_path,
):
    database_path = (
        tmp_path
        / "task8.sqlite"
    )

    engine = create_engine(
        "sqlite+pysqlite:///"
        + str(
            database_path
        ),
        connect_args={
            "check_same_thread":
                False,
        },
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

    AuthSession.__table__.create(
        engine
    )

    EmailVerificationToken.__table__.create(
        engine
    )

    PasswordResetToken.__table__.create(
        engine
    )

    SessionFactory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    monkeypatch.setattr(
        settings,
        "registration_enabled",
        True,
    )

    monkeypatch.setattr(
        settings,
        "browser_origins",
        "http://testserver",
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
        "trusted_proxy_cidrs",
        "",
    )

    monkeypatch.setattr(
        auth_router,
        "RedisRateLimiter",
        AllowRateLimiter,
    )

    monkeypatch.setattr(
        auth_router,
        "verify_turnstile",
        lambda *args, **kwargs:
            True,
        raising=False,
    )

    # Audit behavior has its own focused tests. This API fixture
    # intentionally avoids requiring PostgreSQL JSONB on SQLite.
    monkeypatch.setattr(
        auth_router,
        "write_auth_audit",
        lambda *args, **kwargs:
            None,
        raising=False,
    )

    mail_calls = []

    monkeypatch.setattr(
        auth_router,
        "send_auth_lifecycle_email",
        FakeMailTask(
            mail_calls,
            SessionFactory,
        ),
        raising=False,
    )

    app = FastAPI()

    app.include_router(
        auth_router.router
    )

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
        verified: bool,
    ):
        with SessionFactory() as database:
            user = User(
                id=uuid4(),
                email=email,
                full_name="Task Eight User",
                password_hash=hash_password(
                    PASSWORD
                ),
                role="user",
                is_active=True,
                is_email_verified=verified,
            )

            database.add(
                user
            )

            database.flush()

            create_personal_organization(
                database,
                user,
                role=OrganizationRole.ADMIN,
            )

            database.commit()

            return user.id

    def create_invitation_token(
        email: str,
        *,
        role: OrganizationRole = (
            OrganizationRole.ANALYST
        ),
    ):
        owner_id = create_user(
            "invitation-owner@example.com",
            verified=True,
        )

        with SessionFactory() as database:
            owner = database.get(
                User,
                owner_id,
            )

            membership = (
                get_user_membership(
                    database,
                    owner_id,
                )
            )

            invitation = create_invitation(
                database,
                organization_id=(
                    membership.organization_id
                ),
                email=email,
                role=role,
                invited_by_user_id=owner.id,
            )

            raw = issue_invitation_token(
                database,
                invitation,
            )

            database.commit()

            return (
                raw,
                membership.organization_id,
                invitation.id,
            )

    with TestClient(app) as client:
        yield {
            "client":
                client,
            "factory":
                SessionFactory,
            "mail_calls":
                mail_calls,
            "create_user":
                create_user,
            "create_invitation_token":
                create_invitation_token,
            "module":
                auth_router,
            "monkeypatch":
                monkeypatch,
        }

    engine.dispose()


def test_registration_creates_unverified_user_and_queues_after_commit(
    public_api,
) -> None:
    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/register",
        json={
            "email":
                "new-user@example.com",
            "full_name":
                "New User",
            "password":
                PASSWORD,
            "turnstile_token":
                "turnstile-response",
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert (
        body[
            "is_email_verified"
        ]
        is False
    )

    assert (
        "access_token"
        not in body
    )

    assert (
        "beacon_session"
        not in response.cookies
    )

    assert len(
        public_api[
            "mail_calls"
        ]
    ) == 1

    call = public_api[
        "mail_calls"
    ][0]

    assert (
        call[
            "purpose"
        ]
        == "verify_email"
    )

    assert (
        call[
            "user_visible"
        ]
        is True
    )


def test_registration_disabled_is_explicit(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        settings,
        "registration_enabled",
        False,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/register",
        json={
            "email":
                "disabled@example.com",
            "full_name":
                "Disabled User",
            "password":
                PASSWORD,
            "turnstile_token":
                "token",
        },
    )

    assert response.status_code == 503

    assert (
        response.json()[
            "detail"
        ]["code"]
        == "REGISTRATION_DISABLED"
    )


def test_registration_turnstile_failure_creates_no_user(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "verify_turnstile",
        lambda *args, **kwargs:
            False,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/register",
        json={
            "email":
                "blocked@example.com",
            "full_name":
                "Blocked User",
            "password":
                PASSWORD,
            "turnstile_token":
                "bad-token",
        },
    )

    assert response.status_code == 400

    with public_api[
        "factory"
    ]() as database:
        assert (
            database.scalar(
                select(User).where(
                    User.email
                    == "blocked@example.com"
                )
            )
            is None
        )


def test_registration_rate_limit_returns_429(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "RedisRateLimiter",
        DenyRateLimiter,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/register",
        json={
            "email":
                "limited@example.com",
            "full_name":
                "Limited User",
            "password":
                PASSWORD,
            "turnstile_token":
                "token",
        },
    )

    assert response.status_code == 429

    assert (
        response.json()[
            "detail"
        ]["code"]
        == "AUTH_THROTTLED"
    )


def test_verification_is_one_time_and_does_not_revoke_session(
    public_api,
) -> None:
    user_id = public_api[
        "create_user"
    ](
        "verify@example.com",
        verified=False,
    )

    with public_api[
        "factory"
    ]() as database:
        session_row, _ = (
            SessionService(
                database
            ).create_session(
                user_id
            )
        )

        _, raw = (
            issue_verification_token(
                database,
                user_id,
            )
        )

        database.commit()

        session_id = (
            session_row.id
        )

    first = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verify",
        json={
            "token":
                raw,
        },
    )

    assert first.status_code == 200

    with public_api[
        "factory"
    ]() as database:
        user = database.get(
            User,
            user_id,
        )

        session_row = database.get(
            AuthSession,
            session_id,
        )

        assert (
            user.is_email_verified
        )

        assert (
            session_row.revoked_at
            is None
        )

    reused = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verify",
        json={
            "token":
                raw,
        },
    )

    assert reused.status_code == 400


def test_expired_verification_token_is_rejected(
    public_api,
) -> None:
    user_id = public_api[
        "create_user"
    ](
        "expired-verify@example.com",
        verified=False,
    )

    old_now = (
        datetime.now(
            timezone.utc
        )
        - timedelta(
            hours=25
        )
    )

    with public_api[
        "factory"
    ]() as database:
        _, raw = (
            issue_verification_token(
                database,
                user_id,
                now=old_now,
            )
        )

        database.commit()

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verify",
        json={
            "token":
                raw,
        },
    )

    assert response.status_code == 400


def test_resend_is_generic_and_only_unverified_known_user_queues_mail(
    public_api,
) -> None:
    public_api[
        "create_user"
    ](
        "resend@example.com",
        verified=False,
    )

    known = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verification/resend",
        json={
            "email":
                "resend@example.com",
            "turnstile_token":
                "token",
        },
    )

    unknown = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verification/resend",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "token",
        },
    )

    assert known.status_code == 200
    assert unknown.status_code == 200

    assert (
        known.json()
        == unknown.json()
    )

    assert len(
        public_api[
            "mail_calls"
        ]
    ) == 1

    assert (
        public_api[
            "mail_calls"
        ][0]["purpose"]
        == "verify_email"
    )


def test_resend_turnstile_failure_is_rejected(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "verify_turnstile",
        lambda *args, **kwargs:
            False,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verification/resend",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "bad",
        },
    )

    assert response.status_code == 400


def test_resend_rate_limit_is_enforced(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "RedisRateLimiter",
        DenyRateLimiter,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/email/verification/resend",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "token",
        },
    )

    assert response.status_code == 429


def test_forgot_is_generic_and_unknown_account_queues_no_mail(
    public_api,
) -> None:
    public_api[
        "create_user"
    ](
        "forgot@example.com",
        verified=True,
    )

    known = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/forgot",
        json={
            "email":
                "forgot@example.com",
            "turnstile_token":
                "token",
        },
    )

    unknown = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/forgot",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "token",
        },
    )

    assert known.status_code == 200
    assert unknown.status_code == 200

    assert (
        known.json()
        == unknown.json()
    )

    assert len(
        public_api[
            "mail_calls"
        ]
    ) == 1

    assert (
        public_api[
            "mail_calls"
        ][0]["purpose"]
        == "reset_password"
    )


def test_forgot_turnstile_failure_is_rejected(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "verify_turnstile",
        lambda *args, **kwargs:
            False,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/forgot",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "bad",
        },
    )

    assert response.status_code == 400


def test_forgot_rate_limit_is_enforced(
    public_api,
) -> None:
    public_api[
        "monkeypatch"
    ].setattr(
        public_api[
            "module"
        ],
        "RedisRateLimiter",
        DenyRateLimiter,
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/forgot",
        json={
            "email":
                "unknown@example.com",
            "turnstile_token":
                "token",
        },
    )

    assert response.status_code == 429


def test_reset_changes_password_revokes_all_and_requires_fresh_login(
    public_api,
) -> None:
    user_id = public_api[
        "create_user"
    ](
        "reset@example.com",
        verified=True,
    )

    with public_api[
        "factory"
    ]() as database:
        service = SessionService(
            database
        )

        service.create_session(
            user_id
        )

        service.create_session(
            user_id
        )

        _, raw = (
            issue_password_reset_token(
                database,
                user_id,
            )
        )

        database.commit()

    reset = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/reset",
        json={
            "token":
                raw,
            "new_password":
                NEW_PASSWORD,
        },
    )

    assert reset.status_code == 200

    with public_api[
        "factory"
    ]() as database:
        user = database.get(
            User,
            user_id,
        )

        assert verify_password(
            NEW_PASSWORD,
            user.password_hash,
        )

        assert not verify_password(
            PASSWORD,
            user.password_hash,
        )

        sessions = list(
            database.scalars(
                select(
                    AuthSession
                ).where(
                    AuthSession.user_id
                    == user_id
                )
            )
        )

        assert len(
            sessions
        ) == 2

        assert all(
            row.revoked_at
            is not None
            for row in sessions
        )

    reused = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/reset",
        json={
            "token":
                raw,
            "new_password":
                NEW_PASSWORD,
        },
    )

    assert reused.status_code == 400

    old_login = public_api[
        "client"
    ].post(
        "/api/v1/auth/login",
        json={
            "email":
                "reset@example.com",
            "password":
                PASSWORD,
        },
        headers={
            "Origin":
                "http://testserver",
        },
    )

    assert old_login.status_code == 401

    new_login = public_api[
        "client"
    ].post(
        "/api/v1/auth/login",
        json={
            "email":
                "reset@example.com",
            "password":
                NEW_PASSWORD,
        },
        headers={
            "Origin":
                "http://testserver",
        },
    )

    assert new_login.status_code == 200


def test_expired_reset_token_is_rejected(
    public_api,
) -> None:
    user_id = public_api[
        "create_user"
    ](
        "expired-reset@example.com",
        verified=True,
    )

    old_now = (
        datetime.now(
            timezone.utc
        )
        - timedelta(
            minutes=31
        )
    )

    with public_api[
        "factory"
    ]() as database:
        _, raw = (
            issue_password_reset_token(
                database,
                user_id,
                now=old_now,
            )
        )

        database.commit()

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/password/reset",
        json={
            "token":
                raw,
            "new_password":
                NEW_PASSWORD,
        },
    )

    assert response.status_code == 400



def test_registration_with_invitation_joins_existing_org(
    public_api,
) -> None:
    raw_token, organization_id, invitation_id = (
        public_api[
            "create_invitation_token"
        ](
            "invited-user@example.com",
            role=OrganizationRole.VIEWER,
        )
    )

    response = public_api[
        "client"
    ].post(
        "/api/v1/auth/register",
        json={
            "email":
                "invited-user@example.com",
            "full_name":
                "Invited User",
            "password":
                PASSWORD,
            "turnstile_token":
                "turnstile-response",
            "invitation_token":
                raw_token,
        },
    )

    assert (
        response.status_code
        == 201
    )

    body = response.json()

    assert (
        body[
            "organization_id"
        ]
        == str(
            organization_id
        )
    )

    assert (
        body[
            "organization_role"
        ]
        == OrganizationRole.VIEWER.value
    )

    with public_api[
        "factory"
    ]() as database:
        user = database.scalar(
            select(
                User
            ).where(
                User.email
                == "invited-user@example.com"
            )
        )

        membership = (
            get_user_membership(
                database,
                user.id,
            )
        )

        invitation = database.get(
            OrganizationInvitation,
            invitation_id,
        )

        assert (
            membership.organization_id
            == organization_id
        )

        assert (
            membership.role
            == OrganizationRole.VIEWER.value
        )

        assert (
            invitation.accepted_at
            is not None
        )

        assert (
            invitation.token_hash
            is None
        )
