from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Annotated,
    Literal,
)
from urllib.parse import urlsplit
from uuid import (
    UUID,
)

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.csrf import validate_csrf_token
from app.auth.crypto import hash_opaque_token
from app.auth.errors import (
    InvalidSessionError,
    SessionExpiredError,
    SessionInactiveUserError,
    SessionRevokedError,
    auth_error_detail,
)
from app.auth.sessions import SessionService
from app.config import settings
from app.database import get_database_session
from app.models.auth_session import AuthSession
from app.models.user import User
from app.security.auth import decode_access_token


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/token",
    auto_error=False,
)


SAFE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}

CSRF_HEADER_NAME = "X-CSRF-Token"
ORGANIZATION_HEADER_NAME = "X-Organization-ID"
ORIGIN_HEADER_NAME = "Origin"
REFERER_HEADER_NAME = "Referer"


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Resolved BEACON authentication identity."""

    user: User
    mechanism: Literal[
        "session",
        "bearer",
    ]
    session_id: UUID | None
    organization_id: UUID | None


def _requested_organization_id(
    request: Request,
) -> UUID | None:
    raw_value = request.headers.get(
        ORGANIZATION_HEADER_NAME
    )

    if raw_value is None or not raw_value.strip():
        return None

    try:
        return UUID(raw_value.strip())
    except ValueError as exc:
        raise _auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="ORGANIZATION_CONTEXT_INVALID",
            message="The organization selector is invalid.",
        ) from exc


def _auth_error(
    *,
    status_code: int,
    code: str,
    message: str,
    bearer_challenge: bool = False,
) -> HTTPException:
    headers = None

    if bearer_challenge:
        headers = {
            "WWW-Authenticate": "Bearer",
        }

    return HTTPException(
        status_code=status_code,
        detail=auth_error_detail(
            code,
            message,
        ),
        headers=headers,
    )


def _canonical_origin(
    value: str,
    *,
    allow_path: bool,
) -> str | None:
    candidate = value.strip()

    if not candidate:
        return None

    parsed = urlsplit(
        candidate
    )

    if (
        parsed.scheme.lower()
        not in {
            "http",
            "https",
        }
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None

    if (
        not allow_path
        and parsed.path not in {
            "",
            "/",
        }
    ):
        return None

    return (
        f"{parsed.scheme.lower()}://"
        f"{parsed.netloc.lower()}"
    )


def _allowed_browser_origins() -> set[str]:
    origins: set[str] = set()

    for raw in settings.browser_origins.split(","):
        normalized = _canonical_origin(
            raw,
            allow_path=False,
        )

        if normalized:
            origins.add(
                normalized
            )

    return origins


def _request_origin(
    request: Request,
) -> str | None:
    # Literal header names are intentionally kept here as
    # part of the security contract and test visibility.
    origin = request.headers.get(
        ORIGIN_HEADER_NAME
    )

    if origin:
        return _canonical_origin(
            origin,
            allow_path=False,
        )

    referer = request.headers.get(
        REFERER_HEADER_NAME
    )

    if referer:
        return _canonical_origin(
            referer,
            allow_path=True,
        )

    return None


def _enforce_session_request_protection(
    request: Request,
    session_id: UUID,
) -> None:
    if request.method.upper() in SAFE_METHODS:
        return

    candidate_origin = _request_origin(
        request
    )

    if (
        candidate_origin is None
        or candidate_origin
        not in _allowed_browser_origins()
    ):
        raise _auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ORIGIN_INVALID",
            message=(
                "The request origin is not allowed."
            ),
        )

    candidate_csrf = request.headers.get(
        CSRF_HEADER_NAME
    )

    if (
        not candidate_csrf
        or not validate_csrf_token(
            session_id,
            candidate_csrf,
            settings.csrf_secret,
        )
    ):
        raise _auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="CSRF_INVALID",
            message=(
                "The CSRF token is missing or invalid."
            ),
        )


def _resolve_bearer_user(
    raw_token: str,
    database: Session,
) -> User:
    try:
        user_id = UUID(
            decode_access_token(
                raw_token
            )
        )
    except (
        ValueError,
        TypeError,
    ):
        raise _auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="AUTH_REQUIRED",
            message=(
                "Authentication credentials are "
                "invalid or expired."
            ),
            bearer_challenge=True,
        )

    user = database.get(
        User,
        user_id,
    )

    if user is None:
        raise _auth_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="AUTH_REQUIRED",
            message=(
                "Authentication credentials are "
                "invalid or expired."
            ),
            bearer_challenge=True,
        )

    if not user.is_active:
        raise _auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="ACCOUNT_INACTIVE",
            message=(
                "This user account is inactive."
            ),
        )

    if not user.is_email_verified:
        raise _auth_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="EMAIL_VERIFICATION_REQUIRED",
            message=(
                "Email verification is required."
            ),
        )

    return user


def get_logout_principal(
    request: Request,
    database: Annotated[
        Session,
        Depends(
            get_database_session
        ),
    ],
    bearer_token: Annotated[
        str | None,
        Depends(
            oauth2_scheme
        ),
    ] = None,
) -> AuthenticatedPrincipal:
    """Resolve logout without requiring an active session lifetime."""

    raw_session = request.cookies.get(
        settings.session_cookie_name
    )

    bearer_token = (
        bearer_token.strip()
        if bearer_token
        else None
    )

    raw_session = (
        raw_session.strip()
        if raw_session
        else None
    )

    if bearer_token and raw_session:
        raise _auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="AUTH_MIXED_CREDENTIALS",
            message=(
                "Use either a browser session or "
                "a bearer token, not both."
            ),
        )

    if bearer_token:
        user = _resolve_bearer_user(
            bearer_token,
            database,
        )

        return AuthenticatedPrincipal(
            user=user,
            mechanism="bearer",
            session_id=None,
            organization_id=_requested_organization_id(request),
        )

    if raw_session:
        session_row = database.scalar(
            select(
                AuthSession
            ).where(
                AuthSession.token_hash
                == hash_opaque_token(
                    raw_session
                )
            )
        )

        if session_row is None:
            raise _auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="AUTH_REQUIRED",
                message=(
                    "Authentication credentials are "
                    "invalid or expired."
                ),
            )

        user = database.get(
            User,
            session_row.user_id,
        )

        if user is None:
            raise _auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="AUTH_REQUIRED",
                message=(
                    "Authentication credentials are "
                    "invalid or expired."
                ),
            )

        # Logout remains an unsafe browser operation.
        # Even a stale revoked/expired session must prove
        # same-origin + possession of its session-bound CSRF value.
        _enforce_session_request_protection(
            request,
            session_row.id,
        )

        requested_organization_id = _requested_organization_id(request)

        return AuthenticatedPrincipal(
            user=user,
            mechanism="session",
            session_id=session_row.id,
            organization_id=(
                requested_organization_id
                if requested_organization_id is not None
                else session_row.active_organization_id
            ),
        )

    raise _auth_error(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code="AUTH_REQUIRED",
        message=(
            "Authentication is required."
        ),
        bearer_challenge=True,
    )


def get_current_principal(
    request: Request,
    database: Annotated[
        Session,
        Depends(
            get_database_session
        ),
    ],
    bearer_token: Annotated[
        str | None,
        Depends(
            oauth2_scheme
        ),
    ] = None,
) -> AuthenticatedPrincipal:
    """Resolve exactly one browser-session or bearer credential."""

    raw_session = request.cookies.get(
        settings.session_cookie_name
    )

    bearer_token = (
        bearer_token.strip()
        if bearer_token
        else None
    )

    raw_session = (
        raw_session.strip()
        if raw_session
        else None
    )

    if bearer_token and raw_session:
        raise _auth_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="AUTH_MIXED_CREDENTIALS",
            message=(
                "Use either a browser session or "
                "a bearer token, not both."
            ),
        )

    if bearer_token:
        user = _resolve_bearer_user(
            bearer_token,
            database,
        )

        return AuthenticatedPrincipal(
            user=user,
            mechanism="bearer",
            session_id=None,
            organization_id=_requested_organization_id(request),
        )

    if raw_session:
        service = SessionService(
            database
        )

        try:
            session_row = service.resolve_session(
                raw_session
            )
        except SessionInactiveUserError:
            raise _auth_error(
                status_code=status.HTTP_403_FORBIDDEN,
                code="ACCOUNT_INACTIVE",
                message=(
                    "This user account is inactive."
                ),
            )
        except (
            InvalidSessionError,
            SessionExpiredError,
            SessionRevokedError,
        ) as exc:
            raise _auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code=exc.code,
                message=(
                    "The browser session is invalid "
                    "or has expired."
                ),
            )

        user = database.get(
            User,
            session_row.user_id,
        )

        if user is None:
            raise _auth_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                code="AUTH_REQUIRED",
                message=(
                    "Authentication is required."
                ),
            )

        if not user.is_email_verified:
            raise _auth_error(
                status_code=status.HTTP_403_FORBIDDEN,
                code="EMAIL_VERIFICATION_REQUIRED",
                message=(
                    "Email verification is required."
                ),
            )

        _enforce_session_request_protection(
            request,
            session_row.id,
        )

        # Persist the rolling idle deadline before the endpoint
        # executes. This commit cannot include endpoint mutations
        # because dependency resolution happens first.
        service.touch_session(
            session_row
        )
        database.commit()

        requested_organization_id = _requested_organization_id(request)

        return AuthenticatedPrincipal(
            user=user,
            mechanism="session",
            session_id=session_row.id,
            organization_id=(
                requested_organization_id
                if requested_organization_id is not None
                else session_row.active_organization_id
            ),
        )

    raise _auth_error(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code="AUTH_REQUIRED",
        message=(
            "Authentication is required."
        ),
        bearer_challenge=True,
    )
