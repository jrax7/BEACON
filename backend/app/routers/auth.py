from typing import Annotated
from uuid import UUID
from urllib.parse import urlsplit

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.audit import (
    identity_hash,
    write_auth_audit,
)
from app.auth.client_ip import trusted_client_ip
from app.auth.csrf import derive_csrf_token
from app.auth.errors import auth_error_detail
from app.auth.mail_tasks import send_auth_lifecycle_email
from app.auth.rate_limit import RedisRateLimiter
from app.auth.sessions import SessionService
from app.auth.tokens import (
    PasswordReuseError,
    consume_password_reset_token,
    consume_verification_token,
)
from app.auth.turnstile import verify_turnstile
from app.config import settings
from app.database import get_database_session
from app.dependencies.auth import (
    CurrentLogoutPrincipal,
    CurrentPrincipal,
)
from app.models.auth_session import AuthSession
from app.models.user import User
from app.organizations.context import (
    resolve_organization_context,
)
from app.organizations.invitations import (
    InvitationError,
    accept_invitation,
    resolve_invitation,
)
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
)
from app.schemas.auth import (
    BrowserLoginRequest,
    EmailVerificationRequest,
    ForgotPasswordRequest,
    MessageResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
    RegistrationRequest,
    ResendVerificationRequest,
    TokenResponse,
    UserResponse,
)
from app.security.auth import (
    create_access_token,
    hash_password,
    verify_password,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


DatabaseSession = Annotated[
    Session,
    Depends(
        get_database_session
    ),
]


GENERIC_ACCOUNT_MESSAGE = (
    "If that account exists, an email will be sent."
)


def _auth_http_error(
    *,
    status_code: int,
    code: str,
    message: str,
    bearer_challenge: bool = False,
) -> HTTPException:
    headers = None

    if bearer_challenge:
        headers = {
            "WWW-Authenticate":
                "Bearer",
        }

    return HTTPException(
        status_code=status_code,
        detail=auth_error_detail(
            code,
            message,
        ),
        headers=headers,
    )


def _request_client_ip(
    request: Request,
) -> str:
    return (
        trusted_client_ip(
            request,
            settings,
        )
        or "unknown"
    )


def _canonical_origin(
    value: str | None,
) -> str | None:
    candidate = (
        value
        or ""
    ).strip()

    if not candidate:
        return None

    try:
        parsed = urlsplit(
            candidate
        )
    except ValueError:
        return None

    scheme = (
        parsed.scheme
        .strip()
        .lower()
    )

    if scheme not in {
        "http",
        "https",
    }:
        return None

    if (
        parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    hostname = (
        parsed.hostname
        .lower()
    )

    if (
        ":" in hostname
        and not hostname.startswith(
            "["
        )
    ):
        hostname = (
            f"[{hostname}]"
        )

    default_port = (
        port is None
        or (
            scheme == "http"
            and port == 80
        )
        or (
            scheme == "https"
            and port == 443
        )
    )

    authority = (
        hostname
        if default_port
        else (
            f"{hostname}:"
            f"{port}"
        )
    )

    return (
        f"{scheme}://"
        f"{authority}"
    )


def _configured_browser_origins() -> set[str]:
    configured = (
        settings.browser_origins
    )

    if isinstance(
        configured,
        str,
    ):
        values = configured.split(
            ","
        )
    else:
        values = configured

    allowed = set()

    for value in values:
        origin = _canonical_origin(
            str(
                value
            )
        )

        if origin is not None:
            allowed.add(
                origin
            )

    return allowed


def _enforce_browser_login_origin(
    request: Request,
) -> None:
    origin_header = (
        request.headers.get(
            "origin"
        )
    )

    referer_header = (
        request.headers.get(
            "referer"
        )
    )

    candidate = None

    if (
        origin_header
        and origin_header.strip()
    ):
        candidate = _canonical_origin(
            origin_header
        )

    elif (
        referer_header
        and referer_header.strip()
    ):
        candidate = _canonical_origin(
            referer_header
        )

    if (
        candidate is None
        or candidate
        not in _configured_browser_origins()
    ):
        raise _auth_http_error(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            code="ORIGIN_INVALID",
            message=(
                "The request origin is not allowed."
            ),
        )


def _raise_auth_throttled(
    retry_after: int,
) -> None:
    bounded_retry = max(
        1,
        min(
            int(
                retry_after
                or 1
            ),
            15 * 60,
        ),
    )

    raise HTTPException(
        status_code=(
            status.HTTP_429_TOO_MANY_REQUESTS
        ),
        detail=auth_error_detail(
            "AUTH_THROTTLED",
            (
                "Too many authentication attempts. "
                "Try again later."
            ),
        ),
        headers={
            "Retry-After":
                str(
                    bounded_retry
                ),
        },
    )


def _rate_limit_or_raise(
    limiter: RedisRateLimiter,
    policy_name: str,
    value: object,
) -> None:
    decision = limiter.check(
        policy_name,
        value,
    )

    if not decision.allowed:
        _raise_auth_throttled(
            decision.retry_after
        )


def _known_user(
    database: Session,
    email: str,
) -> User | None:
    return database.scalar(
        select(User).where(
            User.email
            == email.strip().lower()
        )
    )


def _identity_subject(
    database: Session,
    email: str,
) -> tuple[
    User | None,
    dict,
]:
    normalized = (
        email
        .strip()
        .lower()
    )

    user = _known_user(
        database,
        normalized,
    )

    if user is not None:
        return (
            user,
            {},
        )

    return (
        None,
        {
            "identity_hash":
                identity_hash(
                    normalized
                ),
        },
    )


_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$zone48ilLLpDPQL0wzuG0g$L6HVxpOT9ohG6g1in9eoGG0EsWbgeOwzDiFIqcYzMiQ"
)


def _authenticate_credentials(
    email: str,
    password: str,
    database: Session,
) -> User:
    normalized_email = (
        email
        .strip()
        .lower()
    )

    user = _known_user(
        database,
        normalized_email,
    )

    password_hash = (
        user.password_hash
        if user is not None
        else _DUMMY_PASSWORD_HASH
    )

    valid_password = verify_password(
        password,
        password_hash,
    )

    if (
        user is None
        or not valid_password
    ):
        raise _auth_http_error(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            code="AUTH_INVALID_CREDENTIALS",
            message=(
                "Invalid email or password."
            ),
            bearer_challenge=True,
        )

    if not user.is_active:
        raise _auth_http_error(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            code="ACCOUNT_INACTIVE",
            message=(
                "This user account is inactive."
            ),
        )

    if not user.is_email_verified:
        raise _auth_http_error(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            code=(
                "EMAIL_VERIFICATION_REQUIRED"
            ),
            message=(
                "Email verification is required."
            ),
        )

    return user


def _authenticate_with_abuse_controls(
    email: str,
    password: str,
    request: Request,
    database: Session,
    *,
    mechanism: str,
) -> User:
    limiter = RedisRateLimiter()

    source_ip = _request_client_ip(
        request
    )

    normalized_email = (
        email
        .strip()
        .lower()
    )

    known_user, identity_details = (
        _identity_subject(
            database,
            normalized_email,
        )
    )

    ip_decision = limiter.check(
        "login_ip",
        source_ip,
    )

    if not ip_decision.allowed:
        write_auth_audit(
            database,
            action=(
                "auth.login.throttled"
            ),
            user_id=(
                known_user.id
                if known_user
                is not None
                else None
            ),
            ip_address=source_ip,
            details={
                "mechanism":
                    mechanism,
                "reason_code":
                    "source_ip_window",
                **identity_details,
            },
        )

        database.commit()

        _raise_auth_throttled(
            ip_decision.retry_after
        )

    cooldown = (
        limiter
        .login_cooldown_retry_after(
            normalized_email
        )
    )

    if cooldown > 0:
        write_auth_audit(
            database,
            action=(
                "auth.login.throttled"
            ),
            user_id=(
                known_user.id
                if known_user
                is not None
                else None
            ),
            ip_address=source_ip,
            details={
                "mechanism":
                    mechanism,
                "reason_code":
                    "identity_cooldown",
                **identity_details,
            },
        )

        database.commit()

        _raise_auth_throttled(
            cooldown
        )

    try:
        user = _authenticate_credentials(
            normalized_email,
            password,
            database,
        )

    except HTTPException as exc:
        new_cooldown = 0

        if (
            exc.status_code
            == status.HTTP_401_UNAUTHORIZED
        ):
            new_cooldown = (
                limiter
                .record_login_failure(
                    normalized_email
                )
            )

        write_auth_audit(
            database,
            action=(
                "auth.login.throttled"
                if new_cooldown > 0
                else "auth.login.failure"
            ),
            user_id=(
                known_user.id
                if known_user
                is not None
                else None
            ),
            ip_address=source_ip,
            details={
                "mechanism":
                    mechanism,
                "reason_code":
                    (
                        "invalid_credentials"
                        if exc.status_code
                        == status.HTTP_401_UNAUTHORIZED
                        else "account_policy"
                    ),
                **identity_details,
            },
        )

        database.commit()

        if new_cooldown > 0:
            _raise_auth_throttled(
                new_cooldown
            )

        raise

    limiter.clear_login_failures(
        normalized_email
    )

    write_auth_audit(
        database,
        action="auth.login.success",
        user_id=user.id,
        ip_address=source_ip,
        details={
            "mechanism":
                mechanism,
        },
    )

    return user


def _set_session_cookie(
    response: Response,
    raw_cookie: str,
) -> None:
    response.set_cookie(
        key=(
            settings
            .session_cookie_name
        ),
        value=raw_cookie,
        max_age=(
            settings
            .session_absolute_hours
            * 60
            * 60
        ),
        secure=(
            settings
            .session_cookie_secure
        ),
        httponly=True,
        samesite="lax",
        path="/",
    )


def _delete_session_cookie(
    response: Response,
) -> None:
    response.delete_cookie(
        key=(
            settings
            .session_cookie_name
        ),
        path="/",
        secure=(
            settings
            .session_cookie_secure
        ),
        httponly=True,
        samesite="lax",
    )


def _require_turnstile(
    *,
    database: Session,
    request: Request,
    token: str,
    flow: str,
    identity: str | None = None,
) -> str:
    source_ip = _request_client_ip(
        request
    )

    if verify_turnstile(
        token,
        remote_ip=source_ip,
    ):
        return source_ip

    user = None
    identity_details = {}

    if identity:
        (
            user,
            identity_details,
        ) = _identity_subject(
            database,
            identity,
        )

    write_auth_audit(
        database,
        action="auth.turnstile.failed",
        user_id=(
            user.id
            if user is not None
            else None
        ),
        ip_address=source_ip,
        details={
            "flow":
                flow,
            "reason_code":
                "verification_failed",
            **identity_details,
        },
    )

    database.commit()

    raise _auth_http_error(
        status_code=(
            status.HTTP_400_BAD_REQUEST
        ),
        code="TURNSTILE_FAILED",
        message=(
            "Human verification failed."
        ),
    )


def _attach_organization_metadata(
    database: Session,
    user: User,
    organization_id: UUID | None = None,
) -> User:
    setattr(
        user,
        "_beacon_organization_id",
        organization_id,
    )

    context = resolve_organization_context(
        database,
        user,
    )

    user.organization_id = (
        context.organization.id
    )

    user.organization_name = (
        context.organization.name
    )

    user.organization_role = (
        context.role.value
    )

    return user


def _enqueue_auth_mail_safely(
    user_id,
    purpose: str,
) -> None:
    try:
        send_auth_lifecycle_email.delay(
            str(
                user_id
            ),
            purpose,
        )

    except Exception:
        # Account state is already committed.
        # Recovery/resend can be requested again.
        # Avoid introducing an account-existence oracle.
        return


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=(
        status.HTTP_201_CREATED
    ),
)
def register_user(
    request: RegistrationRequest,
    http_request: Request,
    database: DatabaseSession,
) -> User:
    """Create an unverified public account."""

    source_ip = _request_client_ip(
        http_request
    )

    if not settings.registration_enabled:
        raise _auth_http_error(
            status_code=(
                status.HTTP_503_SERVICE_UNAVAILABLE
            ),
            code="REGISTRATION_DISABLED",
            message=(
                "Registration is currently unavailable."
            ),
        )

    limiter = RedisRateLimiter()

    _rate_limit_or_raise(
        limiter,
        "registration_ip",
        source_ip,
    )

    _require_turnstile(
        database=database,
        request=http_request,
        token=(
            request
            .turnstile_token
        ),
        flow="registration",
        identity=str(
            request.email
        ),
    )

    normalized_email = (
        str(request.email)
        .strip()
        .lower()
    )

    if (
        _known_user(
            database,
            normalized_email,
        )
        is not None
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "An account with this email "
                "address already exists."
            ),
        )

    invitation = None

    if request.invitation_token:
        try:
            invitation = resolve_invitation(
                database,
                request.invitation_token,
            )
        except InvitationError as exc:
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "Invalid or expired invitation."
                ),
            ) from exc

        if (
            invitation.email
            != normalized_email
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "Invitation email does not "
                    "match registration."
                ),
            )

    user = User(
        email=normalized_email,
        full_name=request.full_name,
        password_hash=hash_password(
            request.password
        ),
        role="user",
        is_active=True,
        is_email_verified=False,
    )

    database.add(
        user
    )

    try:
        # Establish the UUID and uniqueness result before
        # creating audit rows, while retaining one transaction.
        database.flush()

        if invitation is None:
            organization, _ = (
                create_personal_organization(
                    database,
                    user,
                    role=OrganizationRole.ADMIN,
                )
            )
        else:
            (
                organization,
                _,
                invitation,
            ) = accept_invitation(
                database,
                request.invitation_token,
                user,
                normalized_email,
            )

            write_auth_audit(
                database,
                action=(
                    "organization.invitation.accepted"
                ),
                user_id=user.id,
                organization_id=(
                    organization.id
                ),
                ip_address=source_ip,
                details=None,
            )

        write_auth_audit(
            database,
            action="auth.registration.created",
            user_id=user.id,
            organization_id=organization.id,
            ip_address=source_ip,
            details=None,
        )

        write_auth_audit(
            database,
            action=(
                "auth.email_verification.requested"
            ),
            user_id=user.id,
            organization_id=organization.id,
            ip_address=source_ip,
            details={
                "purpose":
                    "verify_email",
            },
        )

        database.commit()

    except InvitationError as exc:
        database.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=(
                "Invalid or expired invitation."
            ),
        ) from exc

    except IntegrityError:
        database.rollback()

        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "An account with this email "
                "address already exists."
            ),
        )

    database.refresh(
        user
    )

    _enqueue_auth_mail_safely(
        user.id,
        "verify_email",
    )

    return _attach_organization_metadata(
        database,
        user,
    )


@router.post(
    "/login",
    response_model=UserResponse,
)
def browser_login(
    request: BrowserLoginRequest,
    http_request: Request,
    response: Response,
    database: DatabaseSession,
) -> User:
    """Create an opaque browser session."""

    _enforce_browser_login_origin(
        http_request
    )

    user = (
        _authenticate_with_abuse_controls(
            str(request.email),
            request.password,
            http_request,
            database,
            mechanism="session",
        )
    )

    user = _attach_organization_metadata(
        database,
        user,
    )

    session_row, raw_cookie = (
        SessionService(
            database
        ).create_session(
            user.id,
            active_organization_id=user.organization_id,
            created_ip=(
                _request_client_ip(
                    http_request
                )
            ),
            user_agent=(
                http_request
                .headers
                .get(
                    "user-agent"
                )
            ),
        )
    )

    write_auth_audit(
        database,
        action="auth.session.created",
        user_id=user.id,
        organization_id=user.organization_id,
        ip_address=(
            _request_client_ip(
                http_request
            )
        ),
        details={
            "mechanism":
                "session",
            "session_id":
                str(
                    session_row.id
                ),
        },
    )

    database.commit()

    _set_session_cookie(
        response,
        raw_cookie,
    )

    response.headers[
        "X-CSRF-Token"
    ] = derive_csrf_token(
        session_row.id,
        settings.csrf_secret,
    )

    return user


@router.post(
    "/token",
    response_model=TokenResponse,
)
def issue_programmatic_token(
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    http_request: Request,
    database: DatabaseSession,
) -> TokenResponse:
    """Issue retained API/CLI JWT authentication."""

    user = (
        _authenticate_with_abuse_controls(
            form_data.username,
            form_data.password,
            http_request,
            database,
            mechanism="bearer",
        )
    )

    access_token, expires_in = (
        create_access_token(
            subject=str(
                user.id
            ),
        )
    )

    database.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def read_current_user(
    principal: CurrentPrincipal,
    response: Response,
    database: DatabaseSession,
) -> User:
    """Return user and bootstrap CSRF metadata for sessions."""

    if (
        principal.mechanism == "session"
        and principal.session_id is not None
    ):
        response.headers[
            "X-CSRF-Token"
        ] = derive_csrf_token(
            principal.session_id,
            settings.csrf_secret,
        )

    return _attach_organization_metadata(
        database,
        principal.user,
        principal.organization_id,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
)
def logout(
    principal: CurrentLogoutPrincipal,
    http_request: Request,
    response: Response,
    database: DatabaseSession,
) -> MessageResponse:
    """Revoke the current browser session."""

    source_ip = _request_client_ip(
        http_request
    )

    if (
        principal.mechanism == "session"
        and principal.session_id is not None
    ):
        row = database.get(
            AuthSession,
            principal.session_id,
        )

        if row is not None:
            SessionService(
                database
            ).revoke_session(
                row,
                "logout",
            )

            write_auth_audit(
                database,
                action="auth.session.revoked",
                user_id=principal.user.id,
                ip_address=source_ip,
                details={
                    "mechanism":
                        "session",
                    "session_id":
                        str(
                            principal.session_id
                        ),
                },
            )

    write_auth_audit(
        database,
        action="auth.logout",
        user_id=principal.user.id,
        ip_address=source_ip,
        details={
            "mechanism":
                principal.mechanism,
        },
    )

    database.commit()

    _delete_session_cookie(
        response
    )

    return MessageResponse(
        message="Signed out."
    )


@router.post(
    "/password/change",
    response_model=MessageResponse,
)
def change_password(
    request: PasswordChangeRequest,
    principal: CurrentPrincipal,
    http_request: Request,
    response: Response,
    database: DatabaseSession,
) -> MessageResponse:
    """Rotate password and revoke all browser sessions."""

    user = principal.user

    if not verify_password(
        request.current_password,
        user.password_hash,
    ):
        raise _auth_http_error(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            code="AUTH_INVALID_CREDENTIALS",
            message=(
                "Current password is incorrect."
            ),
        )

    if verify_password(
        request.new_password,
        user.password_hash,
    ):
        raise _auth_http_error(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            code="AUTH_PASSWORD_REUSE",
            message=(
                "New password must differ "
                "from current password."
            ),
        )

    user.password_hash = hash_password(
        request.new_password
    )

    database.add(
        user
    )

    SessionService(
        database
    ).revoke_all_for_user(
        user.id,
        "password_changed",
    )

    source_ip = _request_client_ip(
        http_request
    )

    write_auth_audit(
        database,
        action="auth.password.changed",
        user_id=user.id,
        ip_address=source_ip,
        details={
            "mechanism":
                principal.mechanism,
        },
    )

    write_auth_audit(
        database,
        action="auth.sessions.revoked_all",
        user_id=user.id,
        ip_address=source_ip,
        details={
            "reason_code":
                "password_changed",
        },
    )

    database.commit()

    if (
        principal.mechanism
        == "session"
    ):
        _delete_session_cookie(
            response
        )

    return MessageResponse(
        message=(
            "Password changed. "
            "Please sign in again."
        )
    )


@router.post(
    "/email/verify",
    response_model=MessageResponse,
)
def verify_email(
    request: EmailVerificationRequest,
    http_request: Request,
    database: DatabaseSession,
) -> MessageResponse:
    """Consume a one-time email-verification token."""

    try:
        user = (
            consume_verification_token(
                database,
                request.token,
            )
        )

    except ValueError:
        raise _auth_http_error(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            code="AUTH_TOKEN_INVALID",
            message=(
                "The verification token "
                "is invalid or expired."
            ),
        )

    write_auth_audit(
        database,
        action=(
            "auth.email_verification.completed"
        ),
        user_id=user.id,
        ip_address=(
            _request_client_ip(
                http_request
            )
        ),
        details={
            "purpose":
                "verify_email",
        },
    )

    database.commit()

    return MessageResponse(
        message="Email verified."
    )


@router.post(
    "/email/verification/resend",
    response_model=MessageResponse,
)
def resend_verification(
    request: ResendVerificationRequest,
    http_request: Request,
    database: DatabaseSession,
) -> MessageResponse:
    """Request another verification email without account disclosure."""

    source_ip = _request_client_ip(
        http_request
    )

    limiter = RedisRateLimiter()

    _rate_limit_or_raise(
        limiter,
        "resend_ip",
        source_ip,
    )

    _rate_limit_or_raise(
        limiter,
        "resend_identity",
        str(
            request.email
        ),
    )

    _require_turnstile(
        database=database,
        request=http_request,
        token=(
            request
            .turnstile_token
        ),
        flow="verification_resend",
        identity=str(
            request.email
        ),
    )

    (
        user,
        identity_details,
    ) = _identity_subject(
        database,
        str(
            request.email
        ),
    )

    write_auth_audit(
        database,
        action=(
            "auth.email_verification.requested"
        ),
        user_id=(
            user.id
            if user is not None
            else None
        ),
        ip_address=source_ip,
        details={
            "purpose":
                "verify_email",
            **identity_details,
        },
    )

    database.commit()

    if (
        user is not None
        and user.is_active
        and not user.is_email_verified
    ):
        _enqueue_auth_mail_safely(
            user.id,
            "verify_email",
        )

    return MessageResponse(
        message=GENERIC_ACCOUNT_MESSAGE
    )


@router.post(
    "/password/forgot",
    response_model=MessageResponse,
)
def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
    database: DatabaseSession,
) -> MessageResponse:
    """Request password recovery without account disclosure."""

    source_ip = _request_client_ip(
        http_request
    )

    limiter = RedisRateLimiter()

    _rate_limit_or_raise(
        limiter,
        "forgot_ip",
        source_ip,
    )

    _rate_limit_or_raise(
        limiter,
        "forgot_identity",
        str(
            request.email
        ),
    )

    _require_turnstile(
        database=database,
        request=http_request,
        token=(
            request
            .turnstile_token
        ),
        flow="password_forgot",
        identity=str(
            request.email
        ),
    )

    (
        user,
        identity_details,
    ) = _identity_subject(
        database,
        str(
            request.email
        ),
    )

    write_auth_audit(
        database,
        action=(
            "auth.password_reset.requested"
        ),
        user_id=(
            user.id
            if user is not None
            else None
        ),
        ip_address=source_ip,
        details={
            "purpose":
                "reset_password",
            **identity_details,
        },
    )

    database.commit()

    if (
        user is not None
        and user.is_active
    ):
        _enqueue_auth_mail_safely(
            user.id,
            "reset_password",
        )

    return MessageResponse(
        message=GENERIC_ACCOUNT_MESSAGE
    )


@router.post(
    "/password/reset",
    response_model=MessageResponse,
)
def reset_password(
    request: PasswordResetRequest,
    http_request: Request,
    response: Response,
    database: DatabaseSession,
) -> MessageResponse:
    """Reset password and revoke all browser sessions."""

    try:
        user = (
            consume_password_reset_token(
                database,
                request.token,
                request.new_password,
            )
        )

    except PasswordReuseError:
        raise _auth_http_error(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            code="AUTH_PASSWORD_REUSE",
            message=(
                "New password must differ "
                "from current password."
            ),
        )

    except ValueError:
        raise _auth_http_error(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            code="AUTH_TOKEN_INVALID",
            message=(
                "The reset token "
                "is invalid or expired."
            ),
        )

    source_ip = _request_client_ip(
        http_request
    )

    write_auth_audit(
        database,
        action=(
            "auth.password_reset.completed"
        ),
        user_id=user.id,
        ip_address=source_ip,
        details={
            "purpose":
                "reset_password",
        },
    )

    write_auth_audit(
        database,
        action="auth.sessions.revoked_all",
        user_id=user.id,
        ip_address=source_ip,
        details={
            "reason_code":
                "password_reset",
        },
    )

    database.commit()

    _delete_session_cookie(
        response
    )

    return MessageResponse(
        message=(
            "Password reset. "
            "Please sign in again."
        )
    )
