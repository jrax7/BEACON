from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import UUID

from sqlalchemy import (
    select,
    update,
)
from sqlalchemy.orm import Session

from app.auth.crypto import (
    generate_opaque_token,
    hash_opaque_token,
)
from app.auth.errors import (
    InvalidSessionError,
    SessionExpiredError,
    SessionInactiveUserError,
    SessionRevokedError,
)
from app.config import settings
from app.models.auth_session import AuthSession
from app.models.user import User


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _as_utc(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def _bounded_reason(
    reason: str,
) -> str:
    value = reason.strip()

    if not value:
        value = "revoked"

    return value[:100]


class SessionService:
    """Persistence service for revocable opaque browser sessions."""

    def __init__(
        self,
        database: Session,
        *,
        runtime_settings=settings,
    ) -> None:
        self.database = database
        self.settings = runtime_settings

    def create_session(
        self,
        user_id: UUID,
        *,
        active_organization_id: UUID | None = None,
        created_ip: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> tuple[AuthSession, str]:
        """Create one independently revocable browser session."""

        current = _as_utc(
            now or _utc_now()
        )

        user = self.database.get(
            User,
            user_id,
        )

        if (
            user is None
            or not user.is_active
        ):
            raise SessionInactiveUserError(
                "Inactive users cannot create sessions."
            )

        raw_cookie = generate_opaque_token()

        absolute_expires_at = (
            current
            + timedelta(
                hours=self.settings.session_absolute_hours,
            )
        )

        idle_expires_at = min(
            current
            + timedelta(
                minutes=self.settings.session_idle_minutes,
            ),
            absolute_expires_at,
        )

        session = AuthSession(
            user_id=user_id,
            active_organization_id=active_organization_id,
            token_hash=hash_opaque_token(
                raw_cookie
            ),
            last_seen_at=current,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            created_ip=(
                created_ip[:64]
                if created_ip
                else None
            ),
            user_agent=(
                user_agent[:512]
                if user_agent
                else None
            ),
        )

        self.database.add(
            session
        )
        self.database.flush()

        return (
            session,
            raw_cookie,
        )

    def resolve_session(
        self,
        raw_cookie: str,
        *,
        now: datetime | None = None,
    ) -> AuthSession:
        """Resolve and validate an opaque browser-session cookie."""

        current = _as_utc(
            now or _utc_now()
        )

        token_hash = hash_opaque_token(
            raw_cookie
        )

        session = self.database.scalar(
            select(AuthSession).where(
                AuthSession.token_hash
                == token_hash,
            )
        )

        if session is None:
            raise InvalidSessionError(
                "Session token is invalid."
            )

        if session.revoked_at is not None:
            raise SessionRevokedError(
                "Session has been revoked."
            )

        if (
            current
            >= _as_utc(
                session.absolute_expires_at
            )
            or current
            >= _as_utc(
                session.idle_expires_at
            )
        ):
            raise SessionExpiredError(
                "Session has expired."
            )

        user = self.database.get(
            User,
            session.user_id,
        )

        if (
            user is None
            or not user.is_active
        ):
            raise SessionInactiveUserError(
                "Session user is unavailable."
            )

        return session

    def touch_session(
        self,
        session: AuthSession,
        *,
        now: datetime | None = None,
    ) -> None:
        """Extend idle expiry without extending absolute lifetime."""

        current = _as_utc(
            now or _utc_now()
        )

        if session.revoked_at is not None:
            raise SessionRevokedError(
                "Session has been revoked."
            )

        absolute_expires_at = _as_utc(
            session.absolute_expires_at
        )

        if current >= absolute_expires_at:
            raise SessionExpiredError(
                "Session has expired."
            )

        session.last_seen_at = current
        session.idle_expires_at = min(
            current
            + timedelta(
                minutes=self.settings.session_idle_minutes,
            ),
            absolute_expires_at,
        )

        self.database.add(
            session
        )

    def revoke_session(
        self,
        session: AuthSession,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> None:
        """Idempotently revoke one session."""

        if session.revoked_at is not None:
            return

        session.revoked_at = _as_utc(
            now or _utc_now()
        )
        session.revoked_reason = _bounded_reason(
            reason
        )

        self.database.add(
            session
        )

    def revoke_all_for_user(
        self,
        user_id: UUID,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> int:
        """Revoke all currently active browser sessions for one user."""

        current = _as_utc(
            now or _utc_now()
        )

        result = self.database.execute(
            update(AuthSession)
            .where(
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(
                revoked_at=current,
                revoked_reason=_bounded_reason(
                    reason
                ),
            )
            .execution_options(
                synchronize_session=False,
            )
        )

        return int(
            result.rowcount
            or 0
        )
