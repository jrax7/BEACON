from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.crypto import (
    generate_opaque_token,
    hash_opaque_token,
)
from app.auth.sessions import SessionService
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



class PasswordReuseError(ValueError):
    """Raised when a new password matches the current password."""

def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _aware(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def _invalidate_outstanding(
    database: Session,
    model,
    user_id: UUID,
    now: datetime,
) -> None:
    rows = list(
        database.scalars(
            select(model).where(
                model.user_id == user_id,
                model.consumed_at.is_(None),
            )
        )
    )

    for row in rows:
        row.consumed_at = now


def issue_verification_token(
    database: Session,
    user_id: UUID,
    *,
    now: datetime | None = None,
) -> tuple[
    EmailVerificationToken,
    str,
]:
    issued_at = (
        now
        if now is not None
        else _utc_now()
    )

    _invalidate_outstanding(
        database,
        EmailVerificationToken,
        user_id,
        issued_at,
    )

    raw_token = generate_opaque_token()

    row = EmailVerificationToken(
        user_id=user_id,
        token_hash=hash_opaque_token(
            raw_token
        ),
        expires_at=(
            issued_at
            + timedelta(hours=24)
        ),
        consumed_at=None,
    )

    database.add(row)
    database.flush()

    return (
        row,
        raw_token,
    )


def consume_verification_token(
    database: Session,
    raw_token: str,
    *,
    now: datetime | None = None,
) -> User:
    consumed_at = (
        now
        if now is not None
        else _utc_now()
    )

    row = database.scalar(
        select(
            EmailVerificationToken
        ).where(
            EmailVerificationToken.token_hash
            == hash_opaque_token(
                raw_token
            )
        )
    )

    if (
        row is None
        or row.consumed_at is not None
        or _aware(row.expires_at)
        <= _aware(consumed_at)
    ):
        raise ValueError(
            "Invalid or expired verification token."
        )

    user = database.get(
        User,
        row.user_id,
    )

    if user is None:
        raise ValueError(
            "Invalid or expired verification token."
        )

    _invalidate_outstanding(
        database,
        EmailVerificationToken,
        user.id,
        consumed_at,
    )

    row.consumed_at = consumed_at
    user.is_email_verified = True

    database.flush()

    return user


def issue_password_reset_token(
    database: Session,
    user_id: UUID,
    *,
    now: datetime | None = None,
) -> tuple[
    PasswordResetToken,
    str,
]:
    issued_at = (
        now
        if now is not None
        else _utc_now()
    )

    _invalidate_outstanding(
        database,
        PasswordResetToken,
        user_id,
        issued_at,
    )

    raw_token = generate_opaque_token()

    row = PasswordResetToken(
        user_id=user_id,
        token_hash=hash_opaque_token(
            raw_token
        ),
        expires_at=(
            issued_at
            + timedelta(minutes=30)
        ),
        consumed_at=None,
    )

    database.add(row)
    database.flush()

    return (
        row,
        raw_token,
    )


def consume_password_reset_token(
    database: Session,
    raw_token: str,
    new_password: str,
    *,
    now: datetime | None = None,
) -> User:
    consumed_at = (
        now
        if now is not None
        else _utc_now()
    )

    row = database.scalar(
        select(
            PasswordResetToken
        ).where(
            PasswordResetToken.token_hash
            == hash_opaque_token(
                raw_token
            )
        )
    )

    if (
        row is None
        or row.consumed_at is not None
        or _aware(row.expires_at)
        <= _aware(consumed_at)
    ):
        raise ValueError(
            "Invalid or expired password reset token."
        )

    user = database.get(
        User,
        row.user_id,
    )

    if user is None:
        raise ValueError(
            "Invalid or expired password reset token."
        )

    if verify_password(
        new_password,
        user.password_hash,
    ):
        raise PasswordReuseError(
            "New password must differ from current password."
        )

    _invalidate_outstanding(
        database,
        PasswordResetToken,
        user.id,
        consumed_at,
    )

    user.password_hash = hash_password(
        new_password
    )

    SessionService(
        database
    ).revoke_all_for_user(
        user.id,
        "password_reset",
        now=consumed_at,
    )

    row.consumed_at = consumed_at

    database.flush()

    return user
