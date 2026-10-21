from __future__ import annotations

from hashlib import sha256
from uuid import UUID

from app.models.audit_log import AuditLog


AUTH_ACTIONS = frozenset(
    {
        "auth.login.success",
        "auth.login.failure",
        "auth.login.throttled",
        "auth.logout",
        "auth.session.created",
        "auth.session.revoked",
        "auth.sessions.revoked_all",
        "auth.registration.created",
        "organization.invitation.accepted",
        "auth.email_verification.requested",
        "auth.email_verification.completed",
        "auth.password_reset.requested",
        "auth.password_reset.completed",
        "auth.password.changed",
        "auth.turnstile.failed",
    }
)


_ALLOWED_DETAIL_KEYS = frozenset(
    {
        "mechanism",
        "reason_code",
        "identity_hash",
        "session_id",
        "purpose",
        "flow",
    }
)


def identity_hash(
    identity: object,
) -> str:
    """Return SHA-256 of a normalized attempted identity."""

    normalized = str(
        identity
    ).strip().lower()

    return sha256(
        normalized.encode(
            "utf-8"
        )
    ).hexdigest()


def _clean_details(
    details: dict | None,
) -> dict | None:
    if not details:
        return None

    cleaned = {}

    for key, value in details.items():
        if key not in _ALLOWED_DETAIL_KEYS:
            continue

        if value is None:
            continue

        if isinstance(
            value,
            str,
        ):
            value = value[:512]

        cleaned[
            key
        ] = value

    return (
        cleaned
        or None
    )


def write_auth_audit(
    database,
    *,
    action: str,
    user_id: UUID | None,
    ip_address: str | None,
    details: dict | None,
    organization_id: UUID | None = None,
) -> AuditLog:
    """Add one approved sanitized authentication event."""

    if action not in AUTH_ACTIONS:
        raise ValueError(
            "Unsupported authentication audit action."
        )

    row = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        target_id=None,
        scan_id=None,
        action=action,
        ip_address=(
            ip_address[:45]
            if ip_address
            else None
        ),
        details=_clean_details(
            details
        ),
    )

    database.add(
        row
    )

    return row
