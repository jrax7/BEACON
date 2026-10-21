import base64
import hashlib
import hmac
from uuid import UUID


def derive_csrf_token(
    session_id: UUID,
    secret: str,
) -> str:
    """Derive a session-bound CSRF value without DB storage."""

    digest = hmac.new(
        secret.encode("utf-8"),
        session_id.bytes,
        hashlib.sha256,
    ).digest()

    return base64.urlsafe_b64encode(
        digest
    ).rstrip(
        b"="
    ).decode(
        "ascii"
    )


def validate_csrf_token(
    session_id: UUID,
    candidate: str,
    secret: str,
) -> bool:
    """Constant-time validate a derived CSRF value."""

    expected = derive_csrf_token(
        session_id,
        secret,
    )

    return hmac.compare_digest(
        candidate,
        expected,
    )
