import hashlib
import secrets


def generate_opaque_token() -> str:
    """Generate a URL-safe token with at least 256 bits of entropy."""

    return secrets.token_urlsafe(
        32
    )


def hash_opaque_token(
    raw: str,
) -> str:
    """Return the SHA-256 hex digest of an opaque token."""

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()
