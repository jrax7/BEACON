from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from app.config import settings


password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Generate an Argon2 password hash."""

    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    """Compare a plaintext password with its stored hash."""

    return password_hasher.verify(
        plain_password,
        password_hash,
    )


def create_access_token(subject: str) -> tuple[str, int]:
    """Create a signed JWT access token."""

    expires_in_seconds = settings.access_token_expire_minutes * 60

    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=expires_in_seconds,
    )

    payload = {
        "sub": subject,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": expires_at,
    }

    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )

    return token, expires_in_seconds


def decode_access_token(token: str) -> str:
    """Validate an access token and return its subject."""

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except InvalidTokenError as exc:
        raise ValueError("Invalid or expired access token.") from exc

    if payload.get("type") != "access":
        raise ValueError("Incorrect token type.")

    subject = payload.get("sub")

    if not isinstance(subject, str) or not subject:
        raise ValueError("Token subject is missing.")

    return subject
