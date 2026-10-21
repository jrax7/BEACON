from typing import TypedDict


class AuthErrorDetail(TypedDict):
    """Stable public authentication error detail."""

    code: str
    message: str


def auth_error_detail(
    code: str,
    message: str,
) -> AuthErrorDetail:
    """Return a stable code/message authentication error body."""

    return {
        "code": code,
        "message": message,
    }



class SessionError(ValueError):
    """Base class for rejected browser-session credentials."""

    code = "INVALID_SESSION"


class InvalidSessionError(SessionError):
    """Session token does not resolve to a stored session."""

    code = "INVALID_SESSION"


class SessionExpiredError(SessionError):
    """Session exceeded its idle or absolute lifetime."""

    code = "SESSION_EXPIRED"


class SessionRevokedError(SessionError):
    """Session was explicitly revoked."""

    code = "SESSION_REVOKED"


class SessionInactiveUserError(SessionError):
    """Session belongs to an unavailable account."""

    code = "AUTH_REQUIRED"
