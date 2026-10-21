from __future__ import annotations

from collections.abc import Mapping
import re


REDACTED = "[REDACTED]"
TRUNCATION_MARKER = "...[truncated]"
DEFAULT_MAX_BODY_BYTES = 16_384


_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "api-key",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)


_SENSITIVE_HEADER_LINE_RE = re.compile(
    r"(?im)"
    r"^(?P<prefix>[ \t]*"
    r"(?:authorization"
    r"|proxy-authorization"
    r"|cookie"
    r"|set-cookie"
    r"|api-key"
    r"|x-api-key"
    r"|x-auth-token"
    r"|x-access-token"
    r"|x-csrf-token"
    r"|x-xsrf-token)"
    r"[ \t]*:[ \t]*)"
    r"[^\r\n]*"
)


_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        ["']?
        (?:
            password
            |passwd
            |secret
            |token
            |access[_-]?token
            |refresh[_-]?token
            |api[_-]?key
        )
        ["']?
        \s*[:=]\s*
    )
    (?P<value>
        "[^"\r\n]*"
        |
        '[^'\r\n]*'
        |
        [^&\s,;}\]\r\n]+
    )
    """
)


def _normalized_header_name(
    name: object,
) -> str:
    return str(
        name
    ).strip().lower()


def sanitize_headers(
    headers: Mapping[str, object] | None,
) -> dict[str, str]:
    """Return display-safe HTTP headers without mutating the source."""

    if headers is None:
        return {}

    sanitized: dict[str, str] = {}

    for name, value in headers.items():
        key = str(
            name
        )

        if (
            _normalized_header_name(
                name
            )
            in _SENSITIVE_HEADER_NAMES
        ):
            sanitized[
                key
            ] = REDACTED
        else:
            sanitized[
                key
            ] = str(
                value
            )

    return sanitized


def _redact_assignment(
    match: re.Match[str],
) -> str:
    prefix = match.group(
        "prefix"
    )

    value = match.group(
        "value"
    )

    if (
        len(value) >= 2
        and value[0] in {
            '"',
            "'",
        }
        and value[-1] == value[0]
    ):
        return (
            prefix
            + value[0]
            + REDACTED
            + value[-1]
        )

    return (
        prefix
        + REDACTED
    )


def _bounded_utf8_text(
    value: str,
    *,
    max_bytes: int,
) -> str:
    """Bound one display string by encoded UTF-8 byte length."""

    if max_bytes <= 0:
        raise ValueError(
            "Evidence body limit must be positive."
        )

    encoded = value.encode(
        "utf-8"
    )

    if len(
        encoded
    ) <= max_bytes:
        return value

    marker = TRUNCATION_MARKER.encode(
        "utf-8"
    )

    if max_bytes <= len(
        marker
    ):
        return marker[
            :max_bytes
        ].decode(
            "utf-8",
            errors="ignore",
        )

    prefix_budget = (
        max_bytes
        - len(
            marker
        )
    )

    prefix = encoded[
        :prefix_budget
    ].decode(
        "utf-8",
        errors="ignore",
    )

    return (
        prefix
        + TRUNCATION_MARKER
    )


def sanitize_text(
    value: str | bytes | None,
    *,
    max_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> str | None:
    """Redact secrets and bound display text without changing raw evidence."""

    if max_bytes <= 0:
        raise ValueError(
            "Evidence body limit must be positive."
        )

    if value is None:
        return None

    if isinstance(
        value,
        bytes,
    ):
        text = value.decode(
            "utf-8",
            errors="replace",
        )
    else:
        text = str(
            value
        )

    text = _SENSITIVE_HEADER_LINE_RE.sub(
        lambda match: (
            match.group(
                "prefix"
            )
            + REDACTED
        ),
        text,
    )

    text = _SECRET_ASSIGNMENT_RE.sub(
        _redact_assignment,
        text,
    )

    return _bounded_utf8_text(
        text,
        max_bytes=max_bytes,
    )


def sanitize_http_evidence(
    *,
    request_headers: Mapping[
        str,
        object,
    ] | None = None,
    response_headers: Mapping[
        str,
        object,
    ] | None = None,
    request_body: str | bytes | None = None,
    response_body: str | bytes | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> dict[str, dict[str, object]]:
    """Return display-safe HTTP evidence while preserving raw inputs."""

    if max_body_bytes <= 0:
        raise ValueError(
            "Evidence body limit must be positive."
        )

    return {
        "request": {
            "headers": sanitize_headers(
                request_headers
            ),
            "body": sanitize_text(
                request_body,
                max_bytes=max_body_bytes,
            ),
        },
        "response": {
            "headers": sanitize_headers(
                response_headers
            ),
            "body": sanitize_text(
                response_body,
                max_bytes=max_body_bytes,
            ),
        },
    }
