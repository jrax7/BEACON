from __future__ import annotations

import httpx

from app.config import settings


TURNSTILE_SITEVERIFY_URL = (
    "https://challenges.cloudflare.com/"
    "turnstile/v0/siteverify"
)

TURNSTILE_TIMEOUT_SECONDS = 3.0


def verify_turnstile(
    token: str,
    *,
    remote_ip: str | None = None,
    runtime_settings=settings,
    client=None,
) -> bool:
    """Verify a Turnstile response without exposing the backend secret."""

    secret = (
        runtime_settings
        .turnstile_secret_key
        .strip()
    )

    environment = (
        runtime_settings
        .environment
        .strip()
        .lower()
    )

    normalized_token = (
        token or ""
    ).strip()

    if (
        environment != "production"
        and not secret
    ):
        return True

    if (
        not secret
        or not normalized_token
    ):
        return False

    data = {
        "secret": secret,
        "response": normalized_token,
    }

    if remote_ip:
        data[
            "remoteip"
        ] = remote_ip

    try:
        if client is None:
            response = httpx.post(
                TURNSTILE_SITEVERIFY_URL,
                data=data,
                timeout=TURNSTILE_TIMEOUT_SECONDS,
            )
        else:
            response = client.post(
                TURNSTILE_SITEVERIFY_URL,
                data=data,
                timeout=TURNSTILE_TIMEOUT_SECONDS,
            )

        response.raise_for_status()

        payload = response.json()
    except Exception:
        # Production-protected flows fail closed.
        return False

    return (
        payload.get(
            "success"
        )
        is True
    )
