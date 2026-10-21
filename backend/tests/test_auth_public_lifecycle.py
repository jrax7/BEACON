from __future__ import annotations

from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]

AUTH_ROUTER = (
    BACKEND
    / "app"
    / "routers"
    / "auth.py"
)

AUTH_SCHEMA = (
    BACKEND
    / "app"
    / "schemas"
    / "auth.py"
)


def _router() -> str:
    return AUTH_ROUTER.read_text(
        encoding="utf-8",
    )


def _schema() -> str:
    return AUTH_SCHEMA.read_text(
        encoding="utf-8",
    )


def test_public_auth_lifecycle_routes_exist() -> None:
    source = _router()

    for route in (
        '"/register"',
        '"/email/verify"',
        '"/email/verification/resend"',
        '"/password/forgot"',
        '"/password/reset"',
    ):
        assert route in source


def test_public_auth_lifecycle_schemas_exist() -> None:
    source = _schema()

    for model in (
        "RegistrationRequest",
        "EmailVerificationRequest",
        "ResendVerificationRequest",
        "ForgotPasswordRequest",
        "PasswordResetRequest",
    ):
        assert (
            f"class {model}"
            in source
        )


def test_registration_uses_runtime_switch() -> None:
    assert (
        "registration_enabled"
        in _router()
    )


def test_public_abuse_protection_is_integrated() -> None:
    source = _router()

    assert "RedisRateLimiter" in source
    assert "verify_turnstile" in source
    assert "turnstile_token" in source


def test_public_flow_enqueues_nonsecret_mail_task() -> None:
    source = _router()

    assert (
        "send_auth_lifecycle_email"
        in source
    )

    assert '"verify_email"' in source
    assert '"reset_password"' in source


def test_forgot_password_response_is_generic() -> None:
    assert (
        "If that account exists"
        in _router()
    )


def test_password_reset_uses_transactional_token_service() -> None:
    source = _router()

    marker = source.find(
        '"/password/reset"'
    )

    assert marker != -1

    assert (
        "consume_password_reset_token"
        in source[
            marker:
        ]
    )

def test_password_flows_expose_stable_password_reuse_error() -> None:
    source = _router()

    change_marker = source.find(
        '"/password/change"'
    )
    reset_marker = source.find(
        '"/password/reset"'
    )

    assert change_marker != -1
    assert reset_marker != -1

    next_after_change = source.find(
        "@router.",
        change_marker + 1,
    )

    assert next_after_change != -1

    change_section = source[
        change_marker:
        next_after_change
    ]

    reset_section = source[
        reset_marker:
    ]

    assert (
        "AUTH_PASSWORD_REUSE"
        in change_section
    )

    assert (
        "AUTH_PASSWORD_REUSE"
        in reset_section
    )

    assert (
        "PasswordReuseError"
        in reset_section
    )
