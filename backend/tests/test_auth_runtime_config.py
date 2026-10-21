from __future__ import annotations

import pytest

import app.config as config


EXPECTED_PHASE16B_FIELDS = {
    "public_url",
    "registration_enabled",
    "browser_origins",
    "session_cookie_name",
    "session_cookie_secure",
    "session_idle_minutes",
    "session_absolute_hours",
    "csrf_secret",
    "trusted_proxy_cidrs",
    "client_ip_header",
    "turnstile_secret_key",
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "smtp_starttls",
    "smtp_from_address",
    "smtp_from_name",
    "smtp_timeout_seconds",
}


BASE_SETTINGS = {
    "secret_key": "s" * 64,
    "database_url": (
        "postgresql+psycopg://beacon:test@postgres:5432/beacon"
    ),
    "redis_url": "redis://redis:6379/0",
    "celery_broker_url": "redis://redis:6379/1",
    "celery_result_backend": "redis://redis:6379/2",
    "zap_api_key": "z" * 64,
}


VALID_PRODUCTION_AUTH = {
    "environment": "production",
    "public_url": "https://beacon.example.com",
    "registration_enabled": True,
    "browser_origins": "https://beacon.example.com",
    "session_cookie_name": "__Host-beacon_session",
    "session_cookie_secure": True,
    "session_idle_minutes": 60,
    "session_absolute_hours": 12,
    "csrf_secret": "c" * 64,
    "trusted_proxy_cidrs": "172.16.0.0/12,127.0.0.1/32",
    "client_ip_header": "x-forwarded-for",
    "turnstile_secret_key": "t" * 64,
    "smtp_host": "smtp.example.test",
    "smtp_port": 587,
    "smtp_username": "beacon",
    "smtp_password": "p" * 40,
    "smtp_starttls": True,
    "smtp_from_address": "no-reply@beacon.example.com",
    "smtp_from_name": "BEACON",
    "smtp_timeout_seconds": 10,
}


def _settings(**overrides):
    values = {
        **BASE_SETTINGS,
        **overrides,
    }

    return config.Settings(
        _env_file=None,
        **values,
    )


def _valid_production(**overrides):
    return _settings(
        **{
            **VALID_PRODUCTION_AUTH,
            **overrides,
        }
    )


def _validator():
    validator = getattr(
        config,
        "validate_auth_runtime_settings",
        None,
    )

    assert callable(validator), (
        "Phase 16B requires "
        "validate_auth_runtime_settings(settings)"
    )

    return validator


def test_phase16b_auth_runtime_settings_contract_is_declared() -> None:
    fields = set(config.Settings.model_fields)
    missing = EXPECTED_PHASE16B_FIELDS - fields

    assert not missing, (
        "Phase 16B auth runtime settings are missing: "
        + ", ".join(sorted(missing))
    )


def test_phase16b_auth_runtime_validator_exists() -> None:
    assert callable(
        getattr(
            config,
            "validate_auth_runtime_settings",
            None,
        )
    )


def test_valid_phase16b_production_configuration_passes() -> None:
    _validator()(
        _valid_production()
    )


def test_production_requires_https_public_url() -> None:
    with pytest.raises(
        ValueError,
        match="HTTPS",
    ):
        _validator()(
            _valid_production(
                public_url="http://beacon.example.com",
            )
        )


@pytest.mark.parametrize(
    (
        "cookie_name",
        "cookie_secure",
    ),
    [
        (
            "beacon_session",
            True,
        ),
        (
            "__Host-beacon_session",
            False,
        ),
    ],
)
def test_production_requires_host_prefixed_secure_cookie(
    cookie_name: str,
    cookie_secure: bool,
) -> None:
    with pytest.raises(
        ValueError,
        match="cookie",
    ):
        _validator()(
            _valid_production(
                session_cookie_name=cookie_name,
                session_cookie_secure=cookie_secure,
            )
        )


def test_production_requires_strong_csrf_secret() -> None:
    with pytest.raises(
        ValueError,
        match="CSRF",
    ):
        _validator()(
            _valid_production(
                csrf_secret="short",
            )
        )


def test_production_rejects_unsafe_existing_jwt_secret() -> None:
    with pytest.raises(
        ValueError,
        match="SECRET_KEY",
    ):
        _validator()(
            _valid_production(
                secret_key="replace-with-a-random-secret",
            )
        )


def test_production_requires_turnstile_when_registration_enabled() -> None:
    with pytest.raises(
        ValueError,
        match="Turnstile",
    ):
        _validator()(
            _valid_production(
                turnstile_secret_key="",
            )
        )


def test_production_may_disable_registration_without_turnstile() -> None:
    _validator()(
        _valid_production(
            registration_enabled=False,
            turnstile_secret_key="",
        )
    )


@pytest.mark.parametrize(
    (
        "field",
        "value",
    ),
    [
        (
            "smtp_host",
            "",
        ),
        (
            "smtp_username",
            "",
        ),
        (
            "smtp_password",
            "",
        ),
        (
            "smtp_from_address",
            "",
        ),
        (
            "smtp_starttls",
            False,
        ),
    ],
)
def test_production_requires_secure_smtp_configuration(
    field: str,
    value,
) -> None:
    with pytest.raises(
        ValueError,
        match="SMTP",
    ):
        _validator()(
            _valid_production(
                **{
                    field: value,
                },
            )
        )


def test_production_requires_browser_origin_to_match_public_origin() -> None:
    with pytest.raises(
        ValueError,
        match="browser origin",
    ):
        _validator()(
            _valid_production(
                browser_origins=(
                    "https://beacon.example.com,"
                    "https://evil.example"
                ),
            )
        )


def test_invalid_trusted_proxy_cidr_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="CIDR",
    ):
        _validator()(
            _valid_production(
                trusted_proxy_cidrs="not-a-network",
            )
        )


@pytest.mark.parametrize(
    (
        "idle_minutes",
        "absolute_hours",
    ),
    [
        (
            0,
            12,
        ),
        (
            60,
            0,
        ),
        (
            721,
            12,
        ),
    ],
)
def test_session_lifetimes_must_be_positive_and_bounded(
    idle_minutes: int,
    absolute_hours: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="session",
    ):
        _validator()(
            _valid_production(
                session_idle_minutes=idle_minutes,
                session_absolute_hours=absolute_hours,
            )
        )


def test_development_may_use_explicit_local_http_cookie_policy() -> None:
    settings = _settings(
        environment="development",
        public_url="http://localhost:5173",
        registration_enabled=True,
        browser_origins="http://localhost:5173",
        session_cookie_name="beacon_session",
        session_cookie_secure=False,
        session_idle_minutes=60,
        session_absolute_hours=12,
        csrf_secret="",
        trusted_proxy_cidrs="",
        client_ip_header="x-forwarded-for",
        turnstile_secret_key="",
        smtp_host="",
        smtp_port=587,
        smtp_username="",
        smtp_password="",
        smtp_starttls=True,
        smtp_from_address="",
        smtp_from_name="BEACON",
        smtp_timeout_seconds=10,
    )

    _validator()(
        settings
    )


def test_phase16b_preserves_existing_bearer_jwt_configuration() -> None:
    fields = set(config.Settings.model_fields)

    assert "secret_key" in fields
    assert "jwt_algorithm" in fields
    assert "access_token_expire_minutes" in fields
    assert "jwt_secret" not in fields

    settings = _settings()

    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_expire_minutes == 60


def test_get_settings_fails_closed_on_invalid_production_auth_runtime(
    monkeypatch,
) -> None:
    config.get_settings.cache_clear()

    monkeypatch.setenv(
        "ENVIRONMENT",
        "production",
    )
    monkeypatch.setenv(
        "BEACON_PUBLIC_URL",
        "http://beacon.example.com",
    )

    try:
        with pytest.raises(
            ValueError,
            match="HTTPS",
        ):
            config.get_settings()
    finally:
        config.get_settings.cache_clear()


def test_stable_auth_error_body_helper() -> None:
    from app.auth.errors import auth_error_detail

    assert auth_error_detail(
        "AUTH_REQUIRED",
        "Authentication is required.",
    ) == {
        "code": "AUTH_REQUIRED",
        "message": "Authentication is required.",
    }
