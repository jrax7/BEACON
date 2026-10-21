from functools import lru_cache
from ipaddress import ip_network
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "BEACON API"
    environment: str = "development"
    secret_key: str

    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str

    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Phase 16B browser authentication and public-account policy.
    public_url: str = Field(
        default="http://localhost:5173",
        validation_alias="BEACON_PUBLIC_URL",
    )
    registration_enabled: bool = Field(
        default=True,
        validation_alias="BEACON_REGISTRATION_ENABLED",
    )
    browser_origins: str = Field(
        default="http://localhost:5173",
        validation_alias="BEACON_BROWSER_ORIGINS",
    )
    session_cookie_name: str = Field(
        default="beacon_session",
        validation_alias="BEACON_SESSION_COOKIE_NAME",
    )
    session_cookie_secure: bool = Field(
        default=False,
        validation_alias="BEACON_SESSION_COOKIE_SECURE",
    )
    session_idle_minutes: int = Field(
        default=60,
        validation_alias="BEACON_SESSION_IDLE_MINUTES",
    )
    session_absolute_hours: int = Field(
        default=12,
        validation_alias="BEACON_SESSION_ABSOLUTE_HOURS",
    )
    csrf_secret: str = Field(
        default="",
        validation_alias="BEACON_CSRF_SECRET",
    )
    trusted_proxy_cidrs: str = Field(
        default="",
        validation_alias="BEACON_TRUSTED_PROXY_CIDRS",
    )
    client_ip_header: str = Field(
        default="x-forwarded-for",
        validation_alias="BEACON_CLIENT_IP_HEADER",
    )

    turnstile_secret_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    smtp_from_address: str = ""
    smtp_from_name: str = "BEACON"
    smtp_timeout_seconds: int = 10

    allow_lab_targets: bool = False
    lab_allowed_hosts: str = ""
    target_allowed_ports: str = "80,443"
    target_request_timeout_seconds: float = 10
    target_verification_ttl_days: int = 30
    verification_file_max_bytes: int = 4096

    zap_api_url: str = "http://zap:8080"
    zap_api_key: str
    zap_startup_timeout_seconds: int = 120
    zap_spider_timeout_seconds: int = 120
    zap_passive_scan_timeout_seconds: int = 180
    zap_active_scan_timeout_seconds: float = 2760.0
    zap_poll_interval_seconds: float = 2

    report_storage_path: str = "/app/storage/reports"
    report_max_sample_urls: int = 20

    raw_storage_path: str = "/app/storage/raw"
    nmap_allowed_ports: str = "80,443"
    nmap_timeout_seconds: int = 120
    nmap_max_explicit_ports: int = 64

    httpx_binary: str = "/usr/local/bin/pd-httpx"
    httpx_max_response_bytes: int = 1_000_000
    httpx_max_redirects: int = 5

    katana_binary: str = "/usr/local/bin/pd-katana"

    sslyze_binary: str = "sslyze"

    nuclei_binary: str = "/usr/local/bin/pd-nuclei"
    nuclei_template_root: str = "/opt/nuclei-templates"
    nuclei_max_output_bytes: int = 10_000_000

    nikto_binary: str = "nikto"
    nikto_max_time_seconds: int = 120
    nikto_process_timeout_seconds: int = 150
    nikto_request_timeout_seconds: int = 2
    nikto_tuning: str = "23b"
    nikto_user_agent: str = "BEACON-Nikto/0.1"
    nikto_max_output_bytes: int = 10_000_000

    demo_user_email: str = "demo@beacon.example.com"
    demo_target_url: str = "http://lab-target/"
    demo_verification_ttl_days: int = 3650

    # Phase 16A Task 19 scanner runtime policy.
    # Concurrency remains intentionally bounded on the local host.
    control_worker_concurrency: int = 1
    scanner_worker_concurrency: int = 1

    scanner_heartbeat_interval_seconds: int = 15
    scanner_stale_after_seconds: int = 90

    scanner_artifact_max_bytes: int = 52_428_800
    scanner_process_grace_seconds: int = 5


    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )


_UNSAFE_SECRET_VALUES = {
    "",
    "changeme",
    "change-me",
    "development",
    "replace-me",
    "replace-with-a-random-secret",
}


def _normalized_origin(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate)

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "BEACON_PUBLIC_URL/browser origin must be a canonical origin"
        )

    return (
        f"{parsed.scheme.lower()}://"
        f"{parsed.netloc.lower()}"
    )


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for item in value.split(",")
        if item.strip()
    )


def _unsafe_secret(value: str) -> bool:
    normalized = value.strip().lower()

    return (
        normalized in _UNSAFE_SECRET_VALUES
        or normalized.startswith("replace-with-")
    )


def validate_auth_runtime_settings(
    runtime_settings: Settings,
) -> None:
    """Validate Phase 16B authentication runtime invariants."""

    idle_minutes = runtime_settings.session_idle_minutes
    absolute_hours = runtime_settings.session_absolute_hours

    if (
        idle_minutes <= 0
        or absolute_hours <= 0
        or idle_minutes > absolute_hours * 60
    ):
        raise ValueError(
            "Phase 16B session lifetimes must be positive and "
            "idle lifetime cannot exceed absolute lifetime"
        )

    if runtime_settings.smtp_port <= 0:
        raise ValueError(
            "SMTP port must be positive"
        )

    if runtime_settings.smtp_timeout_seconds <= 0:
        raise ValueError(
            "SMTP timeout must be positive"
        )

    trusted_proxy_cidrs = _split_csv(
        runtime_settings.trusted_proxy_cidrs
    )

    for cidr in trusted_proxy_cidrs:
        try:
            ip_network(
                cidr,
                strict=False,
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid trusted proxy CIDR: {cidr}"
            ) from exc

    environment = runtime_settings.environment.strip().lower()

    if environment != "production":
        return

    public_origin = _normalized_origin(
        runtime_settings.public_url
    )

    if not public_origin.startswith("https://"):
        raise ValueError(
            "Production BEACON_PUBLIC_URL must use HTTPS"
        )

    if (
        runtime_settings.session_cookie_name
        != "__Host-beacon_session"
        or not runtime_settings.session_cookie_secure
    ):
        raise ValueError(
            "Production browser session cookie must use "
            "__Host-beacon_session with Secure enabled"
        )

    csrf_secret = runtime_settings.csrf_secret.strip()

    if (
        len(csrf_secret.encode("utf-8")) < 32
        or _unsafe_secret(csrf_secret)
    ):
        raise ValueError(
            "Production CSRF secret must contain at least "
            "32 bytes of non-placeholder secret material"
        )

    jwt_secret = runtime_settings.secret_key.strip()

    if (
        len(jwt_secret.encode("utf-8")) < 32
        or _unsafe_secret(jwt_secret)
    ):
        raise ValueError(
            "Production SECRET_KEY must contain at least "
            "32 bytes of non-placeholder secret material"
        )

    browser_origins = {
        _normalized_origin(origin)
        for origin in _split_csv(
            runtime_settings.browser_origins
        )
    }

    if browser_origins != {public_origin}:
        raise ValueError(
            "Production browser origin must contain only "
            "the canonical BEACON public origin"
        )

    if not trusted_proxy_cidrs:
        raise ValueError(
            "Production trusted proxy CIDR configuration is required"
        )

    if not runtime_settings.client_ip_header.strip():
        raise ValueError(
            "Production client IP header configuration is required"
        )

    if (
        runtime_settings.registration_enabled
        and (
            not runtime_settings.turnstile_secret_key.strip()
            or _unsafe_secret(
                runtime_settings.turnstile_secret_key
            )
        )
    ):
        raise ValueError(
            "Production public registration requires "
            "a configured Turnstile secret"
        )

    smtp_values = (
        runtime_settings.smtp_host.strip(),
        runtime_settings.smtp_username.strip(),
        runtime_settings.smtp_password.strip(),
        runtime_settings.smtp_from_address.strip(),
    )

    if (
        not all(smtp_values)
        or not runtime_settings.smtp_starttls
    ):
        raise ValueError(
            "Production authentication flows require "
            "SMTP host, credentials, From address, and STARTTLS"
        )


@lru_cache
def get_settings() -> Settings:
    """Return one cached, runtime-validated settings object."""

    runtime_settings = Settings()

    validate_auth_runtime_settings(
        runtime_settings
    )

    return runtime_settings


settings = get_settings()
