from pathlib import Path

from fastapi import (
    FastAPI,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from redis import Redis

from app.config import settings
from app.database import database_healthcheck
from app.routers.assessments import router as assessments_router
from app.routers.auth import router as authentication_router
from app.routers.findings import router as findings_router
from app.routers.organizations import router as organizations_router
from app.routers.reports import router as reports_router
from app.routers.scans import router as scans_router
from app.routers.targets import router as targets_router


APP_VERSION = (
    Path(__file__)
    .with_name("VERSION")
    .read_text(encoding="utf-8")
    .strip()
)


def _environment_name(
    runtime_settings,
) -> str:
    """Return a normalized explicit runtime environment name."""

    raw_environment = getattr(
        runtime_settings,
        "environment",
        "",
    )

    value = getattr(
        raw_environment,
        "value",
        raw_environment,
    )

    return str(
        value
    ).strip().lower()


def create_app(
    runtime_settings=settings,
) -> FastAPI:
    """Construct the BEACON API for the requested runtime environment."""

    environment = _environment_name(
        runtime_settings
    )

    production = (
        environment
        == "production"
    )

    application = FastAPI(
        title=runtime_settings.app_name,
        description=(
            "Backend API for the BEACON "
            "security assessment platform."
        ),
        version=APP_VERSION,
        docs_url=(
            None
            if production
            else "/docs"
        ),
        redoc_url=(
            None
            if production
            else "/redoc"
        ),
        openapi_url=(
            None
            if production
            else "/openapi.json"
        ),
    )

    application.include_router(
        authentication_router
    )

    application.include_router(
        assessments_router
    )

    application.include_router(
        targets_router
    )

    application.include_router(
        scans_router
    )

    application.include_router(
        reports_router
    )

    application.include_router(
        findings_router
    )

    application.include_router(
        organizations_router
    )

    @application.middleware(
        "http"
    )
    async def sensitive_response_cache_policy(
        request: Request,
        call_next,
    ):
        """Prevent browser/proxy caching of authentication responses."""

        response = await call_next(
            request
        )

        if request.url.path.startswith(
            "/api/v1/auth/"
        ):
            response.headers[
                "Cache-Control"
            ] = "no-store"

        return response

    @application.get("/")
    def root() -> dict:
        """Return basic non-sensitive application information."""

        return {
            "application":
                runtime_settings.app_name,
            "version":
                APP_VERSION,
            "environment":
                environment,
            "message":
                "BEACON API is running.",
        }

    @application.get(
        "/health"
    )
    def healthcheck():
        """Probe dependencies while exposing only minimal public state."""

        database_ok = False
        redis_ok = False

        try:
            database_ok = bool(
                database_healthcheck()
            )
        except Exception:
            database_ok = False

        redis_client = None

        try:
            redis_client = Redis.from_url(
                runtime_settings.redis_url
            )

            redis_ok = bool(
                redis_client.ping()
            )

        except Exception:
            redis_ok = False

        finally:
            if redis_client is not None:
                try:
                    redis_client.close()
                except Exception:
                    pass

        if not (
            database_ok
            and redis_ok
        ):
            return JSONResponse(
                status_code=(
                    status.HTTP_503_SERVICE_UNAVAILABLE
                ),
                content={
                    "status":
                        "unavailable",
                },
            )

        return {
            "status":
                "ok",
        }

    return application


app = create_app()
