from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main


def _runtime(
    environment: str,
):
    return SimpleNamespace(
        app_name="BEACON",
        environment=environment,
        redis_url="redis://redis.invalid:6379/0",
    )


class _RedisClient:
    def __init__(
        self,
        healthy: bool,
    ):
        self.healthy = healthy

    def ping(
        self,
    ):
        if not self.healthy:
            raise RuntimeError(
                "redis.internal:6379 sensitive detail"
            )

        return True

    def close(
        self,
    ):
        return None


class _RedisFactory:
    healthy = True

    @classmethod
    def from_url(
        cls,
        _url,
    ):
        return _RedisClient(
            cls.healthy
        )


def _client(
    monkeypatch,
    *,
    environment="production",
    database_healthy=True,
    redis_healthy=True,
):
    def database_probe():
        if not database_healthy:
            raise RuntimeError(
                "postgres.internal:5432 sensitive detail"
            )

        return True

    monkeypatch.setattr(
        main,
        "database_healthcheck",
        database_probe,
    )

    _RedisFactory.healthy = (
        redis_healthy
    )

    monkeypatch.setattr(
        main,
        "Redis",
        _RedisFactory,
    )

    application = main.create_app(
        _runtime(
            environment
        )
    )

    return TestClient(
        application
    )


def test_production_health_is_minimal_when_dependencies_are_healthy(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
    )

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status":
            "ok",
    }


def test_health_failure_is_minimal_and_non_leaky(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
        database_healthy=False,
        redis_healthy=False,
    )

    response = client.get(
        "/health"
    )

    assert response.status_code == 503

    assert response.json() == {
        "status":
            "unavailable",
    }

    body = response.text.lower()

    assert "postgres.internal" not in body
    assert "redis.internal" not in body
    assert "5432" not in body
    assert "6379" not in body


def test_production_disables_docs_redoc_and_openapi(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
    )

    assert client.get(
        "/docs"
    ).status_code == 404

    assert client.get(
        "/redoc"
    ).status_code == 404

    assert client.get(
        "/openapi.json"
    ).status_code == 404


def test_development_keeps_openapi_available(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
        environment="development",
    )

    assert client.get(
        "/docs"
    ).status_code == 200

    assert client.get(
        "/openapi.json"
    ).status_code == 200


def test_temporary_task_http_routes_are_not_public_release_surface(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
    )

    assert client.post(
        "/api/v1/tasks/test",
        json={
            "first_number":
                20,
            "second_number":
                22,
        },
    ).status_code == 404

    assert client.get(
        "/api/v1/tasks/example-task"
    ).status_code == 404


def test_auth_responses_are_no_store_directly_from_backend(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
    )

    response = client.get(
        "/api/v1/auth/me"
    )

    assert response.status_code == 401

    assert (
        response.headers.get(
            "Cache-Control"
        )
        == "no-store"
    )


def test_production_never_emits_wildcard_cors(
    monkeypatch,
) -> None:
    client = _client(
        monkeypatch,
    )

    response = client.get(
        "/health",
        headers={
            "Origin":
                "https://evil.example",
        },
    )

    assert (
        response.headers.get(
            "Access-Control-Allow-Origin"
        )
        is None
    )
