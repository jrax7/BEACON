from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace
from unittest.mock import patch


ENGINE_ORDER = (
    "nmap",
    "httpx",
    "katana",
    "sslyze",
    "nuclei",
    "zap",
    "nikto",
)


def test_collect_scanner_health_aggregates_all_engines():
    from app.assessment.health import (
        collect_scanner_health,
    )

    providers = {
        engine:
            (
                lambda value=engine:
                    f"{value}-1.0"
            )
        for engine
        in ENGINE_ORDER
    }

    now = datetime(
        2026,
        8,
        31,
        8,
        0,
        tzinfo=timezone.utc,
    )

    inventory = (
        collect_scanner_health(
            providers=providers,
            clock=lambda: now,
        )
    )

    assert inventory.status == "healthy"
    assert inventory.checked_at == now

    assert tuple(
        item.engine
        for item
        in inventory.engines
    ) == ENGINE_ORDER

    assert all(
        item.status == "healthy"
        for item
        in inventory.engines
    )

    assert all(
        item.version
        for item
        in inventory.engines
    )

    assert all(
        item.error is None
        for item
        in inventory.engines
    )


def test_one_scanner_failure_degrades_without_hiding_others():
    from app.assessment.health import (
        collect_scanner_health,
    )

    def broken():
        raise RuntimeError(
            "nuclei unavailable"
        )

    providers = {
        engine:
            (
                broken
                if engine == "nuclei"
                else (
                    lambda value=engine:
                        f"{value}-1.0"
                )
            )
        for engine
        in ENGINE_ORDER
    }

    inventory = (
        collect_scanner_health(
            providers=providers
        )
    )

    assert inventory.status == "degraded"

    by_engine = {
        item.engine:
            item
        for item
        in inventory.engines
    }

    assert (
        by_engine[
            "nuclei"
        ].status
        == "unavailable"
    )

    assert (
        by_engine[
            "nuclei"
        ].version
        is None
    )

    assert (
        "nuclei unavailable"
        in (
            by_engine[
                "nuclei"
            ].error
            or ""
        )
    )

    assert (
        by_engine[
            "nmap"
        ].status
        == "healthy"
    )

    assert (
        by_engine[
            "zap"
        ].status
        == "healthy"
    )


def test_all_scanner_failures_report_inventory_unavailable():
    from app.assessment.health import (
        collect_scanner_health,
    )

    def unavailable():
        raise RuntimeError(
            "runtime unavailable"
        )

    providers = {
        engine:
            unavailable
        for engine
        in ENGINE_ORDER
    }

    inventory = (
        collect_scanner_health(
            providers=providers
        )
    )

    assert inventory.status == "unavailable"

    assert len(
        inventory.engines
    ) == 7

    assert all(
        item.status == "unavailable"
        for item
        in inventory.engines
    )


def test_scanner_health_api_serializes_collector_result():
    from app.assessment.health import (
        ScannerHealthEngine,
        ScannerHealthInventory,
    )
    from app.routers import (
        assessments as assessment_router,
    )

    now = datetime(
        2026,
        8,
        31,
        8,
        30,
        tzinfo=timezone.utc,
    )

    expected = ScannerHealthInventory(
        status="degraded",
        checked_at=now,
        engines=[
            ScannerHealthEngine(
                engine="nmap",
                status="healthy",
                version="7.95",
                error=None,
            ),
            ScannerHealthEngine(
                engine="zap",
                status="unavailable",
                version=None,
                error="connection refused",
            ),
        ],
    )

    with patch.object(
        assessment_router,
        "collect_scanner_health",
        return_value=expected,
    ) as collect:
        result = (
            assessment_router
            .read_scanner_health(
                SimpleNamespace()
            )
        )

    collect.assert_called_once_with()

    assert result == expected
    assert result.status == "degraded"

    payload = result.model_dump(
        mode="json"
    )

    assert payload[
        "checked_at"
    ] == (
        "2026-08-31T08:30:00Z"
    )

    assert payload[
        "engines"
    ][0] == {
        "engine": "nmap",
        "status": "healthy",
        "version": "7.95",
        "error": None,
    }
