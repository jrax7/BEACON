from __future__ import annotations

import importlib.util
from types import SimpleNamespace


def test_security_posture_service_exists() -> None:
    assert importlib.util.find_spec(
        "app.services.security_posture"
    ) is not None, (
        "security_posture service does not exist yet."
    )


def _finding(
    *,
    lifecycle,
    observation,
    severity="medium",
    disposition=None,
):
    return SimpleNamespace(
        lifecycle_state=lifecycle,
        observation_state=observation,
        severity=severity,
        disposition=disposition,
    )


def test_security_posture_is_deterministic() -> None:
    from app.services.security_posture import (
        summarize_posture,
    )

    result = summarize_posture(
        [
            _finding(
                lifecycle="NEW",
                observation="NEW",
                severity="high",
            ),
            _finding(
                lifecycle="IN_REMEDIATION",
                observation="PERSISTING",
                severity="medium",
            ),
            _finding(
                lifecycle="IN_REMEDIATION",
                observation="REGRESSED",
                severity="critical",
            ),
            _finding(
                lifecycle="RESOLVED",
                observation="RESOLVED",
                severity="low",
            ),
            _finding(
                lifecycle="TRIAGED",
                observation="PERSISTING",
                disposition="RISK_ACCEPTED",
            ),
            _finding(
                lifecycle="TRIAGED",
                observation="PERSISTING",
                disposition="FALSE_POSITIVE",
            ),
        ]
    )

    assert result["active"] == 3
    assert result["new"] == 1
    assert result["persisting"] == 3
    assert result["regressed"] == 1
    assert result["resolved"] == 1
    assert result["awaiting_triage"] == 1
    assert result["in_remediation"] == 2
    assert result["risk_accepted"] == 1
    assert result["false_positive"] == 1

    assert result["severity_breakdown"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "informational": 0,
    }


def test_posture_api_route_precedes_dynamic_finding_route() -> None:
    import app.main as main_module
    import app.routers.findings as findings_module

    paths = main_module.app.openapi()[
        "paths"
    ]

    assert (
        "/api/v1/findings/posture"
        in paths
    )

    assert (
        "get"
        in paths[
            "/api/v1/findings/posture"
        ]
    )

    routes = [
        route.path
        for route in findings_module.router.routes
    ]

    assert routes.index(
        "/api/v1/findings/posture"
    ) < routes.index(
        "/api/v1/findings/{finding_id:path}"
    )
