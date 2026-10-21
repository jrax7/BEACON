from __future__ import annotations

import importlib.util
import inspect
from types import SimpleNamespace
from uuid import uuid4

import pytest


class FakeDatabase:
    def __init__(self):
        self.added = []

    def add(self, value):
        self.added.append(value)


def test_manual_ready_for_retest_to_resolved_is_blocked() -> None:
    from app.services.finding_workflow import (
        FindingWorkflowError,
        transition_finding,
    )

    finding = SimpleNamespace(
        id=uuid4(),
        lifecycle_state="READY_FOR_RETEST",
    )

    database = FakeDatabase()

    with pytest.raises(
        FindingWorkflowError
    ):
        transition_finding(
            database,
            finding=finding,
            organization_id=uuid4(),
            actor_user_id=uuid4(),
            next_state="RESOLVED",
        )

    assert (
        finding.lifecycle_state
        == "READY_FOR_RETEST"
    )

    assert database.added == []


def test_reconciliation_service_exists() -> None:
    assert importlib.util.find_spec(
        "app.services.finding_reconciliation"
    ) is not None, (
        "finding_reconciliation service does not exist yet."
    )


def test_observation_state_semantics() -> None:
    from app.services.finding_reconciliation import (
        derive_observation_state,
    )

    assert (
        derive_observation_state(None)
        == "NEW"
    )

    assert (
        derive_observation_state(
            SimpleNamespace(
                observation_state="NEW",
                lifecycle_state="TRIAGED",
            )
        )
        == "PERSISTING"
    )

    assert (
        derive_observation_state(
            SimpleNamespace(
                observation_state="RESOLVED",
                lifecycle_state="RESOLVED",
            )
        )
        == "REGRESSED"
    )


def _plan(**changes):
    values = {
        "profile": "deep",
        "profile_version": "deep-v1",
        "assessment_mode": "web",
        "authorized_scope": {
            "fqdn": "example.com",
        },
        "resolved_addresses": [
            "192.0.2.10",
        ],
        "engine_policy_versions": {
            "nmap": "deep-v1",
            "httpx": "deep-v1",
        },
        "crawl_policy": {
            "depth": 8,
        },
        "rate_budget": {
            "requests_per_second": 20,
        },
        "timeout_budget": {
            "assessment_seconds": 10800,
        },
        "nuclei_template_snapshot_id":
            uuid4(),
        "zap_policy_version":
            "beacon-deep-v1",
    }

    values.update(
        changes
    )

    return SimpleNamespace(
        **values
    )


def test_absence_resolution_requires_equivalent_plan_and_clean_scan() -> None:
    from app.services.finding_reconciliation import (
        plans_are_comparable,
        scan_allows_absence_resolution,
    )

    snapshot_id = uuid4()

    first = _plan(
        nuclei_template_snapshot_id=snapshot_id,
    )

    equivalent = _plan(
        nuclei_template_snapshot_id=snapshot_id,
    )

    different = _plan(
        nuclei_template_snapshot_id=snapshot_id,
        profile_version="deep-v2",
    )

    assert plans_are_comparable(
        first,
        equivalent,
    )

    assert not plans_are_comparable(
        first,
        different,
    )

    assert scan_allows_absence_resolution(
        SimpleNamespace(
            status="completed",
            completed_with_warnings=False,
        )
    )

    assert not scan_allows_absence_resolution(
        SimpleNamespace(
            status="completed",
            completed_with_warnings=True,
        )
    )

    assert not scan_allows_absence_resolution(
        SimpleNamespace(
            status="failed",
            completed_with_warnings=False,
        )
    )


def test_orchestration_terminal_paths_are_wired_to_lifecycle_services() -> None:
    from app.assessment.orchestration import (
        DatabaseOrchestrationStore,
    )

    source = inspect.getsource(
        DatabaseOrchestrationStore
    )

    assert (
        source.count(
            "reconcile_terminal_scan("
        )
        >= 3
    )

    assert (
        source.count(
            "complete_retests_for_terminal_scan("
        )
        >= 3
    )
