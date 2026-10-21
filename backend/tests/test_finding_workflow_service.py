from __future__ import annotations

from importlib import import_module
import importlib.util
from types import SimpleNamespace
from uuid import uuid4

import pytest


class FakeDatabase:
    def __init__(self):
        self.added = []

    def add(self, value):
        self.added.append(value)


def workflow_module():
    spec = importlib.util.find_spec(
        "app.services.finding_workflow"
    )

    assert spec is not None, (
        "finding_workflow service does not exist yet."
    )

    return import_module(
        "app.services.finding_workflow"
    )


def finding(state="NEW"):
    return SimpleNamespace(
        id=uuid4(),
        lifecycle_state=state,
        observation_state="NEW",
        disposition=None,
        disposition_reason=None,
        disposition_set_by_user_id=None,
        disposition_set_at=None,
        duplicate_of_finding_id=None,
        assignee_user_id=None,
        remediation_owner_user_id=None,
    )


def test_valid_lifecycle_transition_is_audited() -> None:
    workflow = workflow_module()

    database = FakeDatabase()
    actor_id = uuid4()
    organization_id = uuid4()
    item = finding()

    workflow.transition_finding(
        database,
        finding=item,
        organization_id=organization_id,
        actor_user_id=actor_id,
        next_state="TRIAGED",
    )

    assert item.lifecycle_state == "TRIAGED"

    assert len(database.added) == 1

    event = database.added[0]

    assert event.finding_id == item.id
    assert event.organization_id == organization_id
    assert event.actor_user_id == actor_id
    assert event.event_type == "LIFECYCLE_TRANSITION"
    assert event.previous_value == "NEW"
    assert event.new_value == "TRIAGED"


def test_invalid_lifecycle_jump_fails_closed() -> None:
    workflow = workflow_module()

    database = FakeDatabase()
    item = finding()

    with pytest.raises(
        workflow.FindingWorkflowError
    ):
        workflow.transition_finding(
            database,
            finding=item,
            organization_id=uuid4(),
            actor_user_id=uuid4(),
            next_state="RESOLVED",
        )

    assert item.lifecycle_state == "NEW"
    assert database.added == []


def test_risk_acceptance_requires_non_empty_reason() -> None:
    workflow = workflow_module()

    database = FakeDatabase()
    item = finding()

    with pytest.raises(
        workflow.FindingWorkflowError
    ):
        workflow.set_disposition(
            database,
            finding=item,
            organization_id=uuid4(),
            actor_user_id=uuid4(),
            disposition="RISK_ACCEPTED",
            reason="   ",
        )

    assert item.disposition is None
    assert database.added == []


def test_false_positive_records_actor_reason_and_time() -> None:
    workflow = workflow_module()

    database = FakeDatabase()
    actor_id = uuid4()
    organization_id = uuid4()
    item = finding()

    workflow.set_disposition(
        database,
        finding=item,
        organization_id=organization_id,
        actor_user_id=actor_id,
        disposition="FALSE_POSITIVE",
        reason="Scanner evidence is not applicable.",
    )

    assert item.disposition == "FALSE_POSITIVE"
    assert (
        item.disposition_reason
        == "Scanner evidence is not applicable."
    )
    assert item.disposition_set_by_user_id == actor_id
    assert item.disposition_set_at is not None

    assert len(database.added) == 1

    event = database.added[0]

    assert event.actor_user_id == actor_id
    assert event.event_type == "DISPOSITION_SET"
    assert event.new_value == "FALSE_POSITIVE"
    assert (
        event.reason
        == "Scanner evidence is not applicable."
    )
