from __future__ import annotations

from importlib import import_module
import importlib.util


def _one_fk(column):
    keys = list(column.foreign_keys)
    assert len(keys) == 1
    return keys[0]


def test_finding_has_phase16e_workflow_columns() -> None:
    from app.models.finding import Finding

    table = Finding.__table__

    expected = {
        "lifecycle_state",
        "observation_state",
        "assignee_user_id",
        "remediation_owner_user_id",
        "disposition",
        "disposition_reason",
        "disposition_set_by_user_id",
        "disposition_set_at",
        "duplicate_of_finding_id",
    }

    assert expected <= set(table.c.keys()), (
        "Phase 16E workflow columns are missing."
    )

    assert table.c.lifecycle_state.nullable is False
    assert table.c.lifecycle_state.type.length == 30
    assert table.c.lifecycle_state.index is True

    assert table.c.observation_state.nullable is False
    assert table.c.observation_state.type.length == 30
    assert table.c.observation_state.index is True

    assert table.c.assignee_user_id.nullable is True
    assert (
        _one_fk(
            table.c.assignee_user_id
        ).target_fullname
        == "users.id"
    )

    assert table.c.remediation_owner_user_id.nullable is True
    assert (
        _one_fk(
            table.c.remediation_owner_user_id
        ).target_fullname
        == "users.id"
    )

    assert (
        _one_fk(
            table.c.disposition_set_by_user_id
        ).target_fullname
        == "users.id"
    )

    assert (
        _one_fk(
            table.c.duplicate_of_finding_id
        ).target_fullname
        == "findings.id"
    )


def test_finding_workflow_event_model_contract() -> None:
    spec = importlib.util.find_spec(
        "app.models.finding_workflow_event"
    )

    assert spec is not None, (
        "finding_workflow_event model does not exist yet."
    )

    module = import_module(
        "app.models.finding_workflow_event"
    )
    model = getattr(
        module,
        "FindingWorkflowEvent",
        None,
    )

    assert model is not None, (
        "FindingWorkflowEvent does not exist yet."
    )

    table = model.__table__

    assert table.name == "finding_workflow_events"

    assert {
        "id",
        "finding_id",
        "organization_id",
        "actor_user_id",
        "event_type",
        "previous_value",
        "new_value",
        "reason",
        "related_scan_id",
        "created_at",
    } <= set(table.c.keys())

    assert table.c.finding_id.nullable is False
    assert table.c.organization_id.nullable is False
    assert table.c.actor_user_id.nullable is False
    assert table.c.event_type.nullable is False
    assert table.c.created_at.nullable is False

    assert (
        _one_fk(
            table.c.finding_id
        ).target_fullname
        == "findings.id"
    )

    assert (
        _one_fk(
            table.c.organization_id
        ).target_fullname
        == "organizations.id"
    )

    assert (
        _one_fk(
            table.c.actor_user_id
        ).target_fullname
        == "users.id"
    )
