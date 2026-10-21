from uuid import uuid4


def _row(
    *,
    lifecycle_state="NEW",
    observation_state="NEW",
    disposition=None,
    assignee_user_id=None,
    remediation_owner_user_id=None,
):
    return {
        "id": str(
            uuid4()
        ),
        "severity": "high",
        "confidence": "high",
        "target_id": uuid4(),
        "scan_id": uuid4(),
        "classification": "security_issue",
        "sources": [],
        "title": "Example",
        "description": "Example",
        "issue_key": "example",
        "lifecycle_state":
            lifecycle_state,
        "observation_state":
            observation_state,
        "disposition":
            disposition,
        "assignee_user_id":
            assignee_user_id,
        "remediation_owner_user_id":
            remediation_owner_user_id,
    }


def test_workspace_filters_lifecycle_and_observation() -> None:
    from app.services.findings_workspace import (
        filter_workspace_rows,
    )

    rows = [
        _row(
            lifecycle_state="NEW",
            observation_state="NEW",
        ),
        _row(
            lifecycle_state="IN_REMEDIATION",
            observation_state="PERSISTING",
        ),
    ]

    filtered = filter_workspace_rows(
        rows,
        lifecycle_state="in_remediation",
        observation_state="persisting",
    )

    assert len(filtered) == 1

    assert (
        filtered[0][
            "lifecycle_state"
        ]
        == "IN_REMEDIATION"
    )


def test_workspace_filters_disposition_and_owners() -> None:
    from app.services.findings_workspace import (
        filter_workspace_rows,
    )

    assignee = uuid4()
    owner = uuid4()

    rows = [
        _row(),
        _row(
            disposition="RISK_ACCEPTED",
            assignee_user_id=assignee,
            remediation_owner_user_id=owner,
        ),
    ]

    filtered = filter_workspace_rows(
        rows,
        disposition="risk_accepted",
        assignee_user_id=assignee,
        remediation_owner_user_id=owner,
    )

    assert len(filtered) == 1

    assert (
        filtered[0][
            "disposition"
        ]
        == "RISK_ACCEPTED"
    )


def test_findings_openapi_exposes_workflow_filters() -> None:
    import app.main as main_module

    operation = (
        main_module.app.openapi()
        ["paths"]
        ["/api/v1/findings"]
        ["get"]
    )

    parameters = {
        parameter["name"]
        for parameter
        in operation[
            "parameters"
        ]
    }

    assert {
        "lifecycle_state",
        "observation_state",
        "disposition",
        "assignee_user_id",
        "remediation_owner_user_id",
    } <= parameters


def test_workspace_summary_exposes_primary_raw_finding_identity() -> None:
    from app.schemas.findings import (
        WorkspaceFindingSummaryResponse,
    )

    assert (
        "primary_finding_id"
        in WorkspaceFindingSummaryResponse
        .model_fields
    )
