from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.finding_workflow_event import (
    FindingWorkflowEvent,
)
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.scan import Scan
from app.models.user import User


VALID_DISPOSITIONS = frozenset(
    {
        "FALSE_POSITIVE",
        "RISK_ACCEPTED",
        "DUPLICATE",
    }
)

VALID_LIFECYCLE_TRANSITIONS = {
    "NEW": frozenset({"TRIAGED"}),
    "TRIAGED": frozenset(
        {"NEW", "ASSIGNED"}
    ),
    "ASSIGNED": frozenset(
        {"TRIAGED", "IN_REMEDIATION"}
    ),
    "IN_REMEDIATION": frozenset(
        {"ASSIGNED", "READY_FOR_RETEST"}
    ),
    "READY_FOR_RETEST": frozenset(
        {"IN_REMEDIATION"}
    ),
    "RESOLVED": frozenset(
        {"IN_REMEDIATION"}
    ),
}


class FindingWorkflowError(ValueError):
    """Invalid finding workflow mutation."""


def _optional_reason(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


def _required_reason(
    value: str | None,
) -> str:
    normalized = _optional_reason(
        value
    )

    if normalized is None:
        raise FindingWorkflowError(
            "A non-empty reason is required."
        )

    return normalized


def _append_event(
    database: Session,
    *,
    finding_id: UUID,
    organization_id: UUID,
    actor_user_id: UUID,
    event_type: str,
    previous_value: str | None,
    new_value: str | None,
    reason: str | None = None,
    related_scan_id: UUID | None = None,
) -> FindingWorkflowEvent:
    event = FindingWorkflowEvent(
        finding_id=finding_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        previous_value=previous_value,
        new_value=new_value,
        reason=reason,
        related_scan_id=related_scan_id,
    )

    database.add(
        event
    )

    return event


def transition_finding(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    next_state: str,
    reason: str | None = None,
) -> Finding:
    current = str(
        finding.lifecycle_state or "NEW"
    ).strip().upper()

    candidate = str(
        next_state
    ).strip().upper()

    allowed = VALID_LIFECYCLE_TRANSITIONS.get(
        current,
        frozenset(),
    )

    if candidate not in allowed:
        raise FindingWorkflowError(
            "Invalid finding lifecycle transition: "
            f"{current} -> {candidate}."
        )

    finding.lifecycle_state = candidate

    _append_event(
        database,
        finding_id=finding.id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="LIFECYCLE_TRANSITION",
        previous_value=current,
        new_value=candidate,
        reason=_optional_reason(
            reason
        ),
    )

    return finding


def _organization_member_exists(
    database: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
) -> bool:
    membership = database.scalar(
        select(
            OrganizationMembership
        )
        .join(
            User,
            OrganizationMembership.user_id
            == User.id,
        )
        .where(
            OrganizationMembership.organization_id
            == organization_id,
            OrganizationMembership.user_id
            == user_id,
            User.is_active.is_(True),
        )
    )

    return membership is not None


def assign_finding(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    assignee_user_id: UUID | None,
) -> Finding:
    if (
        assignee_user_id is not None
        and not _organization_member_exists(
            database,
            organization_id=organization_id,
            user_id=assignee_user_id,
        )
    ):
        raise FindingWorkflowError(
            "Assignee must belong to "
            "the current organization."
        )

    previous = finding.assignee_user_id

    if previous == assignee_user_id:
        return finding

    finding.assignee_user_id = (
        assignee_user_id
    )

    _append_event(
        database,
        finding_id=finding.id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="ASSIGNEE_CHANGED",
        previous_value=(
            str(previous)
            if previous is not None
            else None
        ),
        new_value=(
            str(assignee_user_id)
            if assignee_user_id is not None
            else None
        ),
    )

    return finding


def set_remediation_owner(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    remediation_owner_user_id: UUID | None,
) -> Finding:
    if (
        remediation_owner_user_id is not None
        and not _organization_member_exists(
            database,
            organization_id=organization_id,
            user_id=remediation_owner_user_id,
        )
    ):
        raise FindingWorkflowError(
            "Remediation owner must belong "
            "to the current organization."
        )

    previous = (
        finding.remediation_owner_user_id
    )

    if previous == remediation_owner_user_id:
        return finding

    finding.remediation_owner_user_id = (
        remediation_owner_user_id
    )

    _append_event(
        database,
        finding_id=finding.id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="REMEDIATION_OWNER_CHANGED",
        previous_value=(
            str(previous)
            if previous is not None
            else None
        ),
        new_value=(
            str(remediation_owner_user_id)
            if remediation_owner_user_id is not None
            else None
        ),
    )

    return finding


def _organization_finding(
    database: Session,
    *,
    organization_id: UUID,
    finding_id: UUID,
) -> Finding | None:
    return database.scalar(
        select(Finding)
        .join(
            Scan,
            Finding.scan_id == Scan.id,
        )
        .where(
            Finding.id == finding_id,
            Scan.organization_id
            == organization_id,
        )
    )


def set_disposition(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    disposition: str,
    reason: str,
    duplicate_of_finding_id: UUID | None = None,
) -> Finding:
    candidate = str(
        disposition
    ).strip().upper()

    if candidate not in VALID_DISPOSITIONS:
        raise FindingWorkflowError(
            "Invalid finding disposition."
        )

    normalized_reason = _required_reason(
        reason
    )

    duplicate_id = None

    if candidate == "DUPLICATE":
        if duplicate_of_finding_id is None:
            raise FindingWorkflowError(
                "Duplicate disposition requires "
                "a canonical finding."
            )

        if duplicate_of_finding_id == finding.id:
            raise FindingWorkflowError(
                "A finding cannot duplicate itself."
            )

        duplicate = _organization_finding(
            database,
            organization_id=organization_id,
            finding_id=duplicate_of_finding_id,
        )

        if duplicate is None:
            raise FindingWorkflowError(
                "Duplicate finding is not available "
                "in this organization."
            )

        duplicate_id = duplicate.id

    previous = finding.disposition

    finding.disposition = candidate
    finding.disposition_reason = (
        normalized_reason
    )
    finding.disposition_set_by_user_id = (
        actor_user_id
    )
    finding.disposition_set_at = (
        datetime.now(
            timezone.utc
        )
    )
    finding.duplicate_of_finding_id = (
        duplicate_id
    )

    _append_event(
        database,
        finding_id=finding.id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="DISPOSITION_SET",
        previous_value=previous,
        new_value=candidate,
        reason=normalized_reason,
    )

    return finding


def clear_disposition(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    reason: str,
) -> Finding:
    normalized_reason = _required_reason(
        reason
    )

    previous = finding.disposition

    if previous is None:
        raise FindingWorkflowError(
            "Finding has no disposition to clear."
        )

    finding.disposition = None
    finding.disposition_reason = None
    finding.disposition_set_by_user_id = None
    finding.disposition_set_at = None
    finding.duplicate_of_finding_id = None

    _append_event(
        database,
        finding_id=finding.id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="DISPOSITION_CLEARED",
        previous_value=previous,
        new_value=None,
        reason=normalized_reason,
    )

    return finding


def list_workflow_history(
    database: Session,
    *,
    finding_id: UUID,
    organization_id: UUID,
) -> list[FindingWorkflowEvent]:
    return list(
        database.scalars(
            select(
                FindingWorkflowEvent
            )
            .where(
                FindingWorkflowEvent.finding_id
                == finding_id,
                FindingWorkflowEvent.organization_id
                == organization_id,
            )
            .order_by(
                FindingWorkflowEvent.created_at.asc(),
                FindingWorkflowEvent.id.asc(),
            )
        )
    )
