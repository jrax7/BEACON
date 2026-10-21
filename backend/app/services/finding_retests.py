from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment_plan import AssessmentScanPlan
from app.models.finding import Finding
from app.models.finding_retest import FindingRetest
from app.models.finding_workflow_event import FindingWorkflowEvent
from app.models.scan import Scan
from app.services.finding_reconciliation import (
    plans_are_comparable,
)
from app.services.finding_workflow import FindingWorkflowError


ACTIVE_RETEST_STATUSES = (
    "REQUESTED",
    "RUNNING",
)


def terminal_retest_status(
    *,
    scan_status: str,
    completed_with_warnings: bool,
    finding_present: bool | None,
    comparable: bool,
) -> str:
    status = (
        scan_status
        .strip()
        .lower()
    )

    if status == "cancelled":
        return "CANCELLED"

    if status == "failed":
        return "FAILED"

    if status != "completed":
        return "RUNNING"

    if (
        completed_with_warnings
        or not comparable
        or finding_present is None
    ):
        return "FAILED"

    if finding_present:
        return "FAILED"

    return "PASSED"


def _event(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    event_type: str,
    previous_value: str | None,
    new_value: str | None,
    scan_id: UUID | None,
    reason: str,
) -> None:
    database.add(
        FindingWorkflowEvent(
            finding_id=finding.id,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            event_type=event_type,
            previous_value=previous_value,
            new_value=new_value,
            reason=reason,
            related_scan_id=scan_id,
        )
    )


def _plan(
    database: Session,
    scan_id: UUID,
):
    return database.scalar(
        select(
            AssessmentScanPlan
        ).where(
            AssessmentScanPlan.scan_id
            == scan_id
        )
    )


def link_retest_scan(
    database: Session,
    *,
    retest: FindingRetest,
    finding: Finding,
    organization_id: UUID,
    scan_id: UUID,
) -> FindingRetest:
    scan = database.scalar(
        select(
            Scan
        ).where(
            Scan.id == scan_id,
            Scan.organization_id
            == organization_id,
        )
    )

    if scan is None:
        raise FindingWorkflowError(
            "Retest scan was not found "
            "in this organization."
        )

    original_scan = database.get(
        Scan,
        finding.scan_id,
    )

    if (
        original_scan is None
        or scan.target_id
        != original_scan.target_id
    ):
        raise FindingWorkflowError(
            "Retest scan must assess "
            "the same target."
        )

    retest.scan_id = scan.id

    if scan.status in {
        "pending",
        "queued",
        "running",
        "cancelling",
    }:
        retest.status = "RUNNING"

    if scan.status in {
        "completed",
        "failed",
        "cancelled",
    }:
        database.flush()

        complete_retests_for_terminal_scan(
            database,
            scan=scan,
        )

    return retest


def request_retest(
    database: Session,
    *,
    finding: Finding,
    organization_id: UUID,
    actor_user_id: UUID,
    scan_id: UUID | None = None,
) -> FindingRetest:
    if (
        finding.lifecycle_state
        != "READY_FOR_RETEST"
    ):
        raise FindingWorkflowError(
            "Finding must be READY_FOR_RETEST "
            "before a retest can be requested."
        )

    active = database.scalar(
        select(
            FindingRetest
        ).where(
            FindingRetest.finding_id
            == finding.id,
            FindingRetest.organization_id
            == organization_id,
            FindingRetest.status.in_(
                ACTIVE_RETEST_STATUSES
            ),
        )
    )

    if active is not None:
        raise FindingWorkflowError(
            "An active retest already exists "
            "for this finding."
        )

    retest = FindingRetest(
        finding_id=finding.id,
        organization_id=organization_id,
        requested_by_user_id=actor_user_id,
        status="REQUESTED",
    )

    database.add(
        retest
    )

    if scan_id is not None:
        link_retest_scan(
            database,
            retest=retest,
            finding=finding,
            organization_id=organization_id,
            scan_id=scan_id,
        )

    _event(
        database,
        finding=finding,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        event_type="RETEST_REQUESTED",
        previous_value=None,
        new_value="REQUESTED",
        scan_id=scan_id,
        reason="A vulnerability retest was requested.",
    )

    if scan_id is not None:
        database.flush()

        scan = database.get(
            Scan,
            scan_id,
        )

        if (
            scan is not None
            and scan.status
            in {
                "completed",
                "failed",
                "cancelled",
            }
        ):
            complete_retests_for_terminal_scan(
                database,
                scan=scan,
            )

    return retest


def list_retests(
    database: Session,
    *,
    finding_id: UUID,
    organization_id: UUID,
) -> list[FindingRetest]:
    return list(
        database.scalars(
            select(
                FindingRetest
            )
            .where(
                FindingRetest.finding_id
                == finding_id,
                FindingRetest.organization_id
                == organization_id,
            )
            .order_by(
                FindingRetest.requested_at.desc(),
                FindingRetest.id.desc(),
            )
        )
    )


def complete_retests_for_terminal_scan(
    database: Session,
    *,
    scan: Scan,
) -> int:
    if (
        scan.status
        not in {
            "completed",
            "failed",
            "cancelled",
        }
    ):
        return 0

    retests = list(
        database.scalars(
            select(
                FindingRetest
            ).where(
                FindingRetest.scan_id
                == scan.id,
                FindingRetest.organization_id
                == scan.organization_id,
                FindingRetest.status.in_(
                    ACTIVE_RETEST_STATUSES
                ),
            )
        )
    )

    if not retests:
        return 0

    current_findings = list(
        database.scalars(
            select(
                Finding
            ).where(
                Finding.scan_id
                == scan.id
            )
        )
    )

    current_fingerprints = {
        finding.fingerprint
        for finding in current_findings
        if finding.fingerprint
    }

    current_plan = _plan(
        database,
        scan.id,
    )

    completed = 0

    for retest in retests:
        finding = database.get(
            Finding,
            retest.finding_id,
        )

        if finding is None:
            retest.status = "FAILED"
            retest.completed_at = (
                scan.completed_at
                or datetime.now(
                    timezone.utc
                )
            )
            completed += 1
            continue

        original_plan = _plan(
            database,
            finding.scan_id,
        )

        comparable = plans_are_comparable(
            current_plan,
            original_plan,
        )

        fingerprint = (
            finding.fingerprint
        )

        finding_present = (
            fingerprint
            in current_fingerprints
            if fingerprint
            else None
        )

        result = terminal_retest_status(
            scan_status=scan.status,
            completed_with_warnings=bool(
                scan.completed_with_warnings
            ),
            finding_present=finding_present,
            comparable=comparable,
        )

        previous_status = (
            retest.status
        )

        retest.status = result
        retest.completed_at = (
            scan.completed_at
            or datetime.now(
                timezone.utc
            )
        )

        if result == "PASSED":
            old_observation = (
                finding.observation_state
                or "NEW"
            )

            finding.observation_state = (
                "RESOLVED"
            )

            if (
                finding.lifecycle_state
                == "READY_FOR_RETEST"
            ):
                finding.lifecycle_state = (
                    "RESOLVED"
                )

            _event(
                database,
                finding=finding,
                organization_id=scan.organization_id,
                actor_user_id=scan.user_id,
                event_type="RETEST_PASSED",
                previous_value=previous_status,
                new_value="PASSED",
                scan_id=scan.id,
                reason=(
                    "Equivalent clean assessment "
                    "verified the finding is absent."
                ),
            )

            if (
                old_observation
                != "RESOLVED"
            ):
                _event(
                    database,
                    finding=finding,
                    organization_id=scan.organization_id,
                    actor_user_id=scan.user_id,
                    event_type="OBSERVATION_RESOLVED",
                    previous_value=old_observation,
                    new_value="RESOLVED",
                    scan_id=scan.id,
                    reason=(
                        "Successful retest verified remediation."
                    ),
                )

        elif (
            result == "FAILED"
            and scan.status == "completed"
            and finding_present is True
        ):
            finding.observation_state = (
                "PERSISTING"
            )

            if (
                finding.lifecycle_state
                == "READY_FOR_RETEST"
            ):
                finding.lifecycle_state = (
                    "IN_REMEDIATION"
                )

            _event(
                database,
                finding=finding,
                organization_id=scan.organization_id,
                actor_user_id=scan.user_id,
                event_type="RETEST_FAILED",
                previous_value=previous_status,
                new_value="FAILED",
                scan_id=scan.id,
                reason=(
                    "Retest evidence confirms "
                    "the finding is still present."
                ),
            )

        else:
            _event(
                database,
                finding=finding,
                organization_id=scan.organization_id,
                actor_user_id=scan.user_id,
                event_type=(
                    "RETEST_CANCELLED"
                    if result == "CANCELLED"
                    else "RETEST_FAILED"
                ),
                previous_value=previous_status,
                new_value=result,
                scan_id=scan.id,
                reason=(
                    "Retest did not provide "
                    "sufficient successful evidence "
                    "to resolve the finding."
                ),
            )

        completed += 1

    return completed
