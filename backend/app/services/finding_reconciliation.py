from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assessment_plan import AssessmentScanPlan
from app.models.finding import Finding
from app.models.finding_workflow_event import FindingWorkflowEvent
from app.models.scan import Scan


COMPARABLE_PLAN_FIELDS = (
    "profile",
    "profile_version",
    "assessment_mode",
    "authorized_scope",
    "resolved_addresses",
    "engine_policy_versions",
    "crawl_policy",
    "rate_budget",
    "timeout_budget",
    "nuclei_template_snapshot_id",
    "zap_policy_version",
)

CONTINUITY_FIELDS = (
    "assignee_user_id",
    "remediation_owner_user_id",
    "disposition",
    "disposition_reason",
    "disposition_set_by_user_id",
    "disposition_set_at",
    "duplicate_of_finding_id",
)


def plans_are_comparable(
    first,
    second,
) -> bool:
    if first is None or second is None:
        return False

    return all(
        getattr(first, field, None)
        == getattr(second, field, None)
        for field in COMPARABLE_PLAN_FIELDS
    )


def scan_allows_absence_resolution(
    scan,
) -> bool:
    return (
        str(
            getattr(
                scan,
                "status",
                "",
            )
        ).strip().lower()
        == "completed"
        and not bool(
            getattr(
                scan,
                "completed_with_warnings",
                False,
            )
        )
    )


def derive_observation_state(
    previous,
) -> str:
    if previous is None:
        return "NEW"

    previous_observation = str(
        getattr(
            previous,
            "observation_state",
            "NEW",
        )
        or "NEW"
    ).upper()

    previous_lifecycle = str(
        getattr(
            previous,
            "lifecycle_state",
            "NEW",
        )
        or "NEW"
    ).upper()

    if (
        previous_observation == "RESOLVED"
        or previous_lifecycle == "RESOLVED"
    ):
        return "REGRESSED"

    return "PERSISTING"


def _event(
    database: Session,
    *,
    finding: Finding,
    scan: Scan,
    event_type: str,
    previous_value: str | None,
    new_value: str | None,
    reason: str,
) -> None:
    database.add(
        FindingWorkflowEvent(
            finding_id=finding.id,
            organization_id=scan.organization_id,
            actor_user_id=scan.user_id,
            event_type=event_type,
            previous_value=previous_value,
            new_value=new_value,
            reason=reason,
            related_scan_id=scan.id,
        )
    )


def _copy_continuity(
    *,
    source: Finding,
    destination: Finding,
) -> None:
    for field in CONTINUITY_FIELDS:
        setattr(
            destination,
            field,
            getattr(
                source,
                field,
                None,
            ),
        )


def _plan_for_scan(
    database: Session,
    scan_id,
):
    return database.scalar(
        select(
            AssessmentScanPlan
        ).where(
            AssessmentScanPlan.scan_id
            == scan_id
        )
    )


def reconcile_terminal_scan(
    database: Session,
    *,
    scan: Scan,
) -> dict[str, int]:
    """Reconcile workflow state after one terminal assessment.

    Positive observations may update lifecycle state even when a completed
    assessment has warnings. Missing findings are only considered resolved
    after a clean completed scan with an equivalent immutable scan plan.
    """

    result = {
        "new": 0,
        "persisting": 0,
        "regressed": 0,
        "resolved": 0,
    }

    if (
        str(
            scan.status
        ).strip().lower()
        != "completed"
    ):
        return result

    current_findings = list(
        database.scalars(
            select(
                Finding
            )
            .where(
                Finding.scan_id
                == scan.id
            )
            .order_by(
                Finding.created_at.asc(),
                Finding.id.asc(),
            )
        )
    )

    prior_scans = list(
        database.scalars(
            select(
                Scan
            )
            .where(
                Scan.organization_id
                == scan.organization_id,
                Scan.target_id
                == scan.target_id,
                Scan.id != scan.id,
                Scan.created_at
                < scan.created_at,
            )
            .order_by(
                Scan.created_at.desc(),
                Scan.id.desc(),
            )
        )
    )

    findings_by_scan = defaultdict(
        list
    )

    if prior_scans:
        prior_scan_ids = [
            item.id
            for item in prior_scans
        ]

        prior_findings = list(
            database.scalars(
                select(
                    Finding
                )
                .where(
                    Finding.scan_id.in_(
                        prior_scan_ids
                    )
                )
                .order_by(
                    Finding.created_at.desc(),
                    Finding.id.asc(),
                )
            )
        )

        for finding in prior_findings:
            findings_by_scan[
                finding.scan_id
            ].append(
                finding
            )

    latest_previous = {}

    for previous_scan in prior_scans:
        for finding in findings_by_scan.get(
            previous_scan.id,
            (),
        ):
            fingerprint = (
                finding.fingerprint
            )

            if (
                not fingerprint
                or fingerprint
                in latest_previous
            ):
                continue

            latest_previous[
                fingerprint
            ] = finding

    current_fingerprints = set()

    for finding in current_findings:
        fingerprint = (
            finding.fingerprint
        )

        previous = (
            latest_previous.get(
                fingerprint
            )
            if fingerprint
            else None
        )

        state = derive_observation_state(
            previous
        )

        old_observation = (
            finding.observation_state
            or "NEW"
        )

        finding.observation_state = (
            state
        )

        if fingerprint:
            current_fingerprints.add(
                fingerprint
            )

        if previous is None:
            result["new"] += 1
            continue

        _copy_continuity(
            source=previous,
            destination=finding,
        )

        finding.first_seen = (
            previous.first_seen
            or previous.created_at
        )

        finding.last_seen = (
            scan.completed_at
            or finding.created_at
        )

        if state == "REGRESSED":
            previous_lifecycle = (
                finding.lifecycle_state
                or "RESOLVED"
            )

            finding.lifecycle_state = (
                "IN_REMEDIATION"
            )

            result[
                "regressed"
            ] += 1

            _event(
                database,
                finding=finding,
                scan=scan,
                event_type="OBSERVATION_REGRESSED",
                previous_value=old_observation,
                new_value="REGRESSED",
                reason=(
                    "A previously resolved finding "
                    "was observed again."
                ),
            )

            _event(
                database,
                finding=finding,
                scan=scan,
                event_type="LIFECYCLE_REOPENED",
                previous_value=previous_lifecycle,
                new_value="IN_REMEDIATION",
                reason=(
                    "Regression evidence reopened "
                    "the vulnerability workflow."
                ),
            )

            continue

        result[
            "persisting"
        ] += 1

        _event(
            database,
            finding=finding,
            scan=scan,
            event_type="OBSERVATION_PERSISTING",
            previous_value=old_observation,
            new_value="PERSISTING",
            reason=(
                "The finding was observed in "
                "another assessment."
            ),
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
                scan=scan,
                event_type="RETEST_EVIDENCE_PERSISTED",
                previous_value="READY_FOR_RETEST",
                new_value="IN_REMEDIATION",
                reason=(
                    "Fresh scan evidence shows "
                    "the finding is still present."
                ),
            )

    if not scan_allows_absence_resolution(
        scan
    ):
        return result

    current_plan = _plan_for_scan(
        database,
        scan.id,
    )

    if current_plan is None:
        return result

    comparable_scan = None

    for previous_scan in prior_scans:
        if not scan_allows_absence_resolution(
            previous_scan
        ):
            continue

        previous_plan = _plan_for_scan(
            database,
            previous_scan.id,
        )

        if plans_are_comparable(
            current_plan,
            previous_plan,
        ):
            comparable_scan = (
                previous_scan
            )
            break

    if comparable_scan is None:
        return result

    for finding in findings_by_scan.get(
        comparable_scan.id,
        (),
    ):
        fingerprint = (
            finding.fingerprint
        )

        if (
            not fingerprint
            or fingerprint
            in current_fingerprints
        ):
            continue

        previous_observation = (
            finding.observation_state
            or "NEW"
        )

        if previous_observation != "RESOLVED":
            finding.observation_state = (
                "RESOLVED"
            )

            result[
                "resolved"
            ] += 1

            _event(
                database,
                finding=finding,
                scan=scan,
                event_type="OBSERVATION_RESOLVED",
                previous_value=previous_observation,
                new_value="RESOLVED",
                reason=(
                    "The finding was absent from "
                    "a clean equivalent completed assessment."
                ),
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
                scan=scan,
                event_type="LIFECYCLE_RESOLVED",
                previous_value="READY_FOR_RETEST",
                new_value="RESOLVED",
                reason=(
                    "Equivalent completed assessment "
                    "verified remediation."
                ),
            )

    return result
