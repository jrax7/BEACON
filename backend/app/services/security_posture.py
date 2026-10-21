from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan


SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)

TERMINAL_DISPOSITIONS = {
    "FALSE_POSITIVE",
    "RISK_ACCEPTED",
    "DUPLICATE",
}


def summarize_posture(
    findings,
) -> dict[str, object]:
    metrics = {
        "active": 0,
        "new": 0,
        "persisting": 0,
        "regressed": 0,
        "resolved": 0,
        "awaiting_triage": 0,
        "awaiting_assignment": 0,
        "in_remediation": 0,
        "awaiting_retest": 0,
        "risk_accepted": 0,
        "false_positive": 0,
        "severity_breakdown": {
            severity: 0
            for severity in SEVERITIES
        },
    }

    for finding in findings:
        lifecycle = str(
            getattr(
                finding,
                "lifecycle_state",
                "NEW",
            )
            or "NEW"
        ).upper()

        observation = str(
            getattr(
                finding,
                "observation_state",
                "NEW",
            )
            or "NEW"
        ).upper()

        disposition = getattr(
            finding,
            "disposition",
            None,
        )

        disposition = (
            str(disposition).upper()
            if disposition
            else None
        )

        if observation == "NEW":
            metrics["new"] += 1

        if observation == "PERSISTING":
            metrics["persisting"] += 1

        if observation == "REGRESSED":
            metrics["regressed"] += 1

        resolved = (
            observation == "RESOLVED"
            or lifecycle == "RESOLVED"
        )

        if resolved:
            metrics["resolved"] += 1

        if disposition == "RISK_ACCEPTED":
            metrics["risk_accepted"] += 1

        if disposition == "FALSE_POSITIVE":
            metrics["false_positive"] += 1

        active = (
            not resolved
            and disposition
            not in TERMINAL_DISPOSITIONS
        )

        if not active:
            continue

        metrics["active"] += 1

        severity = str(
            getattr(
                finding,
                "severity",
                "informational",
            )
            or "informational"
        ).lower()

        if severity not in SEVERITIES:
            severity = "informational"

        metrics[
            "severity_breakdown"
        ][severity] += 1

        if lifecycle == "NEW":
            metrics[
                "awaiting_triage"
            ] += 1

        elif lifecycle == "TRIAGED":
            metrics[
                "awaiting_assignment"
            ] += 1

        elif lifecycle in {
            "ASSIGNED",
            "IN_REMEDIATION",
        }:
            metrics[
                "in_remediation"
            ] += 1

        elif lifecycle == "READY_FOR_RETEST":
            metrics[
                "awaiting_retest"
            ] += 1

    return metrics


def build_security_posture(
    database: Session,
    organization_id,
) -> dict[str, object]:
    scans = list(
        database.scalars(
            select(
                Scan
            )
            .where(
                Scan.organization_id
                == organization_id
            )
            .order_by(
                Scan.created_at.desc(),
                Scan.id.desc(),
            )
        )
    )

    if not scans:
        return summarize_posture(
            []
        )

    scan_ids = [
        scan.id
        for scan in scans
    ]

    findings = list(
        database.scalars(
            select(
                Finding
            ).where(
                Finding.scan_id.in_(
                    scan_ids
                )
            )
        )
    )

    findings_by_scan = defaultdict(
        list
    )

    for finding in findings:
        findings_by_scan[
            finding.scan_id
        ].append(
            finding
        )

    latest = {}

    for scan in scans:
        for finding in findings_by_scan.get(
            scan.id,
            (),
        ):
            identity = (
                scan.target_id,
                finding.fingerprint
                or str(
                    finding.id
                ),
            )

            if identity not in latest:
                latest[
                    identity
                ] = finding

    return summarize_posture(
        list(
            latest.values()
        )
    )
