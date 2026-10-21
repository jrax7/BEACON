from collections import defaultdict
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.services.finding_aggregation import (
    aggregate_findings,
    build_issue_key,
)


def workspace_finding_id(
    scan_id: UUID,
    issue_key: str,
) -> str:
    return f"{scan_id}:{issue_key}"


def parse_workspace_finding_id(
    value: str,
) -> tuple[UUID, str]:
    scan_text, separator, issue_key = value.partition(":")

    if not separator or not issue_key:
        raise ValueError("Invalid finding identifier.")

    return UUID(scan_text), issue_key


def resolve_workspace_members(
    database: Session,
    organization_id: UUID,
    finding_id: str,
) -> list[Finding] | None:
    """Resolve one workspace aggregate to organization-scoped rows."""

    try:
        scan_id, issue_key = parse_workspace_finding_id(
            finding_id
        )
    except ValueError:
        return None

    scan = database.scalar(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == organization_id,
            Scan.archived_at.is_(None),
        )
    )

    if scan is None:
        return None

    findings = list(
        database.scalars(
            select(Finding)
            .where(
                Finding.scan_id == scan_id
            )
            .order_by(
                Finding.created_at.desc(),
                Finding.id.asc(),
            )
        )
    )

    members = [
        finding
        for finding in findings
        if build_issue_key(
            finding
        ) == issue_key
    ]

    return members or None


def build_workspace_rows(
    database: Session,
    organization_id: UUID,
) -> list[dict[str, Any]]:
    scans = list(
        database.scalars(
            select(Scan)
            .where(
                Scan.organization_id == organization_id,
                Scan.archived_at.is_(None),
            )
            .order_by(Scan.created_at.desc())
        )
    )

    if not scans:
        return []

    scan_ids = [
        scan.id
        for scan in scans
    ]

    targets = {
        target.id: target
        for target in database.scalars(
            select(Target).where(
                Target.organization_id == organization_id,
            )
        )
    }

    raw_findings = list(
        database.scalars(
            select(Finding)
            .where(
                Finding.scan_id.in_(scan_ids)
            )
            .order_by(Finding.created_at.desc())
        )
    )

    findings_by_scan = defaultdict(list)

    for finding in raw_findings:
        findings_by_scan[
            finding.scan_id
        ].append(finding)

    rows = []

    for scan in scans:
        target = targets.get(
            scan.target_id
        )

        if target is None:
            continue

        scan_findings = findings_by_scan.get(
            scan.id,
            [],
        )

        if not scan_findings:
            continue

        members_by_issue = defaultdict(list)

        for finding in scan_findings:
            members_by_issue[
                build_issue_key(finding)
            ].append(finding)

        grouped_findings = aggregate_findings(
            scan_findings
        )

        for grouped in grouped_findings:
            members = members_by_issue[
                grouped["issue_key"]
            ]

            workflow = members[0]

            rows.append(
                {
                    **grouped,
                    "primary_finding_id": getattr(
                        workflow,
                        "id",
                        None,
                    ),
                    "lifecycle_state": getattr(
                        workflow,
                        "lifecycle_state",
                        "NEW",
                    ),
                    "observation_state": getattr(
                        workflow,
                        "observation_state",
                        "NEW",
                    ),
                    "assignee_user_id": getattr(
                        workflow,
                        "assignee_user_id",
                        None,
                    ),
                    "remediation_owner_user_id": getattr(
                        workflow,
                        "remediation_owner_user_id",
                        None,
                    ),
                    "disposition": getattr(
                        workflow,
                        "disposition",
                        None,
                    ),
                    "disposition_reason": getattr(
                        workflow,
                        "disposition_reason",
                        None,
                    ),
                    "disposition_set_by_user_id": getattr(
                        workflow,
                        "disposition_set_by_user_id",
                        None,
                    ),
                    "disposition_set_at": getattr(
                        workflow,
                        "disposition_set_at",
                        None,
                    ),
                    "duplicate_of_finding_id": getattr(
                        workflow,
                        "duplicate_of_finding_id",
                        None,
                    ),
                    "id": workspace_finding_id(
                        scan.id,
                        grouped["issue_key"],
                    ),
                    "target_id": target.id,
                    "target_hostname": target.hostname,
                    "target_url": target.normalized_url,
                    "scan_id": scan.id,
                    "scan_status": scan.status,
                    "scan_created_at": scan.created_at,
                    "scan_completed_at": scan.completed_at,
                    "last_observed_at": max(
                        item.created_at
                        for item in members
                    ),
                }
            )

    rows.sort(
        key=lambda item: item[
            "last_observed_at"
        ],
        reverse=True,
    )

    return rows


def filter_workspace_rows(
    rows: list[dict[str, Any]],
    *,
    severity: str | None = None,
    confidence: str | None = None,
    target_id: UUID | None = None,
    scan_id: UUID | None = None,
    tool: str | None = None,
    classification: str | None = None,
    lifecycle_state: str | None = None,
    observation_state: str | None = None,
    disposition: str | None = None,
    assignee_user_id: UUID | None = None,
    remediation_owner_user_id: UUID | None = None,
    q: str | None = None,
) -> list[dict[str, Any]]:
    filtered = list(rows)

    if severity:
        normalized_severity = severity.strip().lower()

        filtered = [
            row
            for row in filtered
            if str(
                row.get(
                    "severity",
                    "",
                )
            ).strip().lower()
            == normalized_severity
        ]

    if confidence:
        normalized_confidence = confidence.strip().lower()

        filtered = [
            row
            for row in filtered
            if str(
                row.get(
                    "confidence",
                    "",
                )
            ).strip().lower()
            == normalized_confidence
        ]

    if target_id is not None:
        filtered = [
            row
            for row in filtered
            if row.get("target_id") == target_id
        ]

    if scan_id is not None:
        filtered = [
            row
            for row in filtered
            if row.get("scan_id") == scan_id
        ]

    if tool:
        normalized_tool = tool.strip().lower()

        filtered = [
            row
            for row in filtered
            if any(
                str(
                    source.get(
                        "tool_name",
                        "",
                    )
                ).strip().lower()
                == normalized_tool
                for source in row.get(
                    "sources",
                    [],
                )
            )
        ]

    if classification:
        normalized_classification = (
            classification.strip().lower()
        )

        filtered = [
            row
            for row in filtered
            if str(
                row.get(
                    "classification",
                    "",
                )
            ).strip().lower()
            == normalized_classification
        ]

    for key, value in (
        (
            "lifecycle_state",
            lifecycle_state,
        ),
        (
            "observation_state",
            observation_state,
        ),
        (
            "disposition",
            disposition,
        ),
    ):
        if value:
            normalized = (
                value
                .strip()
                .upper()
            )

            filtered = [
                row
                for row in filtered
                if str(
                    row.get(
                        key,
                        "",
                    )
                    or ""
                )
                .strip()
                .upper()
                == normalized
            ]

    for key, value in (
        (
            "assignee_user_id",
            assignee_user_id,
        ),
        (
            "remediation_owner_user_id",
            remediation_owner_user_id,
        ),
    ):
        if value is not None:
            filtered = [
                row
                for row in filtered
                if str(
                    row.get(
                        key,
                        "",
                    )
                    or ""
                )
                == str(
                    value
                )
            ]

    if q:
        normalized_query = q.strip().lower()

        if normalized_query:
            search_fields = (
                "title",
                "description",
                "cwe_id",
                "target_hostname",
                "issue_key",
            )

            filtered = [
                row
                for row in filtered
                if any(
                    normalized_query
                    in str(
                        row.get(field) or ""
                    ).lower()
                    for field in search_fields
                )
            ]

    return filtered


def build_workspace_detail(
    database: Session,
    organization_id: UUID,
    finding_id: str,
) -> dict[str, Any] | None:
    try:
        scan_id, issue_key = parse_workspace_finding_id(
            finding_id
        )
    except ValueError:
        return None

    workspace_rows = build_workspace_rows(
        database,
        organization_id,
    )

    summary = next(
        (
            row
            for row in workspace_rows
            if row["id"] == finding_id
        ),
        None,
    )

    if summary is None:
        return None

    raw_findings = list(
        database.scalars(
            select(Finding)
            .where(
                Finding.scan_id == scan_id
            )
            .order_by(Finding.created_at.desc())
        )
    )

    matching_occurrences = [
        finding
        for finding in raw_findings
        if build_issue_key(finding) == issue_key
    ]

    occurrences = [
        {
            "id": finding.id,
            "tool_name": finding.tool_name,
            "external_finding_id":
                finding.external_finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "affected_url": finding.affected_url,
            "affected_port": finding.affected_port,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "cwe_id": finding.cwe_id,
            "cvss_score": finding.cvss_score,
            "status": finding.status,
            "created_at": finding.created_at,
        }
        for finding in matching_occurrences
    ]

    return {
        **summary,
        "occurrences": occurrences,
    }
