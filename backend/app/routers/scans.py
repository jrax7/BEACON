from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_run import ScanToolRun
from app.models.user import User
from app.organizations.context import resolve_organization_context
from app.organizations.rbac import Permission, require_permission
from app.schemas.scans import (
    FindingResponse,
    GroupedFindingsPage,
    ScanBulkActionRequest,
    ScanBulkActionResponse,
    ScanBulkDeleteResponse,
    ScanCreate,
    ScanDeleteResponse,
    ScanResponse,
    ScanSummaryResponse,
    ScanTelemetryResponse,
)
from app.security.demo import (
    ensure_demo_active_scan_allowed,
    ensure_demo_mutation_allowed,
    ensure_demo_scan_level_allowed,
    ensure_demo_target_allowed,
    is_demo_user,
)
from app.security.targets import (
    TargetValidationError,
    normalize_target_url,
    validate_target_destination,
)
from app.services.finding_aggregation import (
    aggregate_findings,
    build_summary,
)
from app.services.scan_lifecycle import cleanup_scan_artifacts
from app.tasks import run_basic_scan


router = APIRouter(
    prefix="/api/v1/scans",
    tags=["Scans"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


ACTIVE_SCAN_STATUSES = {
    "pending",
    "verifying",
    "queued",
    "running",
    "processing",
    "cancelling",
}

ARCHIVABLE_SCAN_STATUSES = {
    "completed",
    "failed",
}


def get_owned_scan(
    scan_id: UUID,
    current_user: User,
    database: Session,
) -> Scan:
    """Return a scan only when it belongs to the current user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_READ,
    )

    scan = database.scalar(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == context.organization.id,
        )
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return scan


def get_owned_scans(
    scan_ids: list[UUID],
    current_user: User,
    database: Session,
) -> list[Scan]:
    """Return a bounded set of scans only when all are owned."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_READ,
    )

    unique_ids = list(dict.fromkeys(scan_ids))

    scans = list(
        database.scalars(
            select(Scan).where(
                Scan.id.in_(unique_ids),
                Scan.organization_id == context.organization.id,
            )
        ).all()
    )

    by_id = {scan.id: scan for scan in scans}

    if len(by_id) != len(unique_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more scans were not found.",
        )

    return [by_id[scan_id] for scan_id in unique_ids]


def ensure_archivable(scan: Scan) -> None:
    """Reject lifecycle changes for scans that are still active."""

    if scan.status not in ARCHIVABLE_SCAN_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Only completed or failed scans can be archived. "
                "Active assessments must finish first."
            ),
        )


def ensure_deletable(scan: Scan) -> None:
    """Require an archived terminal scan before permanent deletion."""

    ensure_archivable(scan)

    if scan.archived_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The scan must be archived before it can be "
                "permanently deleted."
            ),
        )


def get_all_scan_findings(
    scan_id: UUID,
    database: Session,
) -> list[Finding]:
    """Load all raw finding instances for aggregation."""

    findings = database.scalars(
        select(Finding)
        .where(
            Finding.scan_id == scan_id,
        )
        .order_by(
            Finding.created_at.asc(),
        )
    ).all()

    return list(findings)



TOOL_LABELS = {
    "nmap": "Nmap network discovery",
    "zap": "OWASP ZAP passive analysis",
    "nikto": "Nikto web server analysis",
}


def tool_display_name(
    tool_name: str,
) -> str:
    """Return a user-facing scanner name."""

    return TOOL_LABELS.get(
        tool_name,
        tool_name,
    )


def runtime_seconds(
    started_at: datetime | None,
    completed_at: datetime | None,
) -> float | None:
    """Return scanner runtime in seconds."""

    if started_at is None:
        return None

    end = (
        completed_at
        or datetime.now(timezone.utc)
    )

    return round(
        max(
            0.0,
            (
                end - started_at
            ).total_seconds(),
        ),
        3,
    )


def determine_active_stage(
    scan: Scan,
    tool_runs: list[ScanToolRun],
) -> tuple[str, str]:
    """Derive the truthful workflow stage from persisted state."""

    running_tool = next(
        (
            run
            for run in tool_runs
            if run.status == "running"
        ),
        None,
    )

    if running_tool is not None:
        labels = {
            "nmap": (
                "network_discovery",
                "Discovering network services",
            ),
            "zap": (
                "passive_web_analysis",
                "Running passive web analysis",
            ),
            "nikto": (
                "web_server_analysis",
                "Assessing the web server",
            ),
        }

        return labels.get(
            running_tool.tool_name,
            (
                "scanner_running",
                f"Running {running_tool.tool_name}",
            ),
        )

    if scan.status == "cancelling":
        return (
            "cancelling",
            "Cancelling assessment",
        )

    if scan.status == "cancelled":
        return (
            "cancelled",
            "Assessment cancelled",
        )

    if scan.status == "failed":
        return (
            "failed",
            "Assessment failed",
        )

    if scan.status == "completed":
        return (
            "completed",
            "Assessment completed",
        )

    if scan.status == "queued":
        return (
            "queued",
            "Waiting for scanner worker",
        )

    if tool_runs:
        return (
            "finalizing",
            "Processing and finalizing results",
        )

    return (
        "preparing",
        "Preparing assessment",
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(
    request: ScanCreate,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Scan:
    """Create and queue a scan for a verified target."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_CREATE,
    )

    target = database.scalar(
        select(Target).where(
            Target.id == request.target_id,
            Target.organization_id == context.organization.id,
        )
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    ensure_demo_target_allowed(
        current_user,
        target,
    )

    ensure_demo_scan_level_allowed(
        current_user,
        request.scan_level,
    )

    now = datetime.now(timezone.utc)

    if target.verification_status != "verified":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The target must be ownership-verified "
                "before scanning."
            ),
        )

    if (
        target.verification_expires_at is None
        or target.verification_expires_at <= now
    ):
        target.verification_status = "expired"
        database.commit()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The target ownership verification "
                "has expired."
            ),
        )

    try:
        normalized_target = normalize_target_url(
            target.normalized_url
        )

        validate_target_destination(
            normalized_target
        )
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    active_scan_query = select(Scan).where(
        Scan.organization_id == context.organization.id,
        Scan.status.in_(ACTIVE_SCAN_STATUSES),
    )

    if not is_demo_user(current_user):
        active_scan_query = active_scan_query.where(
            Scan.target_id == target.id,
        )

    active_scan = database.scalar(
        active_scan_query
    )

    ensure_demo_active_scan_allowed(
        current_user,
        active_scan,
    )

    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This target already has an active scan."
            ),
        )

    scan = Scan(
        organization_id=context.organization.id,
        user_id=current_user.id,
        target_id=target.id,
        scan_level=request.scan_level,
        status="queued",
        progress=0,
    )

    database.add(scan)
    database.flush()

    database.add(
        AuditLog(
            organization_id=context.organization.id,
            user_id=current_user.id,
            target_id=target.id,
            scan_id=scan.id,
            action="scan.created",
            details={
                "scan_level": request.scan_level,
            },
        )
    )

    database.commit()
    database.refresh(scan)

    try:
        task = run_basic_scan.delay(
            str(scan.id)
        )
    except Exception as exc:
        scan.status = "failed"
        scan.progress = 100
        scan.failure_reason = (
            "The scan could not be submitted "
            "to the task queue."
        )
        scan.completed_at = datetime.now(
            timezone.utc
        )

        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=target.id,
                scan_id=scan.id,
                action="scan.failed",
                details={
                    "reason": str(exc)[:1000],
                },
            )
        )

        database.commit()

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is currently unavailable.",
        ) from exc

    scan.celery_task_id = task.id
    database.commit()
    database.refresh(scan)

    return scan


@router.get(
    "",
    response_model=list[ScanResponse],
)
def list_scans(
    current_user: CurrentUser,
    database: DatabaseSession,
    archived: Annotated[
        Literal["active", "archived", "all"],
        Query(),
    ] = "active",
) -> list[Scan]:
    """List current, archived, or all scans owned by the user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_READ,
    )

    query = select(Scan).where(
        Scan.organization_id == context.organization.id,
    )

    if archived == "active":
        query = query.where(
            Scan.archived_at.is_(None),
        )
    elif archived == "archived":
        query = query.where(
            Scan.archived_at.is_not(None),
        )

    scans = database.scalars(
        query.order_by(
            Scan.created_at.desc(),
        )
    ).all()

    return list(scans)


@router.post(
    "/bulk/archive",
    response_model=ScanBulkActionResponse,
)
def bulk_archive_scans(
    request: ScanBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ScanBulkActionResponse:
    """Archive up to 100 completed or failed scans atomically."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scans = get_owned_scans(
        request.scan_ids,
        current_user,
        database,
    )

    for scan in scans:
        ensure_archivable(scan)

    now = datetime.now(timezone.utc)
    affected_ids: list[UUID] = []

    for scan in scans:
        if scan.archived_at is not None:
            continue

        scan.archived_at = now
        affected_ids.append(scan.id)
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.archived",
                details={
                    "status": scan.status,
                    "bulk": True,
                },
            )
        )

    database.commit()

    return ScanBulkActionResponse(
        action="archive",
        affected_count=len(affected_ids),
        affected_scan_ids=affected_ids,
    )


@router.post(
    "/bulk/restore",
    response_model=ScanBulkActionResponse,
)
def bulk_restore_scans(
    request: ScanBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ScanBulkActionResponse:
    """Restore up to 100 archived terminal scans atomically."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scans = get_owned_scans(
        request.scan_ids,
        current_user,
        database,
    )

    for scan in scans:
        ensure_archivable(scan)

    affected_ids: list[UUID] = []

    for scan in scans:
        if scan.archived_at is None:
            continue

        archived_at = scan.archived_at
        scan.archived_at = None
        affected_ids.append(scan.id)
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.restored",
                details={
                    "archived_at": archived_at.isoformat(),
                    "bulk": True,
                },
            )
        )

    database.commit()

    return ScanBulkActionResponse(
        action="restore",
        affected_count=len(affected_ids),
        affected_scan_ids=affected_ids,
    )


@router.post(
    "/{scan_id}/archive",
    response_model=ScanResponse,
)
def archive_scan(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Scan:
    """Hide one terminal scan from normal history without deleting it."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )
    ensure_archivable(scan)

    if scan.archived_at is None:
        scan.archived_at = datetime.now(timezone.utc)
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.archived",
                details={
                    "status": scan.status,
                },
            )
        )
        database.commit()
        database.refresh(scan)

    return scan


@router.post(
    "/{scan_id}/restore",
    response_model=ScanResponse,
)
def restore_scan(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Scan:
    """Restore one archived scan to normal assessment history."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )
    ensure_archivable(scan)

    if scan.archived_at is not None:
        archived_at = scan.archived_at
        scan.archived_at = None
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.restored",
                details={
                    "archived_at": archived_at.isoformat(),
                },
            )
        )
        database.commit()
        database.refresh(scan)

    return scan


def delete_archived_scans(
    scans: list[Scan],
    current_user: User,
    database: Session,
) -> tuple[list[UUID], int, list[str]]:
    """Delete archived scans from PostgreSQL, then clean their files."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_DELETE,
    )

    for scan in scans:
        ensure_deletable(scan)

    scan_ids = [scan.id for scan in scans]
    report_counts = dict(
        database.execute(
            select(
                Report.scan_id,
                func.count(Report.id),
            )
            .where(
                Report.scan_id.in_(scan_ids),
            )
            .group_by(Report.scan_id)
        ).all()
    )

    total_reports = sum(
        int(report_counts.get(scan.id, 0))
        for scan in scans
    )

    for scan in scans:
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.deleted",
                details={
                    "deleted_scan_id": str(scan.id),
                    "scan_level": scan.scan_level,
                    "original_status": scan.status,
                    "archived_at": (
                        scan.archived_at.isoformat()
                        if scan.archived_at
                        else None
                    ),
                    "report_count": int(
                        report_counts.get(scan.id, 0)
                    ),
                },
            )
        )

    database.flush()

    for scan in scans:
        database.delete(scan)

    database.commit()

    cleanup_warnings: list[str] = []

    for scan_id in scan_ids:
        for warning in cleanup_scan_artifacts(scan_id):
            cleanup_warnings.append(
                f"{scan_id}: {warning}"
            )

    if cleanup_warnings:
        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                action="scan.artifact_cleanup_warning",
                details={
                    "deleted_scan_ids": [
                        str(scan_id) for scan_id in scan_ids
                    ],
                    "warnings": cleanup_warnings[:100],
                },
            )
        )
        database.commit()

    return scan_ids, total_reports, cleanup_warnings


@router.delete(
    "/{scan_id}",
    response_model=ScanDeleteResponse,
)
def delete_scan(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ScanDeleteResponse:
    """Permanently delete one archived scan and its stored artifacts."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_DELETE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )

    deleted_ids, report_count, warnings = delete_archived_scans(
        [scan],
        current_user,
        database,
    )

    return ScanDeleteResponse(
        deleted_scan_id=deleted_ids[0],
        deleted_report_count=report_count,
        cleanup_warnings=warnings,
    )


@router.post(
    "/bulk/delete",
    response_model=ScanBulkDeleteResponse,
)
def bulk_delete_scans(
    request: ScanBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ScanBulkDeleteResponse:
    """Permanently delete up to 100 archived scans and artifacts."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_DELETE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    scans = get_owned_scans(
        request.scan_ids,
        current_user,
        database,
    )

    deleted_ids, report_count, warnings = delete_archived_scans(
        scans,
        current_user,
        database,
    )

    return ScanBulkDeleteResponse(
        affected_count=len(deleted_ids),
        affected_scan_ids=deleted_ids,
        deleted_report_count=report_count,
        cleanup_warnings=warnings,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def read_scan(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Scan:
    """Return one scan belonging to the current user."""

    return get_owned_scan(
        scan_id,
        current_user,
        database,
    )


@router.get(
    "/{scan_id}/summary",
    response_model=ScanSummaryResponse,
)
def read_scan_summary(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> dict:
    """Return grouped counts and top issues for one scan."""

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )

    findings = get_all_scan_findings(
        scan.id,
        database,
    )

    summary = build_summary(findings)

    return {
        "scan_id": scan.id,
        "scan_status": scan.status,
        **summary,
    }


@router.get(
    "/{scan_id}/issues",
    response_model=GroupedFindingsPage,
)
def list_grouped_issues(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
    severity: Annotated[
        str | None,
        Query(
            pattern=(
                "^(critical|high|medium|low|informational)$"
            ),
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100),
    ] = 25,
    offset: Annotated[
        int,
        Query(ge=0),
    ] = 0,
) -> dict:
    """Return paginated actionable issue groups."""

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )

    findings = get_all_scan_findings(
        scan.id,
        database,
    )

    grouped_issues = aggregate_findings(
        findings
    )

    if severity is not None:
        grouped_issues = [
            issue
            for issue in grouped_issues
            if issue["severity"] == severity
        ]

    total_groups = len(grouped_issues)

    items = grouped_issues[
        offset:offset + limit
    ]

    return {
        "scan_id": scan.id,
        "total_groups": total_groups,
        "offset": offset,
        "limit": limit,
        "items": items,
    }


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
)
def list_raw_scan_findings(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
    limit: Annotated[
        int,
        Query(ge=1, le=500),
    ] = 100,
    offset: Annotated[
        int,
        Query(ge=0),
    ] = 0,
) -> list[Finding]:
    """Return paginated raw finding evidence."""

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )

    findings = database.scalars(
        select(Finding)
        .where(
            Finding.scan_id == scan.id,
        )
        .order_by(
            Finding.created_at.asc(),
        )
        .offset(offset)
        .limit(limit)
    ).all()

    return list(findings)


@router.get(
    "/{scan_id}/telemetry",
    response_model=ScanTelemetryResponse,
)
def read_scan_telemetry(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> dict:
    """Return safe live telemetry for one owned scan."""

    scan = get_owned_scan(
        scan_id,
        current_user,
        database,
    )

    tool_runs = list(
        database.scalars(
            select(ScanToolRun)
            .where(
                ScanToolRun.scan_id
                == scan.id,
            )
            .order_by(
                ScanToolRun.created_at.asc(),
            )
        ).all()
    )

    finding_rows = database.execute(
        select(
            Finding.tool_name,
            func.count(Finding.id),
        )
        .where(
            Finding.scan_id == scan.id,
        )
        .group_by(
            Finding.tool_name,
        )
    ).all()

    finding_counts = {
        str(tool_name): int(count)
        for tool_name, count
        in finding_rows
    }

    audit_rows = list(
        database.scalars(
            select(AuditLog)
            .where(
                AuditLog.scan_id
                == scan.id,
            )
            .order_by(
                AuditLog.created_at.asc(),
            )
        ).all()
    )

    warning_by_tool: dict[str, str] = {}
    progress_by_tool: dict[str, dict] = {}
    completion_by_tool: dict[str, dict] = {}

    for audit in audit_rows:
        details = (
            audit.details
            if isinstance(
                audit.details,
                dict,
            )
            else {}
        )

        tool_name = details.get(
            "tool"
        )

        if not isinstance(
            tool_name,
            str,
        ):
            continue

        if audit.action == "scan.tool_progress":
            progress_by_tool[tool_name] = details

        if audit.action == "scan.tool_completed":
            completion_by_tool[tool_name] = details

        if tool_name == "nikto":
            nikto_warnings: list[str] = []

            if details.get(
                "reached_max_time"
            ):
                nikto_warnings.append(
                    "Nikto reached the configured maximum "
                    "scan time. Results may be partial."
                )

            if details.get(
                "soft_404_detected"
            ):
                nikto_warnings.append(
                    "The target returned the same HTTP 200 "
                    "body for a random nonexistent path. "
                    "Path-based Nikto observations may be "
                    "noisy on SPA/soft-404 applications and "
                    "require manual validation."
                )

            if nikto_warnings:
                warning_by_tool[tool_name] = " ".join(
                    nikto_warnings
                )

    tool_payload = []
    has_warning = False

    for run in tool_runs:
        warning = warning_by_tool.get(
            run.tool_name
        )

        if (
            run.status == "skipped"
            and warning is None
        ):
            warning = (
                run.error_message
                or (
                    f"{tool_display_name(run.tool_name)} "
                    "was skipped."
                )
            )

        if warning is not None:
            has_warning = True

        if run.status == "failed":
            has_warning = True

        progress_details = progress_by_tool.get(
            run.tool_name,
            {},
        )
        completion_details = completion_by_tool.get(
            run.tool_name,
            {},
        )

        tool_payload.append(
            {
                "id": run.id,
                "tool_name":
                    run.tool_name,
                "tool_version":
                    run.tool_version,
                "status":
                    run.status,
                "finding_count":
                    finding_counts.get(
                        run.tool_name,
                        0,
                    ),
                "exit_code":
                    run.exit_code,
                "error_message":
                    run.error_message,
                "warning":
                    warning,
                "started_at":
                    run.started_at,
                "completed_at":
                    run.completed_at,
                "duration_seconds":
                    runtime_seconds(
                        run.started_at,
                        run.completed_at,
                    ),
                "progress_percent":
                    progress_details.get(
                        "percent"
                    ),
                "progress_message":
                    progress_details.get(
                        "message"
                    ),
                "completed_requests": (
                    completion_details.get(
                        "completed_requests"
                    )
                    or progress_details.get(
                        "completed_requests"
                    )
                ),
                "estimated_total_requests": (
                    progress_details.get(
                        "estimated_total_requests"
                    )
                ),
                "request_error_count": (
                    completion_details.get(
                        "request_error_count"
                    )
                ),
            }
        )

    if scan.status == "failed":
        outcome = "failed"

    elif scan.status == "completed":
        outcome = (
            "completed_with_warnings"
            if has_warning
            else "completed"
        )

    elif scan.status == "queued":
        outcome = "queued"

    else:
        outcome = "running"

    events: list[dict] = []

    events.append(
        {
            "timestamp":
                scan.created_at,
            "level": "info",
            "component": "scan",
            "event": "scan.queued",
            "message":
                "Assessment queued.",
        }
    )

    if scan.started_at is not None:
        events.append(
            {
                "timestamp":
                    scan.started_at,
                "level": "info",
                "component": "scan",
                "event":
                    "scan.started",
                "message":
                    "Assessment worker started.",
            }
        )

    for run in tool_runs:
        display_name = (
            tool_display_name(
                run.tool_name
            )
        )

        if run.started_at is not None:
            events.append(
                {
                    "timestamp":
                        run.started_at,
                    "level": "info",
                    "component":
                        run.tool_name,
                    "event":
                        "tool.started",
                    "message":
                        f"{display_name} started.",
                }
            )

        if run.completed_at is None:
            continue

        warning = warning_by_tool.get(
            run.tool_name
        )

        count = finding_counts.get(
            run.tool_name,
            0,
        )

        if run.status == "failed":
            level = "error"

            message = (
                f"{display_name} failed."
            )

        elif run.status == "skipped":
            level = "warning"

            message = (
                f"{display_name} was skipped."
            )

        elif warning is not None:
            level = "warning"

            message = (
                f"{display_name} completed "
                f"with {count} finding "
                "instances and a warning."
            )

        else:
            level = "success"

            message = (
                f"{display_name} completed "
                f"with {count} finding "
                "instances."
            )

        events.append(
            {
                "timestamp":
                    run.completed_at,
                "level":
                    level,
                "component":
                    run.tool_name,
                "event":
                    f"tool.{run.status}",
                "message":
                    message,
            }
        )

    for audit in audit_rows:
        if audit.action != "scan.tool_progress":
            continue

        details = (
            audit.details
            if isinstance(
                audit.details,
                dict,
            )
            else {}
        )

        tool_name = details.get("tool")
        completed = details.get(
            "completed_requests"
        )
        percent = details.get("percent")

        if (
            not isinstance(tool_name, str)
            or not isinstance(completed, int)
        ):
            continue

        percent_text = (
            f" (~{percent}% complete)"
            if isinstance(percent, int)
            else ""
        )

        events.append(
            {
                "timestamp":
                    audit.created_at,
                "level": "info",
                "component": tool_name,
                "event":
                    "tool.progress",
                "message": (
                    f"{tool_display_name(tool_name)} "
                    f"completed {completed:,} requests"
                    f"{percent_text}."
                ),
            }
        )

    if scan.completed_at is not None:
        if scan.status == "failed":
            final_level = "error"
            final_message = (
                "Assessment failed."
            )

        elif has_warning:
            final_level = "warning"
            final_message = (
                "Assessment completed "
                "with warnings."
            )

        else:
            final_level = "success"
            final_message = (
                "Assessment completed "
                "successfully."
            )

        events.append(
            {
                "timestamp":
                    scan.completed_at,
                "level":
                    final_level,
                "component": "scan",
                "event":
                    f"scan.{scan.status}",
                "message":
                    final_message,
            }
        )

    events.sort(
        key=lambda item:
            item["timestamp"]
    )

    stage, stage_label = (
        determine_active_stage(
            scan,
            tool_runs,
        )
    )

    return {
        "scan_id":
            scan.id,
        "scan_status":
            scan.status,
        "outcome":
            outcome,
        "workflow_progress":
            scan.progress,
        "active_stage":
            stage,
        "active_stage_label":
            stage_label,
        "tool_runs":
            tool_payload,
        "events":
            events,
    }
