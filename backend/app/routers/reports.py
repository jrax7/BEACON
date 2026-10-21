import re
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
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.audit_log import AuditLog
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.organizations.context import resolve_organization_context
from app.organizations.rbac import Permission, require_permission
from app.reporting.generator import (
    ReportGenerationError,
    resolve_report_path,
    sha256_file,
)
from app.reporting.tasks import generate_scan_report
from app.schemas.reports import (
    ReportBulkActionRequest,
    ReportBulkActionResponse,
    ReportBulkDeleteResponse,
    ReportDeleteResponse,
    ReportGenerateRequest,
    ReportGenerationResponse,
    ReportListItemResponse,
    ReportResponse,
)
from app.security.demo import ensure_demo_mutation_allowed
from app.services.report_lifecycle import cleanup_report_artifact


router = APIRouter(
    prefix="/api/v1",
    tags=["Reports"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


REPORT_ARCHIVE_FILTER = Literal[
    "active",
    "archived",
    "all",
]


def get_owned_scan(
    scan_id: UUID,
    current_user: User,
    database: Session,
) -> Scan:
    """Return a scan belonging to the active user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
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


def get_owned_report(
    report_id: UUID,
    current_user: User,
    database: Session,
) -> tuple[Report, Scan, Target]:
    """Return report metadata only to its scan owner."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )

    row = database.execute(
        select(
            Report,
            Scan,
            Target,
        )
        .join(
            Scan,
            Report.scan_id == Scan.id,
        )
        .join(
            Target,
            Scan.target_id == Target.id,
        )
        .where(
            Report.id == report_id,
            Scan.organization_id == context.organization.id,
        )
    ).one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found.",
        )

    report, scan, target = row
    return report, scan, target


def get_owned_reports(
    report_ids: list[UUID],
    current_user: User,
    database: Session,
) -> list[tuple[Report, Scan, Target]]:
    """Resolve an exact, bounded set of reports belonging to the user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )

    unique_ids = list(dict.fromkeys(report_ids))

    rows = database.execute(
        select(
            Report,
            Scan,
            Target,
        )
        .join(Scan, Report.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(
            Report.id.in_(unique_ids),
            Scan.organization_id == context.organization.id,
        )
    ).all()

    by_id = {
        report.id: (report, scan, target)
        for report, scan, target in rows
    }

    if len(by_id) != len(unique_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "One or more reports were not found or do not belong "
                "to the current user."
            ),
        )

    return [by_id[report_id] for report_id in unique_ids]


def report_response(
    report: Report,
) -> ReportResponse:
    """Convert a report record into safe API metadata."""

    return ReportResponse(
        id=report.id,
        scan_id=report.scan_id,
        format=report.format,
        checksum_sha256=report.checksum_sha256,
        archived_at=report.archived_at,
        generated_at=report.generated_at,
        created_at=report.created_at,
        download_url=(
            f"/api/v1/reports/"
            f"{report.id}/download"
        ),
    )


def report_list_item_response(
    report: Report,
    scan: Scan,
    target: Target,
) -> ReportListItemResponse:
    """Convert a joined report row into global-list metadata."""

    base = report_response(report)

    return ReportListItemResponse(
        **base.model_dump(),
        target_id=target.id,
        target_hostname=target.hostname,
        target_url=target.normalized_url,
        scan_level=scan.scan_level,
        scan_status=scan.status,
    )


def download_filename(
    target: Target,
    scan: Scan,
    report: Report,
) -> str:
    """Create a safe client-facing filename."""

    safe_hostname = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        target.hostname,
    ).strip(
        "-._"
    ) or "target"

    return (
        f"BEACON-{safe_hostname}-"
        f"{str(scan.id)[:8]}."
        f"{report.format}"
    )


def ensure_report_archived(report: Report) -> None:
    if report.archived_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "The report must be archived before it can be "
                "permanently deleted."
            ),
        )


def archive_report_rows(
    rows: list[tuple[Report, Scan, Target]],
    current_user: User,
    database: Session,
) -> list[UUID]:
    now = datetime.now(timezone.utc)
    affected: list[UUID] = []

    for report, scan, target in rows:
        if report.archived_at is not None:
            continue

        report.archived_at = now
        affected.append(report.id)
        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=current_user.id,
                target_id=target.id,
                scan_id=scan.id,
                action="report.archived",
                details={
                    "report_id": str(report.id),
                    "format": report.format,
                    "generated_at": report.generated_at.isoformat(),
                },
            )
        )

    database.commit()
    return affected


def restore_report_rows(
    rows: list[tuple[Report, Scan, Target]],
    current_user: User,
    database: Session,
) -> list[UUID]:
    affected: list[UUID] = []

    for report, scan, target in rows:
        if report.archived_at is None:
            continue

        archived_at = report.archived_at
        report.archived_at = None
        affected.append(report.id)
        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=current_user.id,
                target_id=target.id,
                scan_id=scan.id,
                action="report.restored",
                details={
                    "report_id": str(report.id),
                    "format": report.format,
                    "archived_at": archived_at.isoformat(),
                },
            )
        )

    database.commit()
    return affected


def delete_report_rows(
    rows: list[tuple[Report, Scan, Target]],
    current_user: User,
    database: Session,
) -> tuple[list[UUID], list[str]]:
    for report, _, _ in rows:
        ensure_report_archived(report)

    deleted_ids = [report.id for report, _, _ in rows]
    artifact_paths = [report.file_path for report, _, _ in rows]

    for report, scan, target in rows:
        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=current_user.id,
                target_id=target.id,
                scan_id=scan.id,
                action="report.deleted",
                details={
                    "deleted_report_id": str(report.id),
                    "format": report.format,
                    "generated_at": report.generated_at.isoformat(),
                    "archived_at": (
                        report.archived_at.isoformat()
                        if report.archived_at
                        else None
                    ),
                    "checksum_sha256": report.checksum_sha256,
                },
            )
        )
        database.delete(report)

    database.commit()

    cleanup_warnings: list[str] = []

    for report_id, relative_path in zip(deleted_ids, artifact_paths, strict=True):
        for warning in cleanup_report_artifact(relative_path):
            cleanup_warnings.append(f"{report_id}: {warning}")

    if cleanup_warnings:
        database.add(
            AuditLog(
                organization_id=(
                    rows[0][1].organization_id
                    if rows
                    else None
                ),
                user_id=current_user.id,
                action="report.artifact_cleanup_warning",
                details={
                    "deleted_report_ids": [str(value) for value in deleted_ids],
                    "warnings": cleanup_warnings[:100],
                },
            )
        )
        database.commit()

    return deleted_ids, cleanup_warnings


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportGenerationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_report_generation(
    scan_id: UUID,
    request: ReportGenerateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportGenerationResponse:
    """Queue HTML and/or PDF generation."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_GENERATE,
    )

    scan = get_owned_scan(scan_id, current_user, database)

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Reports can only be generated for completed scans.",
        )

    if scan.archived_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Archived scans must be restored before "
                "new reports can be generated."
            ),
        )

    try:
        task = generate_scan_report.delay(
            str(scan.id),
            list(request.formats),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The report-generation queue is currently unavailable.",
        ) from exc

    database.add(
        AuditLog(
            organization_id=scan.organization_id,
            user_id=current_user.id,
            target_id=scan.target_id,
            scan_id=scan.id,
            action="report.generation_requested",
            details={
                "task_id": task.id,
                "formats": list(request.formats),
            },
        )
    )
    database.commit()

    return ReportGenerationResponse(
        scan_id=scan.id,
        task_id=task.id,
        status="queued",
        requested_formats=list(request.formats),
    )


@router.get(
    "/reports",
    response_model=list[ReportListItemResponse],
)
def list_reports(
    current_user: CurrentUser,
    database: DatabaseSession,
    archived: Annotated[
        REPORT_ARCHIVE_FILTER,
        Query(
            description=(
                "Filter active, archived, or all "
                "owned report artifacts."
            )
        ),
    ] = "active",
) -> list[ReportListItemResponse]:
    """List owned reports with assessment and target context."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )

    statement = (
        select(
            Report,
            Scan,
            Target,
        )
        .join(
            Scan,
            Report.scan_id == Scan.id,
        )
        .join(
            Target,
            Scan.target_id == Target.id,
        )
        .where(
            Scan.organization_id == context.organization.id,
        )
    )

    if archived == "active":
        statement = statement.where(
            Report.archived_at.is_(None)
        )
    elif archived == "archived":
        statement = statement.where(
            Report.archived_at.is_not(None)
        )

    rows = database.execute(
        statement.order_by(
            Report.generated_at.desc()
        )
    ).all()

    return [
        report_list_item_response(
            report,
            scan,
            target,
        )
        for report, scan, target in rows
    ]


@router.get(
    "/scans/{scan_id}/reports",
    response_model=list[ReportResponse],
)
def list_scan_reports(
    scan_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
    archived: Annotated[
        REPORT_ARCHIVE_FILTER,
        Query(description="Filter active, archived, or all report artifacts."),
    ] = "active",
) -> list[ReportResponse]:
    """List generated reports for one scan by lifecycle state."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )

    scan = get_owned_scan(scan_id, current_user, database)

    statement = select(Report).where(Report.scan_id == scan.id)

    if archived == "active":
        statement = statement.where(Report.archived_at.is_(None))
    elif archived == "archived":
        statement = statement.where(Report.archived_at.is_not(None))

    reports = database.scalars(
        statement.order_by(Report.generated_at.desc())
    ).all()

    return [report_response(report) for report in reports]


@router.post(
    "/reports/bulk/archive",
    response_model=ReportBulkActionResponse,
)
def bulk_archive_reports(
    request: ReportBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportBulkActionResponse:


    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_LIFECYCLE,
    )
    ensure_demo_mutation_allowed(
        current_user,
    )
    rows = get_owned_reports(request.report_ids, current_user, database)
    affected = archive_report_rows(rows, current_user, database)
    return ReportBulkActionResponse(
        action="archive",
        affected_count=len(affected),
        affected_report_ids=affected,
    )


@router.post(
    "/reports/bulk/restore",
    response_model=ReportBulkActionResponse,
)
def bulk_restore_reports(
    request: ReportBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportBulkActionResponse:


    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_LIFECYCLE,
    )
    ensure_demo_mutation_allowed(
        current_user,
    )
    rows = get_owned_reports(request.report_ids, current_user, database)
    affected = restore_report_rows(rows, current_user, database)
    return ReportBulkActionResponse(
        action="restore",
        affected_count=len(affected),
        affected_report_ids=affected,
    )


@router.post(
    "/reports/bulk/delete",
    response_model=ReportBulkDeleteResponse,
)
def bulk_delete_reports(
    request: ReportBulkActionRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportBulkDeleteResponse:


    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_DELETE,
    )
    ensure_demo_mutation_allowed(
        current_user,
    )
    rows = get_owned_reports(request.report_ids, current_user, database)
    deleted, warnings = delete_report_rows(rows, current_user, database)
    return ReportBulkDeleteResponse(
        affected_count=len(deleted),
        affected_report_ids=deleted,
        cleanup_warnings=warnings,
    )


@router.post(
    "/reports/{report_id}/archive",
    response_model=ReportResponse,
)
def archive_report(
    report_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportResponse:
    """Archive one generated report without deleting its artifact."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    row = get_owned_report(report_id, current_user, database)
    archive_report_rows([row], current_user, database)
    report = database.get(Report, report_id)
    return report_response(report)


@router.post(
    "/reports/{report_id}/restore",
    response_model=ReportResponse,
)
def restore_report(
    report_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportResponse:
    """Restore one archived report to the active report list."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_LIFECYCLE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    row = get_owned_report(report_id, current_user, database)
    restore_report_rows([row], current_user, database)
    report = database.get(Report, report_id)
    return report_response(report)


@router.get(
    "/reports/{report_id}",
    response_model=ReportResponse,
)
def read_report(
    report_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportResponse:

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )
    report, _, _ = get_owned_report(report_id, current_user, database)
    return report_response(report)


@router.delete(
    "/reports/{report_id}",
    response_model=ReportDeleteResponse,
)
def delete_report(
    report_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> ReportDeleteResponse:
    """Permanently delete one archived report and its stored file."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_DELETE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    row = get_owned_report(report_id, current_user, database)
    deleted, warnings = delete_report_rows([row], current_user, database)
    return ReportDeleteResponse(
        deleted_report_id=deleted[0],
        cleanup_warnings=warnings,
    )


@router.get(
    "/reports/{report_id}/download",
    response_class=FileResponse,
)
def download_report(
    report_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FileResponse:
    """Validate and download an active or archived generated report."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.REPORT_READ,
    )

    report, scan, target = get_owned_report(report_id, current_user, database)

    try:
        report_path = resolve_report_path(report.file_path)
    except ReportGenerationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The stored report path is invalid.",
        ) from exc

    if not report_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                "The report database record exists, "
                "but its file is unavailable."
            ),
        )

    actual_checksum = sha256_file(report_path)

    if report.checksum_sha256 is None or actual_checksum != report.checksum_sha256:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The report failed its integrity check and cannot be downloaded."
            ),
        )

    media_types = {
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
    }
    media_type = media_types.get(report.format)

    if media_type is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The report format is unsupported.",
        )

    database.add(
        AuditLog(
            organization_id=scan.organization_id,
            user_id=current_user.id,
            target_id=target.id,
            scan_id=scan.id,
            action="report.downloaded",
            details={
                "report_id": str(report.id),
                "format": report.format,
                "archived": report.archived_at is not None,
                "checksum_sha256": actual_checksum,
            },
        )
    )
    database.commit()

    return FileResponse(
        path=report_path,
        media_type=media_type,
        filename=download_filename(target, scan, report),
        headers={"X-BEACON-SHA256": actual_checksum},
    )
