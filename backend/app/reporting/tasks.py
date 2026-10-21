from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_run import ScanToolRun
from app.models.user import User
from app.reporting.generator import (
    GeneratedReportArtifact,
    cleanup_report_artifacts,
    generate_report_artifacts,
)


@celery_app.task(
    name="beacon.generate_scan_report"
)
def generate_scan_report(
    scan_id: str,
    formats: list[str],
) -> dict:
    """Generate report files for a completed scan."""

    database = SessionLocal()
    scan_uuid = UUID(scan_id)

    artifacts: list[
        GeneratedReportArtifact
    ] = []

    scan: Scan | None = None

    try:
        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The requested scan does not exist."
            )

        if scan.status != "completed":
            raise RuntimeError(
                "Reports can only be generated "
                "for completed scans."
            )

        if scan.archived_at is not None:
            raise RuntimeError(
                "Archived scans must be restored before "
                "new reports can be generated."
            )

        target = database.get(
            Target,
            scan.target_id,
        )

        if target is None:
            raise RuntimeError(
                "The scan target no longer exists."
            )

        if (
            scan.organization_id
            != target.organization_id
        ):
            raise RuntimeError(
                "The scan and target belong to "
                "different organizations."
            )

        user = database.get(
            User,
            scan.user_id,
        )

        if user is None:
            raise RuntimeError(
                "The scan owner no longer exists."
            )

        findings = list(
            database.scalars(
                select(Finding)
                .where(
                    Finding.scan_id == scan.id,
                )
                .order_by(
                    Finding.created_at.asc(),
                )
            ).all()
        )

        tool_runs = list(
            database.scalars(
                select(ScanToolRun)
                .where(
                    ScanToolRun.scan_id == scan.id,
                )
                .order_by(
                    ScanToolRun.created_at.asc(),
                )
            ).all()
        )

        artifacts = generate_report_artifacts(
            scan=scan,
            target=target,
            user=user,
            findings=findings,
            tool_runs=tool_runs,
            formats=formats,
        )

        database.refresh(scan)

        if scan.archived_at is not None:
            raise RuntimeError(
                "The scan was archived while report generation "
                "was in progress."
            )

        reports: list[Report] = []

        for artifact in artifacts:
            report = Report(
                scan_id=scan.id,
                format=artifact.format,
                file_path=artifact.relative_path,
                checksum_sha256=(
                    artifact.checksum_sha256
                ),
                generated_at=artifact.generated_at,
            )

            database.add(report)
            reports.append(report)

        database.flush()

        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=scan.user_id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="report.generated",
                details={
                    "formats": [
                        artifact.format
                        for artifact in artifacts
                    ],
                    "report_ids": [
                        str(report.id)
                        for report in reports
                    ],
                    "total_size_bytes": sum(
                        artifact.size_bytes
                        for artifact in artifacts
                    ),
                },
            )
        )

        database.commit()

        return {
            "scan_id": str(scan.id),
            "status": "completed",
            "reports": [
                {
                    "id": str(report.id),
                    "format": report.format,
                    "checksum_sha256":
                        report.checksum_sha256,
                }
                for report in reports
            ],
        }

    except Exception as exc:
        database.rollback()

        cleanup_report_artifacts(
            artifacts
        )

        if scan is None:
            scan = database.get(
                Scan,
                scan_uuid,
            )

        if scan is not None:
            database.add(
                AuditLog(
                    organization_id=scan.organization_id,
                    user_id=scan.user_id,
                    target_id=scan.target_id,
                    scan_id=scan.id,
                    action="report.generation_failed",
                    details={
                        "reason": str(exc)[:1000],
                        "formats": formats,
                    },
                )
            )

            database.commit()

        raise

    finally:
        database.close()
