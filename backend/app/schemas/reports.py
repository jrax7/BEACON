from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)


ReportFormat = Literal["html", "pdf"]


class ReportGenerateRequest(BaseModel):
    """Requested formats for a completed scan report."""

    formats: list[ReportFormat] = Field(
        default_factory=lambda: [
            "html",
            "pdf",
        ],
        min_length=1,
        max_length=2,
    )

    @field_validator("formats")
    @classmethod
    def remove_duplicate_formats(
        cls,
        value: list[ReportFormat],
    ) -> list[ReportFormat]:
        return list(dict.fromkeys(value))


class ReportGenerationResponse(BaseModel):
    """Background report-generation job."""

    scan_id: UUID
    task_id: str
    status: str
    requested_formats: list[ReportFormat]


class ReportResponse(BaseModel):
    """Safe report metadata."""

    id: UUID
    scan_id: UUID
    format: str
    checksum_sha256: str | None
    archived_at: datetime | None
    generated_at: datetime
    created_at: datetime
    download_url: str


class ReportListItemResponse(ReportResponse):
    """Report metadata with assessment and target context."""

    target_id: UUID
    target_hostname: str
    target_url: str
    scan_level: str
    scan_status: str


class ReportListItemResponse(ReportResponse):
    """Report metadata with assessment and target context."""

    target_id: UUID
    target_hostname: str
    target_url: str
    scan_level: str
    scan_status: str


class ReportBulkActionRequest(BaseModel):
    """A bounded collection of owned reports for one lifecycle action."""

    report_ids: list[UUID] = Field(
        min_length=1,
        max_length=100,
    )


class ReportBulkActionResponse(BaseModel):
    """Result of a bulk archive or restore operation."""

    action: Literal["archive", "restore"]
    affected_count: int
    affected_report_ids: list[UUID]


class ReportDeleteResponse(BaseModel):
    """Result of permanently deleting one archived report."""

    deleted_report_id: UUID
    cleanup_warnings: list[str]


class ReportBulkDeleteResponse(BaseModel):
    """Result of permanently deleting archived reports."""

    action: Literal["delete"] = "delete"
    affected_count: int
    affected_report_ids: list[UUID]
    cleanup_warnings: list[str]
