from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Input for creating a BEACON security scan."""

    target_id: UUID
    scan_level: Literal["basic"] = "basic"


class ScanResponse(BaseModel):
    """Safe scan information returned by the API."""

    id: UUID
    target_id: UUID
    scan_level: str
    status: str
    progress: int
    started_at: datetime | None
    completed_at: datetime | None
    archived_at: datetime | None
    failure_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class ScanBulkActionRequest(BaseModel):
    """A bounded set of owned scans for one lifecycle action."""

    scan_ids: list[UUID] = Field(
        min_length=1,
        max_length=100,
    )


class ScanBulkActionResponse(BaseModel):
    """Result of a bulk archive or restore operation."""

    action: Literal["archive", "restore"]
    affected_count: int
    affected_scan_ids: list[UUID]


class ScanDeleteResponse(BaseModel):
    """Result of permanent deletion and artifact cleanup."""

    deleted_scan_id: UUID
    deleted_report_count: int
    cleanup_warnings: list[str]


class ScanBulkDeleteResponse(BaseModel):
    """Result of permanently deleting archived scans."""

    action: Literal["delete"] = "delete"
    affected_count: int
    affected_scan_ids: list[UUID]
    deleted_report_count: int
    cleanup_warnings: list[str]


class FindingResponse(BaseModel):
    """One raw security-finding instance."""

    id: UUID
    scan_id: UUID
    tool_name: str
    external_finding_id: str | None
    title: str
    description: str | None
    severity: str
    confidence: str | None
    affected_url: str | None
    affected_port: int | None
    evidence: dict | None
    remediation: str | None
    cwe_id: str | None
    cvss_score: Decimal | None
    fingerprint: str | None
    status: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class GroupedFindingSourceResponse(BaseModel):
    """Scanner provenance contributing to one BEACON issue."""

    tool_name: str
    external_finding_ids: list[str]
    occurrence_count: int


class GroupedFindingResponse(BaseModel):
    """One correlated BEACON issue backed by raw observations."""

    issue_key: str
    classification: Literal[
        "security_issue",
        "attack_surface",
        "observation",
        "limitation",
    ]
    tool_name: str
    external_finding_id: str | None
    title: str
    severity: str
    confidence: str | None
    cwe_id: str | None
    description: str | None
    remediation: str | None
    occurrence_count: int
    affected_url_count: int
    sample_affected_urls: list[str]
    source_count: int
    sources: list[GroupedFindingSourceResponse]
    requires_manual_validation: bool


class GroupedFindingsPage(BaseModel):
    """Paginated collection of grouped issues."""

    scan_id: UUID
    total_groups: int
    offset: int
    limit: int
    items: list[GroupedFindingResponse]


class ScanSummaryResponse(BaseModel):
    """Executive and technical summary for one scan."""

    scan_id: UUID
    scan_status: str
    total_finding_instances: int
    distinct_issues: int
    highest_severity: str
    instances_by_severity: dict[str, int]
    issues_by_severity: dict[str, int]

    security_issue_count: int
    attack_surface_count: int
    observation_count: int
    limitation_count: int

    highest_security_severity: str
    security_issues_by_severity: dict[str, int]

    top_issues: list[GroupedFindingResponse]


class ScanToolTelemetryResponse(BaseModel):
    """Safe runtime information for one scanner execution."""

    id: UUID
    tool_name: str
    tool_version: str | None
    status: str
    finding_count: int
    exit_code: int | None
    error_message: str | None
    warning: str | None
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    progress_percent: int | None = None
    progress_message: str | None = None
    completed_requests: int | None = None
    estimated_total_requests: int | None = None
    request_error_count: int | None = None


class ScanEventResponse(BaseModel):
    """One safe event shown in the live scan activity console."""

    timestamp: datetime
    level: Literal[
        "info",
        "success",
        "warning",
        "error",
    ]
    component: str
    event: str
    message: str


class ScanTelemetryResponse(BaseModel):
    """Current workflow and scanner telemetry for one scan."""

    scan_id: UUID
    scan_status: str

    outcome: Literal[
        "queued",
        "running",
        "completed",
        "completed_with_warnings",
        "failed",
    ]

    workflow_progress: int
    active_stage: str
    active_stage_label: str

    tool_runs: list[
        ScanToolTelemetryResponse
    ]

    events: list[
        ScanEventResponse
    ]
