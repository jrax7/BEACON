from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.assessment.types import (
    AssessmentMode,
    AssessmentProfileName,
)


class EnginePolicyMetadata(BaseModel):
    """Safe profile metadata for one scanner engine."""

    enabled: bool
    active: bool
    required: bool
    timeout_seconds: int


class AssessmentProfileResponse(BaseModel):
    """Versioned assessment profile metadata."""

    name: AssessmentProfileName
    version: str

    active_web_testing: bool
    active_authorization_version: (
        str | None
    )

    infrastructure_extension_allowed: bool
    infrastructure_extension_default: bool

    target_request_rate: int
    total_timeout_seconds: int

    destructive_testing_enabled: bool = False

    engines: dict[
        str,
        EnginePolicyMetadata,
    ]


class InfrastructureAuthorizationRequest(
    BaseModel
):
    """Explicit Deep infrastructure authorization."""

    authorized_ips: list[str] = Field(
        default_factory=list,
        max_length=128,
    )

    authorized_cidrs: list[str] = Field(
        default_factory=list,
        max_length=128,
    )

    broad_port_scan_allowed: bool = False
    network_active_checks_allowed: bool = False

    third_party_infrastructure_attested_excluded: (
        bool
    ) = False


class AssessmentCreate(BaseModel):
    """Create one immutable Engine v2 assessment."""

    target_id: UUID

    profile: AssessmentProfileName

    assessment_mode: AssessmentMode = "web"

    active_testing_confirmed: bool = False

    infrastructure: (
        InfrastructureAuthorizationRequest
        | None
    ) = None


class AssessmentEngineExecutionResponse(BaseModel):
    """Persisted state for one Engine v2 scanner execution."""

    engine: str
    profile_enabled: bool

    status: str
    tool_version: str | None = None

    queued_at: datetime | None = None
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    completed_at: datetime | None = None
    cancelled_at: datetime | None = None

    elapsed_seconds: int | None = None

    exit_code: int | None = None

    failure_type: str | None = None
    failure_message: str | None = None
    skipped_reason: str | None = None

    attempt: int = 1

    metrics: dict[
        str,
        int | float | str,
    ] = Field(
        default_factory=dict
    )


class AssessmentCoverageResponse(BaseModel):
    """Truthful persisted coverage view for one assessment.

    Detailed URL/service counters remain nullable because Phase 16A
    currently calculates them during orchestration but does not persist
    those counters.
    """

    engines_total: int
    engines_completed: int

    engines_failed: int
    engines_timed_out: int
    engines_skipped: int
    engines_cancelled: int
    engines_interrupted: int

    engines_incomplete: int

    complete: bool

    limitations: list[str] = Field(
        default_factory=list
    )

    detailed_metrics_available: bool = False

    http_services_discovered: int | None = None
    http_services_assessed: int | None = None

    urls_discovered: int | None = None
    urls_authorized: int | None = None
    urls_assessed: int | None = None

    tls_services_discovered: int | None = None
    tls_services_assessed: int | None = None


class AssessmentResponse(BaseModel):
    """Safe Engine v2 assessment state."""

    id: UUID
    target_id: UUID

    profile: str | None
    profile_version: str | None
    assessment_mode: str | None
    engine_version: str | None

    status: str
    progress: int

    celery_task_id: str | None

    active_testing_authorized_at: (
        datetime | None
    )

    cancel_requested: bool
    completed_with_warnings: bool

    current_stage: str | None = None
    current_stage_label: str | None = None

    elapsed_seconds: int | None = None

    engine_executions: list[
        AssessmentEngineExecutionResponse
    ] = Field(
        default_factory=list
    )

    coverage: AssessmentCoverageResponse | None = None

    started_at: datetime | None
    completed_at: datetime | None
    failure_reason: str | None

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class AssessmentCancelResponse(BaseModel):
    """Result of a cooperative cancellation request."""

    assessment_id: UUID
    status: str
    cancellation_requested: bool


class ScannerHealthResponse(BaseModel):
    """Task-18 scanner-health API compatibility surface."""

    status: Literal[
        "not_collected"
    ] = "not_collected"

    engines: list[str]

    detail: str
