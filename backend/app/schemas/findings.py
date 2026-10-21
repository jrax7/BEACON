from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


FindingClassification = Literal[
    "security_issue",
    "attack_surface",
    "observation",
    "limitation",
]

FindingLifecycleState = Literal[
    "NEW",
    "TRIAGED",
    "ASSIGNED",
    "IN_REMEDIATION",
    "READY_FOR_RETEST",
    "RESOLVED",
]

FindingObservationState = Literal[
    "NEW",
    "PERSISTING",
    "RESOLVED",
    "REGRESSED",
]

FindingDisposition = Literal[
    "FALSE_POSITIVE",
    "RISK_ACCEPTED",
    "DUPLICATE",
]


class WorkspaceFindingSourceResponse(BaseModel):
    tool_name: str
    external_finding_ids: list[str]
    occurrence_count: int


class WorkspaceFindingSummaryResponse(BaseModel):
    id: str
    primary_finding_id: UUID | None = None
    issue_key: str
    classification: FindingClassification
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
    sources: list[WorkspaceFindingSourceResponse]
    requires_manual_validation: bool

    lifecycle_state: FindingLifecycleState = "NEW"
    observation_state: FindingObservationState = "NEW"
    assignee_user_id: UUID | None = None
    remediation_owner_user_id: UUID | None = None
    disposition: FindingDisposition | None = None
    disposition_reason: str | None = None
    disposition_set_by_user_id: UUID | None = None
    disposition_set_at: datetime | None = None
    duplicate_of_finding_id: UUID | None = None

    target_id: UUID
    target_hostname: str
    target_url: str

    scan_id: UUID
    scan_status: str
    scan_created_at: datetime
    scan_completed_at: datetime | None
    last_observed_at: datetime


class WorkspaceFindingsPageResponse(BaseModel):
    total: int
    offset: int
    limit: int
    items: list[
        WorkspaceFindingSummaryResponse
    ]


class WorkspaceFindingOccurrenceResponse(BaseModel):
    id: UUID
    tool_name: str
    external_finding_id: str | None
    title: str
    severity: str
    confidence: str | None
    affected_url: str | None
    affected_port: int | None
    evidence: dict | None
    remediation: str | None
    cwe_id: str | None
    cvss_score: Decimal | None
    status: str
    created_at: datetime


class WorkspaceFindingDetailResponse(
    WorkspaceFindingSummaryResponse
):
    occurrences: list[
        WorkspaceFindingOccurrenceResponse
    ]


class FindingLifecycleUpdateRequest(BaseModel):
    next_state: FindingLifecycleState
    reason: str | None = None


class FindingDispositionUpdateRequest(BaseModel):
    disposition: FindingDisposition
    reason: str
    duplicate_of_finding_id: UUID | None = None


class FindingDispositionClearRequest(BaseModel):
    reason: str


class FindingAssigneeUpdateRequest(BaseModel):
    assignee_user_id: UUID | None = None


class FindingRemediationOwnerUpdateRequest(BaseModel):
    remediation_owner_user_id: UUID | None = None


class FindingWorkflowEventResponse(BaseModel):
    id: UUID
    finding_id: UUID
    organization_id: UUID
    actor_user_id: UUID
    event_type: str
    previous_value: str | None
    new_value: str | None
    reason: str | None
    related_scan_id: UUID | None
    created_at: datetime


class FindingWorkflowHistoryResponse(BaseModel):
    events: list[
        FindingWorkflowEventResponse
    ]


class FindingRetestCreateRequest(BaseModel):
    scan_id: UUID | None = None


class FindingRetestResponse(BaseModel):
    id: UUID
    finding_id: UUID
    organization_id: UUID
    requested_by_user_id: UUID
    status: Literal[
        "REQUESTED",
        "RUNNING",
        "PASSED",
        "FAILED",
        "CANCELLED",
    ]
    scan_id: UUID | None
    requested_at: datetime
    completed_at: datetime | None


class FindingRetestListResponse(BaseModel):
    items: list[
        FindingRetestResponse
    ]


class FindingPostureResponse(BaseModel):
    active: int
    new: int
    persisting: int
    regressed: int
    resolved: int
    awaiting_triage: int
    awaiting_assignment: int
    in_remediation: int
    awaiting_retest: int
    risk_accepted: int
    false_positive: int
    severity_breakdown: dict[str, int]


class FindingRetestLinkRequest(BaseModel):
    scan_id: UUID
