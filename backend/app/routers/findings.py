from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.finding import Finding
from app.models.finding_retest import FindingRetest
from app.organizations.context import resolve_organization_context
from app.organizations.rbac import Permission, require_permission
from app.schemas.findings import (
    FindingAssigneeUpdateRequest,
    FindingDispositionClearRequest,
    FindingDispositionUpdateRequest,
    FindingLifecycleUpdateRequest,
    FindingRemediationOwnerUpdateRequest,
    FindingPostureResponse,
    FindingRetestCreateRequest,
    FindingRetestLinkRequest,
    FindingRetestListResponse,
    FindingRetestResponse,
    FindingWorkflowEventResponse,
    FindingWorkflowHistoryResponse,
    WorkspaceFindingDetailResponse,
    WorkspaceFindingsPageResponse,
)
from app.services.finding_workflow import (
    FindingWorkflowError,
    assign_finding,
    clear_disposition,
    list_workflow_history,
    set_disposition,
    set_remediation_owner,
    transition_finding,
)
from app.services.finding_retests import (
    link_retest_scan,
    list_retests,
    request_retest,
)
from app.services.security_posture import (
    build_security_posture,
)
from app.services.findings_workspace import (
    build_workspace_detail,
    build_workspace_rows,
    filter_workspace_rows,
    resolve_workspace_members,
)


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


def _workflow_error(
    exc: FindingWorkflowError,
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
    )


def _members_or_404(
    database: Session,
    *,
    organization_id: UUID,
    finding_id: str,
):
    members = resolve_workspace_members(
        database,
        organization_id,
        finding_id,
    )

    if not members:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    return members


def _copy_fields(
    source,
    members,
    fields,
) -> None:
    for member in members[1:]:
        for field in fields:
            setattr(
                member,
                field,
                getattr(
                    source,
                    field,
                ),
            )


def _retest_response(
    retest,
) -> FindingRetestResponse:
    return FindingRetestResponse(
        id=retest.id,
        finding_id=retest.finding_id,
        organization_id=retest.organization_id,
        requested_by_user_id=(
            retest.requested_by_user_id
        ),
        status=retest.status,
        scan_id=retest.scan_id,
        requested_at=retest.requested_at,
        completed_at=retest.completed_at,
    )


def _detail_or_404(
    database: Session,
    *,
    organization_id: UUID,
    finding_id: str,
) -> WorkspaceFindingDetailResponse:
    detail = build_workspace_detail(
        database,
        organization_id,
        finding_id,
    )

    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    return WorkspaceFindingDetailResponse(
        **detail
    )


@router.get(
    "",
    response_model=WorkspaceFindingsPageResponse,
)
def list_findings(
    current_user: CurrentUser,
    database: DatabaseSession,
    severity: str | None = Query(
        default=None,
    ),
    confidence: str | None = Query(
        default=None,
    ),
    target_id: UUID | None = Query(
        default=None,
    ),
    scan_id: UUID | None = Query(
        default=None,
    ),
    tool: str | None = Query(
        default=None,
    ),
    classification: str | None = Query(
        default=None,
    ),
    lifecycle_state: str | None = None,
    observation_state: str | None = None,
    disposition: str | None = None,
    assignee_user_id: UUID | None = None,
    remediation_owner_user_id: UUID | None = None,
    q: str | None = Query(
        default=None,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
) -> WorkspaceFindingsPageResponse:
    """List correlated findings belonging to the current user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_READ,
    )

    rows = build_workspace_rows(
        database,
        context.organization.id,
    )

    valid_classifications = {
        "security_issue",
        "attack_surface",
        "observation",
        "limitation",
    }

    normalized_classification = None

    if classification:
        candidate = classification.strip().lower()

        if candidate in valid_classifications:
            normalized_classification = candidate

    workflow_filters = {}

    if lifecycle_state is not None:
        workflow_filters[
            "lifecycle_state"
        ] = lifecycle_state

    if observation_state is not None:
        workflow_filters[
            "observation_state"
        ] = observation_state

    if disposition is not None:
        workflow_filters[
            "disposition"
        ] = disposition

    if assignee_user_id is not None:
        workflow_filters[
            "assignee_user_id"
        ] = assignee_user_id

    if remediation_owner_user_id is not None:
        workflow_filters[
            "remediation_owner_user_id"
        ] = remediation_owner_user_id

    filtered = filter_workspace_rows(
        rows,
        severity=severity,
        confidence=confidence,
        target_id=target_id,
        scan_id=scan_id,
        tool=tool,
        classification=normalized_classification,
        q=q,
        **workflow_filters,
    )

    total = len(filtered)

    items = filtered[
        offset:offset + limit
    ]

    return WorkspaceFindingsPageResponse(
        total=total,
        offset=offset,
        limit=limit,
        items=items,
    )


@router.patch(
    "/retests/{retest_id}/scan",
    response_model=FindingRetestResponse,
)
def link_finding_retest_scan(
    retest_id: UUID,
    request: FindingRetestLinkRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FindingRetestResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    retest = database.get(
        FindingRetest,
        retest_id,
    )

    if (
        retest is None
        or retest.organization_id
        != context.organization.id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding retest not found.",
        )

    if retest.status not in {
        "REQUESTED",
        "RUNNING",
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Only an active retest can be "
                "linked to an assessment."
            ),
        )

    if (
        retest.scan_id is not None
        and retest.scan_id
        != request.scan_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "This retest is already linked "
                "to another assessment."
            ),
        )

    finding = database.get(
        Finding,
        retest.finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Original finding not found.",
        )

    try:
        link_retest_scan(
            database,
            retest=retest,
            finding=finding,
            organization_id=(
                context.organization.id
            ),
            scan_id=request.scan_id,
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    database.commit()

    return _retest_response(
        retest
    )


@router.get(
    "/posture",
    response_model=FindingPostureResponse,
)
def get_finding_posture(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FindingPostureResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_READ,
    )

    return FindingPostureResponse(
        **build_security_posture(
            database,
            context.organization.id,
        )
    )


@router.post(
    "/{finding_id:path}/retests",
    response_model=FindingRetestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_finding_retest(
    finding_id: str,
    request: FindingRetestCreateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FindingRetestResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    try:
        retest = request_retest(
            database,
            finding=members[0],
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            scan_id=request.scan_id,
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    database.commit()

    return _retest_response(
        retest
    )


@router.get(
    "/{finding_id:path}/retests",
    response_model=FindingRetestListResponse,
)
def get_finding_retests(
    finding_id: str,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FindingRetestListResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_READ,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    retests = list_retests(
        database,
        finding_id=members[0].id,
        organization_id=context.organization.id,
    )

    return FindingRetestListResponse(
        items=[
            _retest_response(
                retest
            )
            for retest in retests
        ]
    )


@router.patch(
    "/{finding_id:path}/lifecycle",
    response_model=WorkspaceFindingDetailResponse,
)
def update_finding_lifecycle(
    finding_id: str,
    request: FindingLifecycleUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    primary = members[0]

    try:
        transition_finding(
            database,
            finding=primary,
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            next_state=request.next_state,
            reason=request.reason,
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    _copy_fields(
        primary,
        members,
        ("lifecycle_state",),
    )

    database.commit()

    return _detail_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )


@router.patch(
    "/{finding_id:path}/disposition",
    response_model=WorkspaceFindingDetailResponse,
)
def update_finding_disposition(
    finding_id: str,
    request: FindingDispositionUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    primary = members[0]

    try:
        set_disposition(
            database,
            finding=primary,
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            disposition=request.disposition,
            reason=request.reason,
            duplicate_of_finding_id=(
                request.duplicate_of_finding_id
            ),
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    _copy_fields(
        primary,
        members,
        (
            "disposition",
            "disposition_reason",
            "disposition_set_by_user_id",
            "disposition_set_at",
            "duplicate_of_finding_id",
        ),
    )

    database.commit()

    return _detail_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )


@router.delete(
    "/{finding_id:path}/disposition",
    response_model=WorkspaceFindingDetailResponse,
)
def delete_finding_disposition(
    finding_id: str,
    request: FindingDispositionClearRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    primary = members[0]

    try:
        clear_disposition(
            database,
            finding=primary,
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            reason=request.reason,
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    _copy_fields(
        primary,
        members,
        (
            "disposition",
            "disposition_reason",
            "disposition_set_by_user_id",
            "disposition_set_at",
            "duplicate_of_finding_id",
        ),
    )

    database.commit()

    return _detail_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )


@router.patch(
    "/{finding_id:path}/assignee",
    response_model=WorkspaceFindingDetailResponse,
)
def update_finding_assignee(
    finding_id: str,
    request: FindingAssigneeUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    primary = members[0]

    try:
        assign_finding(
            database,
            finding=primary,
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            assignee_user_id=request.assignee_user_id,
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    _copy_fields(
        primary,
        members,
        ("assignee_user_id",),
    )

    database.commit()

    return _detail_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )


@router.patch(
    "/{finding_id:path}/remediation-owner",
    response_model=WorkspaceFindingDetailResponse,
)
def update_finding_remediation_owner(
    finding_id: str,
    request: FindingRemediationOwnerUpdateRequest,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_MANAGE,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    primary = members[0]

    try:
        set_remediation_owner(
            database,
            finding=primary,
            organization_id=context.organization.id,
            actor_user_id=current_user.id,
            remediation_owner_user_id=(
                request.remediation_owner_user_id
            ),
        )
    except FindingWorkflowError as exc:
        raise _workflow_error(
            exc
        ) from exc

    _copy_fields(
        primary,
        members,
        ("remediation_owner_user_id",),
    )

    database.commit()

    return _detail_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )


@router.get(
    "/{finding_id:path}/history",
    response_model=FindingWorkflowHistoryResponse,
)
def get_finding_history(
    finding_id: str,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> FindingWorkflowHistoryResponse:
    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_READ,
    )

    members = _members_or_404(
        database,
        organization_id=context.organization.id,
        finding_id=finding_id,
    )

    events = list_workflow_history(
        database,
        finding_id=members[0].id,
        organization_id=context.organization.id,
    )

    return FindingWorkflowHistoryResponse(
        events=[
            FindingWorkflowEventResponse(
                id=event.id,
                finding_id=event.finding_id,
                organization_id=event.organization_id,
                actor_user_id=event.actor_user_id,
                event_type=event.event_type,
                previous_value=event.previous_value,
                new_value=event.new_value,
                reason=event.reason,
                related_scan_id=event.related_scan_id,
                created_at=event.created_at,
            )
            for event in events
        ]
    )


@router.get(
    "/{finding_id:path}",
    response_model=WorkspaceFindingDetailResponse,
)
def get_finding(
    finding_id: str,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> WorkspaceFindingDetailResponse:
    """Return one owned correlated finding with raw occurrences."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.FINDING_READ,
    )

    detail = build_workspace_detail(
        database,
        context.organization.id,
        finding_id,
    )

    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    return WorkspaceFindingDetailResponse(
        **detail
    )
