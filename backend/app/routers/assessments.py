from datetime import (
    datetime,
    timezone,
)
import hashlib
from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.authorization import (
    ActiveAuthorizationConfirmation,
    InfrastructureScopeAuthorization,
    validate_active_authorization,
    validate_infrastructure_authorization,
)
from app.assessment.health import (
    ScannerHealthInventory,
    collect_scanner_health,
)
from app.assessment.nuclei_policy import (
    resolve_nuclei_policy,
)
from app.assessment.profiles import (
    assessment_profile_names,
    get_assessment_profile,
)
from app.assessment.zap_policy import (
    resolve_zap_policy,
)
from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.assessment_plan import (
    AssessmentScanPlan,
)
from app.models.audit_log import AuditLog
from app.models.infrastructure_authorization import (
    InfrastructureAuthorization,
)
from app.models.nuclei_template_snapshot import (
    NucleiTemplateSnapshot,
)
from app.models.scan import Scan
from app.models.tool_run import ScanToolRun
from app.models.target import Target
from app.models.user import User
from app.organizations.context import resolve_organization_context
from app.organizations.rbac import Permission, require_permission
from app.schemas.assessments import (
    AssessmentCancelResponse,
    AssessmentCoverageResponse,
    AssessmentEngineExecutionResponse,
    AssessmentCreate,
    AssessmentProfileResponse,
    AssessmentResponse,
    EnginePolicyMetadata,
)
from app.security.demo import (
    ensure_demo_active_scan_allowed,
    ensure_demo_scan_level_allowed,
    ensure_demo_target_allowed,
    is_demo_user,
)
from app.security.targets import (
    TargetValidationError,
    normalize_target_url,
    validate_target_destination,
)
from app.tasks_v2 import (
    request_assessment_v2_cancellation,
    run_assessment_v2,
)


router = APIRouter(
    prefix="/api/v1",
    tags=["Assessments"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


ACTIVE_ASSESSMENT_STATUSES = {
    "pending",
    "verifying",
    "queued",
    "running",
    "processing",
    "cancelling",
}


TERMINAL_ASSESSMENT_STATUSES = {
    "completed",
    "failed",
    "cancelled",
}


ENGINE_NAMES = [
    "nmap",
    "httpx",
    "katana",
    "sslyze",
    "nuclei",
    "zap",
    "nikto",
]


ACTIVE_AUTHORIZATION_VERSION = (
    "beacon-active-testing-v1"
)


INFRASTRUCTURE_AUTHORIZATION_VERSION = (
    "beacon-infrastructure-v1"
)


INFRASTRUCTURE_AUTHORIZATION_TEXT = (
    "I confirm that I own or possess explicit "
    "authorization from the owner to security-test "
    "the exact infrastructure scope supplied to "
    "BEACON, and that unauthorized shared or "
    "third-party infrastructure is excluded."
)


CRAWL_POLICIES = {
    "quick": {
        "depth": 2,
        "crawl_duration_seconds": 120,
        "max_response_bytes": 1_048_576,
        "max_output_bytes": 5_242_880,
    },
    "standard": {
        "depth": 5,
        "crawl_duration_seconds": 300,
        "max_response_bytes": 2_097_152,
        "max_output_bytes": 10_485_760,
    },
    "deep": {
        "depth": 8,
        "crawl_duration_seconds": 600,
        "max_response_bytes": 2_097_152,
        "max_output_bytes": 20_971_520,
    },
}


def _profile_response(
    profile_name: str,
) -> AssessmentProfileResponse:
    profile = get_assessment_profile(
        profile_name
    )

    return AssessmentProfileResponse(
        name=profile.name,
        version=profile.version,
        active_web_testing=(
            profile.active_web_testing
        ),
        active_authorization_version=(
            ACTIVE_AUTHORIZATION_VERSION
            if profile.active_web_testing
            else None
        ),
        infrastructure_extension_allowed=(
            profile
            .infrastructure_extension_allowed
        ),
        infrastructure_extension_default=(
            profile
            .infrastructure_extension_default
        ),
        target_request_rate=(
            profile.target_request_rate
        ),
        total_timeout_seconds=(
            profile.total_timeout_seconds
        ),
        destructive_testing_enabled=False,
        engines={
            engine:
                EnginePolicyMetadata(
                    enabled=policy.enabled,
                    active=policy.active,
                    required=policy.required,
                    timeout_seconds=(
                        policy.timeout_seconds
                    ),
                )
            for engine, policy
            in profile.engines.items()
        },
    )


def _get_owned_assessment(
    assessment_id: UUID,
    current_user: User,
    database: Session,
) -> Scan:

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_READ,
    )
    assessment = database.scalar(
        select(
            Scan
        ).where(
            Scan.id == assessment_id,
            Scan.organization_id == context.organization.id,
            Scan.profile.is_not(
                None
            ),
        )
    )

    if assessment is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Assessment not found.",
        )

    return assessment


def _select_nuclei_snapshot(
    *,
    profile_name: str,
    infrastructure_authorized: bool,
    database: Session,
) -> NucleiTemplateSnapshot:
    policy = resolve_nuclei_policy(
        profile=profile_name,
        infrastructure_authorized=(
            infrastructure_authorized
        ),
    )

    approved_groups = [
        group.value
        for group
        in policy.allowed_groups
    ]

    snapshot = database.scalar(
        select(
            NucleiTemplateSnapshot
        )
        .where(
            NucleiTemplateSnapshot
            .policy_version
            == policy.version,
            NucleiTemplateSnapshot
            .approved_groups
            == approved_groups,
        )
        .order_by(
            NucleiTemplateSnapshot
            .created_at
            .desc()
        )
        .limit(
            1
        )
    )

    if snapshot is None:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "No approved immutable Nuclei "
                "template snapshot is available "
                "for this assessment profile."
            ),
        )

    return snapshot


def _active_confirmation(
    *,
    profile_name: str,
    confirmed: bool,
    current_user: User,
    now: datetime,
) -> ActiveAuthorizationConfirmation | None:
    profile = get_assessment_profile(
        profile_name
    )

    if not profile.active_web_testing:
        return None

    if not confirmed:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "This profile requires explicit "
                "active testing authorization."
            ),
        )

    confirmation = (
        ActiveAuthorizationConfirmation(
            confirmed=True,
            confirmed_by_user_id=(
                current_user.id
            ),
            confirmed_at=now,
            authorization_version=(
                ACTIVE_AUTHORIZATION_VERSION
            ),
        )
    )

    try:
        validate_active_authorization(
            profile_name=(
                profile_name
            ),
            confirmation=confirmation,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=str(
                exc
            ),
        ) from exc

    return confirmation


def _infrastructure_authorization(
    *,
    request: AssessmentCreate,
    resolved_addresses: tuple[str, ...],
) -> InfrastructureScopeAuthorization | None:
    infrastructure = (
        request.infrastructure
    )

    if infrastructure is None:
        return None

    authorization = (
        InfrastructureScopeAuthorization(
            authorized_ips=tuple(
                infrastructure
                .authorized_ips
            ),
            authorized_cidrs=tuple(
                infrastructure
                .authorized_cidrs
            ),
            broad_port_scan_allowed=(
                infrastructure
                .broad_port_scan_allowed
            ),
            network_active_checks_allowed=(
                infrastructure
                .network_active_checks_allowed
            ),
            third_party_infrastructure_attested_excluded=(
                infrastructure
                .third_party_infrastructure_attested_excluded
            ),
        )
    )

    try:
        validate_infrastructure_authorization(
            profile_name=(
                request.profile
            ),
            authorization=authorization,
            requested_addresses=(
                resolved_addresses
            ),
        )
    except (
        ValueError,
        TypeError,
    ) as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=str(
                exc
            ),
        ) from exc

    return authorization


@router.get(
    "/assessment-profiles",
    response_model=list[
        AssessmentProfileResponse
    ],
)
def list_assessment_profiles(
    current_user: CurrentUser,
) -> list[
    AssessmentProfileResponse
]:
    """Return immutable metadata for available Engine v2 profiles."""

    del current_user

    return [
        _profile_response(
            profile_name
        )
        for profile_name
        in assessment_profile_names()
    ]


@router.post(
    "/assessments",
    response_model=AssessmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_assessment(
    request: AssessmentCreate,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Scan:
    """Create, snapshot, and queue one Engine v2 assessment."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_CREATE,
    )

    target = database.scalar(
        select(
            Target
        ).where(
            Target.id
            == request.target_id,
            Target.organization_id == context.organization.id,
        )
    )

    if target is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Target not found.",
        )

    ensure_demo_target_allowed(
        current_user,
        target,
    )

    # Demo Basic remains a legacy compatibility path until Task 26.
    # Engine v2 profile launches are intentionally not mapped here.
    ensure_demo_scan_level_allowed(
        current_user,
        request.profile,
    )

    now = datetime.now(
        timezone.utc
    )

    if (
        target.verification_status
        != "verified"
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "The target must be "
                "ownership-verified before "
                "assessment."
            ),
        )

    if (
        target.verification_expires_at
        is None
        or target
        .verification_expires_at
        <= now
    ):
        target.verification_status = (
            "expired"
        )

        database.commit()

        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "The target ownership "
                "verification has expired."
            ),
        )

    try:
        normalized_target = (
            normalize_target_url(
                target.normalized_url
            )
        )

        resolved_addresses = tuple(
            validate_target_destination(
                normalized_target
            )
        )
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=str(
                exc
            ),
        ) from exc

    if not resolved_addresses:
        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=(
                "The target did not resolve "
                "to an assessable address."
            ),
        )

    profile = get_assessment_profile(
        request.profile
    )

    confirmation = _active_confirmation(
        profile_name=profile.name,
        confirmed=(
            request
            .active_testing_confirmed
        ),
        current_user=current_user,
        now=now,
    )

    infrastructure_authorization = (
        _infrastructure_authorization(
            request=request,
            resolved_addresses=(
                resolved_addresses
            ),
        )
    )

    nuclei_snapshot = (
        _select_nuclei_snapshot(
            profile_name=(
                profile.name
            ),
            infrastructure_authorized=(
                infrastructure_authorization
                is not None
            ),
            database=database,
        )
    )

    zap_policy = resolve_zap_policy(
        profile_name=profile.name,
        active_confirmation=(
            confirmation
        ),
    )

    active_scan_query = (
        select(
            Scan
        ).where(
            Scan.organization_id == context.organization.id,
            Scan.status.in_(
                ACTIVE_ASSESSMENT_STATUSES
            ),
        )
    )

    if not is_demo_user(
        current_user
    ):
        active_scan_query = (
            active_scan_query.where(
                Scan.target_id
                == target.id
            )
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
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "This target already has "
                "an active assessment."
            ),
        )

    scan = Scan(
        organization_id=context.organization.id,
        user_id=current_user.id,
        target_id=target.id,
        scan_level=profile.name,
        status="queued",
        progress=0,
        profile=profile.name,
        profile_version=(
            profile.version
        ),
        assessment_mode=(
            request.assessment_mode
        ),
        engine_version="v2",
        active_testing_authorized_at=(
            confirmation.confirmed_at
            if confirmation is not None
            else None
        ),
        cancel_requested=False,
        completed_with_warnings=False,
    )

    database.add(
        scan
    )

    database.flush()

    engine_policy_versions = {
        engine:
            profile.version
        for engine
        in profile.engines
    }

    engine_policy_versions[
        "nuclei"
    ] = nuclei_snapshot.policy_version

    engine_policy_versions[
        "zap"
    ] = zap_policy.policy_version

    if confirmation is not None:
        engine_policy_versions[
            "authorization"
        ] = (
            confirmation
            .authorization_version
        )

    crawl_policy = dict(
        CRAWL_POLICIES[
            profile.name
        ]
    )

    plan = AssessmentScanPlan(
        scan_id=scan.id,
        profile=profile.name,
        profile_version=(
            profile.version
        ),
        assessment_mode=(
            request.assessment_mode
        ),
        authorized_scope={
            "fqdn":
                target.hostname,
        },
        resolved_addresses=list(
            resolved_addresses
        ),
        engine_policy_versions=(
            engine_policy_versions
        ),
        crawl_policy=(
            crawl_policy
        ),
        rate_budget={
            "requests_per_second":
                profile
                .target_request_rate,
        },
        timeout_budget={
            "assessment_seconds":
                profile
                .total_timeout_seconds,
        },
        nuclei_template_snapshot_id=(
            nuclei_snapshot.id
        ),
        zap_policy_version=(
            zap_policy.policy_version
        ),
    )

    database.add(
        plan
    )

    if (
        infrastructure_authorization
        is not None
    ):
        infrastructure = (
            request.infrastructure
        )

        if infrastructure is None:
            raise RuntimeError(
                "Validated infrastructure "
                "authorization disappeared."
            )

        authorization_hash = (
            hashlib.sha256(
                INFRASTRUCTURE_AUTHORIZATION_TEXT
                .encode(
                    "utf-8"
                )
            ).hexdigest()
        )

        database.add(
            InfrastructureAuthorization(
                scan_id=scan.id,
                confirmed_by_user_id=(
                    current_user.id
                ),
                authorization_version=(
                    INFRASTRUCTURE_AUTHORIZATION_VERSION
                ),
                authorization_text_hash=(
                    authorization_hash
                ),
                confirmed_at=now,
                source_ip=None,
                authorized_ips=list(
                    infrastructure_authorization
                    .authorized_ips
                ),
                authorized_cidrs=list(
                    infrastructure_authorization
                    .authorized_cidrs
                ),
                resolved_target_ips=list(
                    resolved_addresses
                ),
                broad_port_scan_allowed=(
                    infrastructure_authorization
                    .broad_port_scan_allowed
                ),
                network_active_checks_allowed=(
                    infrastructure_authorization
                    .network_active_checks_allowed
                ),
                third_party_infrastructure_attested_excluded=(
                    infrastructure_authorization
                    .third_party_infrastructure_attested_excluded
                ),
            )
        )

    database.add(
        AuditLog(
            organization_id=context.organization.id,
            user_id=current_user.id,
            target_id=target.id,
            scan_id=scan.id,
            action="assessment.created",
            details={
                "engine_version":
                    "v2",
                "profile":
                    profile.name,
                "profile_version":
                    profile.version,
                "assessment_mode":
                    request
                    .assessment_mode,
                "active_testing":
                    profile
                    .active_web_testing,
                "infrastructure_extension":
                    (
                        infrastructure_authorization
                        is not None
                    ),
                "nuclei_template_snapshot_id":
                    str(
                        nuclei_snapshot.id
                    ),
                "zap_policy_version":
                    zap_policy
                    .policy_version,
            },
        )
    )

    # PostgreSQL is authoritative. Persist the immutable plan before
    # Celery receives work so a fast worker can never observe a
    # partially-created assessment.
    database.commit()

    database.refresh(
        scan
    )

    try:
        task = (
            run_assessment_v2.delay(
                str(
                    scan.id
                )
            )
        )
    except Exception as exc:
        scan.status = "failed"
        scan.progress = 100
        scan.failure_reason = (
            "The assessment could not "
            "be submitted to the "
            "Engine v2 task queue."
        )
        scan.completed_at = (
            datetime.now(
                timezone.utc
            )
        )

        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=target.id,
                scan_id=scan.id,
                action="assessment.failed",
                details={
                    "reason":
                        str(
                            exc
                        )[:1000],
                },
            )
        )

        database.commit()

        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "The assessment queue is "
                "currently unavailable."
            ),
        ) from exc

    scan.celery_task_id = task.id

    database.commit()

    database.refresh(
        scan
    )

    return scan


ENGINE_TERMINAL_STATES = {
    "completed",
    "failed",
    "timed_out",
    "cancelled",
    "skipped",
    "interrupted",
}


ENGINE_INCOMPLETE_STATES = {
    "failed",
    "timed_out",
    "cancelled",
    "interrupted",
}


def _aware_datetime(
    value: datetime | None,
) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value


def _elapsed_seconds(
    *,
    started_at: datetime | None,
    completed_at: datetime | None,
    now: datetime,
) -> int | None:
    started = _aware_datetime(
        started_at
    )

    if started is None:
        return None

    ended = (
        _aware_datetime(
            completed_at
        )
        or now
    )

    return max(
        0,
        int(
            (
                ended
                - started
            ).total_seconds()
        ),
    )


def _engine_display_name(
    engine: str,
) -> str:
    names = {
        "nmap":
            "Nmap service discovery",
        "httpx":
            "httpx HTTP classification",
        "katana":
            "Katana application discovery",
        "sslyze":
            "SSLyze TLS assessment",
        "nuclei":
            "Nuclei vulnerability checks",
        "zap":
            "OWASP ZAP assessment",
        "nikto":
            "Nikto server checks",
    }

    return names.get(
        engine,
        engine,
    )


def _engine_execution_response(
    *,
    engine: str,
    profile_enabled: bool,
    run: ScanToolRun | None,
    profile_name: str,
    now: datetime,
) -> AssessmentEngineExecutionResponse:
    if run is None:
        if profile_enabled:
            return AssessmentEngineExecutionResponse(
                engine=engine,
                profile_enabled=True,
                status="pending",
            )

        return AssessmentEngineExecutionResponse(
            engine=engine,
            profile_enabled=False,
            status="skipped",
            skipped_reason=(
                "Disabled by the "
                f"{profile_name} profile."
            ),
        )

    metrics: dict[
        str,
        int | float | str,
    ] = {}

    # Only expose counters the scanner actually persisted.
    # In particular, do not expose legacy/estimated progress_percent.
    for attribute in (
        "completed_requests",
        "estimated_total_requests",
        "request_error_count",
        "finding_count",
    ):
        value = getattr(
            run,
            attribute,
            None,
        )

        if (
            isinstance(
                value,
                (
                    int,
                    float,
                ),
            )
            and not isinstance(
                value,
                bool,
            )
        ):
            metrics[
                attribute
            ] = value

    failure_message = (
        getattr(
            run,
            "failure_message",
            None,
        )
        or getattr(
            run,
            "error_message",
            None,
        )
    )

    return AssessmentEngineExecutionResponse(
        engine=engine,
        profile_enabled=(
            profile_enabled
        ),
        status=str(
            run.status
        ).strip().lower(),
        tool_version=(
            run.tool_version
        ),
        queued_at=getattr(
            run,
            "queued_at",
            None,
        ),
        started_at=(
            run.started_at
        ),
        last_heartbeat_at=getattr(
            run,
            "last_heartbeat_at",
            None,
        ),
        completed_at=(
            run.completed_at
        ),
        cancelled_at=getattr(
            run,
            "cancelled_at",
            None,
        ),
        elapsed_seconds=(
            _elapsed_seconds(
                started_at=(
                    run.started_at
                ),
                completed_at=(
                    run.completed_at
                ),
                now=now,
            )
        ),
        exit_code=(
            run.exit_code
        ),
        failure_type=getattr(
            run,
            "failure_type",
            None,
        ),
        failure_message=(
            failure_message
        ),
        skipped_reason=getattr(
            run,
            "skipped_reason",
            None,
        ),
        attempt=int(
            getattr(
                run,
                "attempt",
                1,
            )
            or 1
        ),
        metrics=metrics,
    )


def _current_assessment_stage(
    *,
    assessment: Scan,
    executions: list[
        AssessmentEngineExecutionResponse
    ],
) -> tuple[
    str,
    str,
]:
    status_value = str(
        assessment.status
    ).strip().lower()

    if (
        assessment.cancel_requested
        and status_value
        not in {
            "completed",
            "failed",
            "cancelled",
        }
    ):
        return (
            "cancelling",
            "Cancellation requested",
        )

    for execution in executions:
        if (
            execution.profile_enabled
            and execution.status
            == "running"
        ):
            return (
                execution.engine,
                _engine_display_name(
                    execution.engine
                ),
            )

    if status_value in {
        "queued",
        "pending",
    }:
        return (
            "queued",
            "Waiting for assessment worker",
        )

    if (
        status_value
        == "completed"
        and assessment
        .completed_with_warnings
    ):
        return (
            "completed_with_warnings",
            "Completed with coverage warnings",
        )

    if status_value == "completed":
        return (
            "completed",
            "Assessment completed",
        )

    if status_value == "failed":
        return (
            "failed",
            "Assessment failed",
        )

    if status_value == "cancelled":
        return (
            "cancelled",
            "Assessment cancelled",
        )

    enabled = [
        execution
        for execution
        in executions
        if execution.profile_enabled
    ]

    if (
        enabled
        and all(
            execution.status
            in ENGINE_TERMINAL_STATES
            for execution
            in enabled
        )
    ):
        return (
            "post_processing",
            (
                "Normalization, correlation, "
                "and coverage"
            ),
        )

    if any(
        execution.status
        not in {
            "pending",
            "queued",
        }
        for execution
        in enabled
    ):
        return (
            "orchestration",
            (
                "Preparing next persisted "
                "engine stage"
            ),
        )

    return (
        "scope_authorization",
        "Scope and authorization",
    )


def _coverage_response(
    *,
    assessment: Scan,
    executions: list[
        AssessmentEngineExecutionResponse
    ],
) -> AssessmentCoverageResponse:
    enabled = [
        execution
        for execution
        in executions
        if execution.profile_enabled
    ]

    statuses = [
        execution.status
        for execution
        in enabled
    ]

    def count(
        status_value: str,
    ) -> int:
        return statuses.count(
            status_value
        )

    limitations: list[str] = []

    for execution in enabled:
        if (
            execution.status
            in ENGINE_INCOMPLETE_STATES
        ):
            detail = (
                execution.failure_message
                or execution
                .skipped_reason
                or execution.status
            )

            limitations.append(
                (
                    f"{execution.engine}: "
                    f"{detail}"
                )
            )

        elif (
            execution.status
            == "skipped"
        ):
            detail = (
                execution.skipped_reason
                or "skipped"
            )

            limitations.append(
                (
                    f"{execution.engine}: "
                    f"{detail}"
                )
            )

    # Preserve insertion order while removing duplicate messages.
    limitations = list(
        dict.fromkeys(
            limitations
        )
    )

    incomplete = sum(
        1
        for execution
        in enabled
        if execution.status
        in ENGINE_INCOMPLETE_STATES
    )

    successfully_terminal = (
        bool(
            enabled
        )
        and all(
            execution.status
            in {
                "completed",
                "skipped",
            }
            for execution
            in enabled
        )
    )

    return AssessmentCoverageResponse(
        engines_total=len(
            enabled
        ),
        engines_completed=count(
            "completed"
        ),
        engines_failed=count(
            "failed"
        ),
        engines_timed_out=count(
            "timed_out"
        ),
        engines_skipped=count(
            "skipped"
        ),
        engines_cancelled=count(
            "cancelled"
        ),
        engines_interrupted=count(
            "interrupted"
        ),
        engines_incomplete=(
            incomplete
        ),
        complete=(
            successfully_terminal
            and assessment.status
            == "completed"
        ),
        limitations=limitations,

        # Task 15 currently calculates the counters below during
        # orchestration but they are not persisted. Keep this false
        # and the counters null rather than inventing historical data.
        detailed_metrics_available=False,
        http_services_discovered=None,
        http_services_assessed=None,
        urls_discovered=None,
        urls_authorized=None,
        urls_assessed=None,
        tls_services_discovered=None,
        tls_services_assessed=None,
    )


def _assessment_detail_response(
    *,
    assessment: Scan,
    database: Session,
) -> AssessmentResponse:
    now = datetime.now(
        timezone.utc
    )

    runs = list(
        database.scalars(
            select(
                ScanToolRun
            )
            .where(
                ScanToolRun.scan_id
                == assessment.id
            )
            .order_by(
                ScanToolRun
                .created_at
                .asc()
            )
        ).all()
    )

    latest_run_by_engine: dict[
        str,
        ScanToolRun,
    ] = {}

    for run in runs:
        name = str(
            run.tool_name
        ).strip().lower()

        if name:
            latest_run_by_engine[
                name
            ] = run

    profile = get_assessment_profile(
        str(
            assessment.profile
        )
    )

    executions: list[
        AssessmentEngineExecutionResponse
    ] = []

    for engine in ENGINE_NAMES:
        policy = (
            profile.engines.get(
                engine
            )
        )

        profile_enabled = bool(
            policy
            and policy.enabled
        )

        executions.append(
            _engine_execution_response(
                engine=engine,
                profile_enabled=(
                    profile_enabled
                ),
                run=(
                    latest_run_by_engine
                    .get(
                        engine
                    )
                ),
                profile_name=(
                    profile.name
                ),
                now=now,
            )
        )

    (
        current_stage,
        current_stage_label,
    ) = _current_assessment_stage(
        assessment=assessment,
        executions=executions,
    )

    base = (
        AssessmentResponse
        .model_validate(
            assessment
        )
    )

    return base.model_copy(
        update={
            "current_stage":
                current_stage,
            "current_stage_label":
                current_stage_label,
            "elapsed_seconds":
                _elapsed_seconds(
                    started_at=(
                        assessment
                        .started_at
                    ),
                    completed_at=(
                        assessment
                        .completed_at
                    ),
                    now=now,
                ),
            "engine_executions":
                executions,
            "coverage":
                _coverage_response(
                    assessment=(
                        assessment
                    ),
                    executions=(
                        executions
                    ),
                ),
        }
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentResponse,
)
def read_assessment(
    assessment_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> AssessmentResponse:
    """Read one owned assessment with persisted Engine v2 execution state."""

    assessment = (
        _get_owned_assessment(
            assessment_id,
            current_user,
            database,
        )
    )

    return _assessment_detail_response(
        assessment=assessment,
        database=database,
    )


@router.post(
    "/assessments/{assessment_id}/cancel",
    response_model=AssessmentCancelResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def cancel_assessment(
    assessment_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> AssessmentCancelResponse:
    """Request cooperative cancellation for one owned assessment."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.ASSESSMENT_CANCEL,
    )

    assessment = _get_owned_assessment(
        assessment_id,
        current_user,
        database,
    )

    if (
        assessment.status
        in TERMINAL_ASSESSMENT_STATUSES
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=(
                "A terminal assessment "
                "cannot be cancelled."
            ),
        )

    result = (
        request_assessment_v2_cancellation(
            assessment.id
        )
    )

    requested = bool(
        result.get(
            "cancellation_requested"
        )
    )

    if requested:
        assessment.cancel_requested = (
            True
        )
        assessment.status = "cancelling"

        database.add(
            AuditLog(
                organization_id=context.organization.id,
                user_id=current_user.id,
                target_id=(
                    assessment.target_id
                ),
                scan_id=assessment.id,
                action=(
                    "assessment."
                    "cancel_requested"
                ),
                details={
                    "engine_version":
                        assessment
                        .engine_version,
                },
            )
        )

        database.commit()

    return AssessmentCancelResponse(
        assessment_id=(
            assessment.id
        ),
        status=(
            "cancelling"
            if requested
            else assessment.status
        ),
        cancellation_requested=(
            requested
        ),
    )

@router.get(
    "/scanner-health",
    response_model=ScannerHealthInventory,
)
def read_scanner_health(
    current_user: CurrentUser,
) -> ScannerHealthInventory:
    """Return actual Engine v2 scanner runtime inventory."""

    del current_user

    return collect_scanner_health()
