from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import base64
import hashlib
import socket
from tempfile import TemporaryDirectory
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import select

from app.assessment.authorization import (
    ActiveAuthorizationConfirmation,
    InfrastructureScopeAuthorization,
    validate_active_authorization,
    validate_infrastructure_authorization,
)
from app.assessment.cancellation import (
    AssessmentCancellationService,
)
from app.assessment.correlation import (
    CorrelationInput,
    decide_correlation,
)
from app.assessment.coverage import (
    EngineCoverageState,
    calculate_coverage,
)
from app.assessment.telemetry import (
    EngineContributionInput,
    calculate_engine_contribution,
)
from app.assessment.handoff import (
    HTTPServiceInventory,
    ServiceInventory,
    TLSService,
    TLSServiceInventory,
    WebEndpoint,
    WebEndpointInventory,
)
from app.assessment.profiles import (
    get_assessment_profile,
)
from app.assessment.scope import (
    host_is_within_exact_fqdn,
    validate_resolved_addresses,
)
from app.assessment.zap_policy import (
    resolve_zap_policy,
)
from app.config import settings
from app.database import SessionLocal
from app.models.assessment_plan import (
    AssessmentScanPlan,
)
from app.models.correlation_decision import (
    CorrelationDecision,
)
from app.models.detection import Detection
from app.models.finding import Finding
from app.models.finding_occurrence import (
    FindingOccurrence,
)
from app.models.infrastructure_authorization import (
    InfrastructureAuthorization,
)
from app.models.scanner_evidence import (
    RawScannerEvidence,
)
from app.models.nuclei_template_snapshot import (
    NucleiTemplateSnapshot,
)
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_run import ScanToolRun
from app.services.finding_reconciliation import (
    reconcile_terminal_scan,
)
from app.services.finding_retests import (
    complete_retests_for_terminal_scan,
)
from app.scanners.httpx import (
    run_httpx_probe,
)
from app.scanners.katana import (
    run_katana_crawl,
)
from app.scanners.nikto import (
    run_nikto_assessment,
)
from app.scanners.nmap import (
    run_nmap_discovery,
)
from app.scanners.nuclei import (
    run_nuclei_assessment,
)
from app.scanners.sslyze import (
    run_sslyze_assessment,
)
from app.scanners.zap import (
    ZapAssessmentRequest,
    ZapClient,
)


ENGINE_ORDER = (
    "nmap",
    "httpx",
    "katana",
    "sslyze",
    "nuclei",
    "zap",
    "nikto",
)


POST_PROCESSING_STAGES = (
    "normalization",
    "correlation",
    "coverage",
)


@dataclass(frozen=True)
class AssessmentClaim:
    """Persisted assessment snapshot claimed for Engine v2 execution."""

    scan_id: UUID
    profile_name: str
    profile_version: str
    assessment_mode: str
    target_hostname: str
    plan: object | None

    # TASK23_PERSISTED_INFRASTRUCTURE_HYDRATION
    infrastructure: dict[str, object] | None = None
    infrastructure_authorization: (
        InfrastructureScopeAuthorization | None
    ) = None

    user_id: UUID | None = None
    target_id: UUID | None = None
    target_normalized_url: str | None = None
    target_verification_status: str | None = None
    target_verification_expires_at: datetime | None = None
    active_testing_authorized_at: datetime | None = None

    scan_profile: str | None = None
    scan_profile_version: str | None = None
    scan_assessment_mode: str | None = None


@dataclass(frozen=True)
class OrchestrationResult:
    """User-safe summary of one orchestration delivery."""

    scan_id: UUID
    status: str
    duplicate: bool
    completed_with_warnings: bool
    warnings: tuple[str, ...]
    executed_stages: tuple[str, ...]
    failed_stage: str | None = None

    def to_dict(
        self,
    ) -> dict[str, object]:
        return {
            "scan_id":
                str(
                    self.scan_id
                ),
            "status":
                self.status,
            "duplicate":
                self.duplicate,
            "completed_with_warnings":
                self.completed_with_warnings,
            "warnings":
                list(
                    self.warnings
                ),
            "executed_stages":
                list(
                    self.executed_stages
                ),
            "failed_stage":
                self.failed_stage,
        }


class OrchestrationStore(
    Protocol,
):
    """Persistence boundary used by the orchestration state machine."""

    def claim(
        self,
        *,
        scan_id: UUID,
        celery_task_id: str | None,
    ) -> AssessmentClaim | None:
        ...

    def start_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
    ) -> None:
        ...

    def complete_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        output: object,
    ) -> None:
        ...

    def fail_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        error: Exception,
    ) -> None:
        ...

    def skip_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        reason: str,
    ) -> None:
        ...

    def finish_success(
        self,
        *,
        claim: AssessmentClaim,
        warnings: tuple[str, ...],
    ) -> None:
        ...

    def cancel_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        reason: str,
    ) -> None:
        ...

    def finish_cancelled(
        self,
        *,
        claim: AssessmentClaim,
        reason: str,
    ) -> None:
        ...

    def finish_failure(
        self,
        *,
        claim: AssessmentClaim,
        reason: str,
    ) -> None:
        ...


class StageRunner(
    Protocol,
):
    """Scanner/control-plane stage boundary for Engine v2."""

    def run(
        self,
        *,
        stage: str,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        ...


class AssessmentOrchestrator:
    """Deterministic profile-driven Engine v2 state machine."""

    def __init__(
        self,
        *,
        store: OrchestrationStore,
        runner: StageRunner,
        cancellation_service=None,
    ) -> None:
        self.store = store
        self.runner = runner
        self.cancellation_service = (
            cancellation_service
        )

    def _failed_result(
        self,
        *,
        claim: AssessmentClaim,
        reason: str,
        executed_stages: list[str],
        failed_stage: str,
        warnings: list[str],
    ) -> OrchestrationResult:
        self.store.finish_failure(
            claim=claim,
            reason=reason,
        )

        return OrchestrationResult(
            scan_id=claim.scan_id,
            status="failed",
            duplicate=False,
            completed_with_warnings=bool(
                warnings
            ),
            warnings=tuple(
                warnings
            ),
            executed_stages=tuple(
                executed_stages
            ),
            failed_stage=failed_stage,
        )

    # TASK17_CANCELLATION_INTEGRATION

    def _cancel_requested(
        self,
        *,
        claim: AssessmentClaim,
    ) -> bool:
        service = (
            self.cancellation_service
        )

        if service is None:
            return False

        return bool(
            service.is_cancel_requested(
                scan_id=claim.scan_id
            )
        )

    def _heartbeat(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
    ) -> None:
        service = (
            self.cancellation_service
        )

        if service is None:
            return

        service.heartbeat(
            scan_id=claim.scan_id,
            engine=engine,
        )

    def _cancelled_result(
        self,
        *,
        claim: AssessmentClaim,
        executed_stages: list[str],
        warnings: list[str],
    ) -> OrchestrationResult:
        reason = (
            "Assessment cancellation "
            "was requested."
        )

        finish_cancelled = getattr(
            self.store,
            "finish_cancelled",
            None,
        )

        if callable(
            finish_cancelled
        ):
            finish_cancelled(
                claim=claim,
                reason=reason,
            )
        else:
            self.store.finish_failure(
                claim=claim,
                reason=reason,
            )

        return OrchestrationResult(
            scan_id=claim.scan_id,
            status="cancelled",
            duplicate=False,
            completed_with_warnings=bool(
                warnings
            ),
            warnings=tuple(
                warnings
            ),
            executed_stages=tuple(
                executed_stages
            ),
            failed_stage=None,
        )

    def _skip_after_required_failure(
        self,
        *,
        claim: AssessmentClaim,
        profile,
        failed_engine: str,
    ) -> None:
        found_failed = False

        for engine in ENGINE_ORDER:
            if engine == failed_engine:
                found_failed = True
                continue

            if not found_failed:
                continue

            policy = profile.engines[
                engine
            ]

            reason = (
                f"blocked_by_required_failure:"
                f"{failed_engine}"
                if policy.enabled
                else "disabled_by_profile"
            )

            self.store.skip_engine(
                claim=claim,
                engine=engine,
                reason=reason,
            )

    def run(
        self,
        *,
        scan_id: UUID,
        celery_task_id: str | None = None,
    ) -> OrchestrationResult:
        claim = self.store.claim(
            scan_id=scan_id,
            celery_task_id=celery_task_id,
        )

        if claim is None:
            return OrchestrationResult(
                scan_id=scan_id,
                status="duplicate",
                duplicate=True,
                completed_with_warnings=False,
                warnings=(),
                executed_stages=(),
                failed_stage=None,
            )

        try:
            profile = (
                get_assessment_profile(
                    claim.profile_name
                )
            )
        except ValueError as exc:
            return self._failed_result(
                claim=claim,
                reason=str(
                    exc
                ),
                executed_stages=[],
                failed_stage="profile",
                warnings=[],
            )

        if (
            profile.version
            != claim.profile_version
        ):
            return self._failed_result(
                claim=claim,
                reason=(
                    "Persisted assessment profile version "
                    "does not match the runtime profile "
                    f"definition: persisted="
                    f"{claim.profile_version!r}, "
                    f"runtime={profile.version!r}."
                ),
                executed_stages=[],
                failed_stage="profile",
                warnings=[],
            )

        context: dict[
            str,
            object,
        ] = {}

        warnings: list[
            str
        ] = []

        executed_stages: list[
            str
        ] = []

        if self._cancel_requested(
            claim=claim
        ):
            return self._cancelled_result(
                claim=claim,
                executed_stages=(
                    executed_stages
                ),
                warnings=warnings,
            )

        safety_stage = (
            "scope_authorization"
        )

        executed_stages.append(
            safety_stage
        )

        try:
            context[
                safety_stage
            ] = self.runner.run(
                stage=safety_stage,
                claim=claim,
                context=context,
            )
        except Exception as exc:
            return self._failed_result(
                claim=claim,
                reason=(
                    "Assessment scope/authorization "
                    f"validation failed: {str(exc)[:1500]}"
                ),
                executed_stages=executed_stages,
                failed_stage=safety_stage,
                warnings=warnings,
            )

        for engine in ENGINE_ORDER:
            if self._cancel_requested(
                claim=claim
            ):
                return self._cancelled_result(
                    claim=claim,
                    executed_stages=(
                        executed_stages
                    ),
                    warnings=warnings,
                )

            policy = profile.engines[
                engine
            ]

            if not policy.enabled:
                self.store.skip_engine(
                    claim=claim,
                    engine=engine,
                    reason=(
                        "disabled_by_profile"
                    ),
                )
                continue

            self.store.start_engine(
                claim=claim,
                engine=engine,
            )

            self._heartbeat(
                claim=claim,
                engine=engine,
            )

            executed_stages.append(
                engine
            )

            try:
                output = self.runner.run(
                    stage=engine,
                    claim=claim,
                    context=context,
                )
            except Exception as exc:
                if self._cancel_requested(
                    claim=claim
                ):
                    reason = (
                        "Assessment cancellation "
                        "was requested."
                    )

                    cancel_engine = getattr(
                        self.store,
                        "cancel_engine",
                        None,
                    )

                    if callable(
                        cancel_engine
                    ):
                        cancel_engine(
                            claim=claim,
                            engine=engine,
                            reason=reason,
                        )
                    else:
                        self.store.fail_engine(
                            claim=claim,
                            engine=engine,
                            error=exc,
                        )

                    return self._cancelled_result(
                        claim=claim,
                        executed_stages=(
                            executed_stages
                        ),
                        warnings=warnings,
                    )

                self.store.fail_engine(
                    claim=claim,
                    engine=engine,
                    error=exc,
                )

                if policy.required:
                    self._skip_after_required_failure(
                        claim=claim,
                        profile=profile,
                        failed_engine=engine,
                    )

                    return self._failed_result(
                        claim=claim,
                        reason=(
                            f"Required engine {engine} failed: "
                            f"{str(exc)[:1500]}"
                        ),
                        executed_stages=(
                            executed_stages
                        ),
                        failed_stage=engine,
                        warnings=warnings,
                    )

                warnings.append(
                    f"Optional engine {engine} failed: "
                    f"{str(exc)[:1000]}"
                )

                continue

            context[
                engine
            ] = output

            self.store.complete_engine(
                claim=claim,
                engine=engine,
                output=output,
            )

            self._heartbeat(
                claim=claim,
                engine=engine,
            )

        for stage in POST_PROCESSING_STAGES:
            if self._cancel_requested(
                claim=claim
            ):
                return self._cancelled_result(
                    claim=claim,
                    executed_stages=(
                        executed_stages
                    ),
                    warnings=warnings,
                )

            executed_stages.append(
                stage
            )

            try:
                context[
                    stage
                ] = self.runner.run(
                    stage=stage,
                    claim=claim,
                    context=context,
                )
            except Exception as exc:
                return self._failed_result(
                    claim=claim,
                    reason=(
                        f"Required assessment stage "
                        f"{stage} failed: "
                        f"{str(exc)[:1500]}"
                    ),
                    executed_stages=(
                        executed_stages
                    ),
                    failed_stage=stage,
                    warnings=warnings,
                )

        self.store.finish_success(
            claim=claim,
            warnings=tuple(
                warnings
            ),
        )

        return OrchestrationResult(
            scan_id=claim.scan_id,
            status="completed",
            duplicate=False,
            completed_with_warnings=bool(
                warnings
            ),
            warnings=tuple(
                warnings
            ),
            executed_stages=tuple(
                executed_stages
            ),
            failed_stage=None,
        )


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


class DatabaseOrchestrationStore:
    """Short-transaction PostgreSQL persistence boundary."""

    LAUNCHABLE_SCAN_STATUSES = {
        "pending",
        "queued",
    }

    def __init__(
        self,
        *,
        session_factory=SessionLocal,
        clock=_utc_now,
    ) -> None:
        self.session_factory = (
            session_factory
        )
        self.clock = clock

    def _load_scan_for_update(
        self,
        database,
        scan_id: UUID,
    ) -> Scan | None:
        return database.scalar(
            select(
                Scan
            )
            .where(
                Scan.id == scan_id
            )
            .with_for_update()
        )

    def _load_plan(
        self,
        database,
        scan_id: UUID,
    ) -> AssessmentScanPlan | None:
        return database.scalar(
            select(
                AssessmentScanPlan
            ).where(
                AssessmentScanPlan.scan_id
                == scan_id
            )
        )

    def _load_infrastructure_authorization(
        self,
        database,
        scan_id: UUID,
    ) -> InfrastructureAuthorization | None:
        return database.scalar(
            select(
                InfrastructureAuthorization
            ).where(
                InfrastructureAuthorization.scan_id
                == scan_id
            )
        )

    def _load_target(
        self,
        database,
        target_id: UUID,
    ) -> Target | None:
        return database.get(
            Target,
            target_id,
        )

    def _load_engine_run_for_update(
        self,
        database,
        scan_id: UUID,
        engine: str,
    ) -> ScanToolRun | None:
        return database.scalar(
            select(
                ScanToolRun
            )
            .where(
                ScanToolRun.scan_id
                == scan_id,
                ScanToolRun.tool_name
                == engine,
            )
            .order_by(
                ScanToolRun.created_at.desc()
            )
            .limit(
                1
            )
            .with_for_update()
        )

    def claim(
        self,
        *,
        scan_id: UUID,
        celery_task_id: str | None,
    ) -> AssessmentClaim | None:
        with self.session_factory() as database:
            scan = (
                self._load_scan_for_update(
                    database,
                    scan_id,
                )
            )

            if scan is None:
                raise RuntimeError(
                    "The requested Engine v2 "
                    "assessment does not exist."
                )

            if (
                scan.status
                not in
                self.LAUNCHABLE_SCAN_STATUSES
            ):
                return None

            plan = self._load_plan(
                database,
                scan_id,
            )

            target = self._load_target(
                database,
                scan.target_id,
            )

            if (
                target is not None
                and (
                    scan.organization_id
                    != target.organization_id
                )
            ):
                raise RuntimeError(
                    "The assessment scan and target "
                    "belong to different organizations."
                )

            profile_name = (
                scan.profile
                or (
                    plan.profile
                    if plan is not None
                    else ""
                )
            )

            profile_version = (
                scan.profile_version
                or (
                    plan.profile_version
                    if plan is not None
                    else ""
                )
            )

            assessment_mode = (
                scan.assessment_mode
                or (
                    plan.assessment_mode
                    if plan is not None
                    else ""
                )
            )

            infrastructure_scope = None
            infrastructure_authorization = None

            if profile_name == "deep":
                persisted_infrastructure = (
                    self._load_infrastructure_authorization(
                        database,
                        scan_id,
                    )
                )

                if persisted_infrastructure is not None:
                    infrastructure_scope = {
                        "enabled":
                            True,
                        "infrastructure_extension_enabled":
                            True,
                        "authorized_ips":
                            list(
                                persisted_infrastructure
                                .authorized_ips
                            ),
                        "authorized_cidrs":
                            list(
                                persisted_infrastructure
                                .authorized_cidrs
                            ),
                        "resolved_target_ips":
                            list(
                                persisted_infrastructure
                                .resolved_target_ips
                            ),
                        "broad_port_scan_allowed":
                            bool(
                                persisted_infrastructure
                                .broad_port_scan_allowed
                            ),
                        "network_active_checks_allowed":
                            bool(
                                persisted_infrastructure
                                .network_active_checks_allowed
                            ),
                        "third_party_infrastructure_attested_excluded":
                            bool(
                                persisted_infrastructure
                                .third_party_infrastructure_attested_excluded
                            ),
                    }

                    infrastructure_authorization = (
                        InfrastructureScopeAuthorization(
                            authorized_ips=tuple(
                                persisted_infrastructure
                                .authorized_ips
                            ),
                            authorized_cidrs=tuple(
                                persisted_infrastructure
                                .authorized_cidrs
                            ),
                            broad_port_scan_allowed=bool(
                                persisted_infrastructure
                                .broad_port_scan_allowed
                            ),
                            network_active_checks_allowed=bool(
                                persisted_infrastructure
                                .network_active_checks_allowed
                            ),
                            third_party_infrastructure_attested_excluded=bool(
                                persisted_infrastructure
                                .third_party_infrastructure_attested_excluded
                            ),
                        )
                    )

            now = self.clock()

            scan.status = "running"

            scan.started_at = (
                scan.started_at
                or now
            )

            scan.completed_at = None
            scan.failure_reason = None

            scan.completed_with_warnings = (
                False
            )

            scan.engine_version = "v2"

            scan.progress = max(
                int(
                    scan.progress
                    or 0
                ),
                1,
            )

            if celery_task_id is not None:
                scan.celery_task_id = (
                    celery_task_id
                )

            database.commit()

            return AssessmentClaim(
                scan_id=scan.id,
                profile_name=profile_name,
                profile_version=(
                    profile_version
                ),
                assessment_mode=(
                    assessment_mode
                ),
                target_hostname=(
                    target.hostname
                    if target is not None
                    else ""
                ),
                plan=plan,
                infrastructure=(
                    infrastructure_scope
                ),
                infrastructure_authorization=(
                    infrastructure_authorization
                ),
                user_id=scan.user_id,
                target_id=scan.target_id,
                target_normalized_url=(
                    target.normalized_url
                    if target is not None
                    else None
                ),
                target_verification_status=(
                    target.verification_status
                    if target is not None
                    else None
                ),
                target_verification_expires_at=(
                    target.verification_expires_at
                    if target is not None
                    else None
                ),
                active_testing_authorized_at=(
                    scan.active_testing_authorized_at
                ),
                scan_profile=scan.profile,
                scan_profile_version=(
                    scan.profile_version
                ),
                scan_assessment_mode=(
                    scan.assessment_mode
                ),
            )

    def start_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
    ) -> None:
        with self.session_factory() as database:
            existing = (
                self._load_engine_run_for_update(
                    database,
                    claim.scan_id,
                    engine,
                )
            )

            now = self.clock()

            if existing is None:
                engine_run = ScanToolRun(
                    scan_id=claim.scan_id,
                    tool_name=engine,
                    status="running",
                    queued_at=now,
                    started_at=now,
                    last_heartbeat_at=now,
                    attempt=1,
                    lease_token=str(
                        uuid4()
                    ),
                )

                database.add(
                    engine_run
                )
            elif existing.status in {
                "pending",
                "queued",
            }:
                engine_run = existing

                engine_run.status = (
                    "running"
                )

                engine_run.queued_at = (
                    engine_run.queued_at
                    or now
                )

                engine_run.started_at = now

                engine_run.last_heartbeat_at = (
                    now
                )

                engine_run.completed_at = None
                engine_run.cancelled_at = None

                engine_run.failure_type = None
                engine_run.failure_message = None
                engine_run.error_message = None
                engine_run.skipped_reason = None

                engine_run.lease_token = str(
                    uuid4()
                )
            else:
                raise RuntimeError(
                    "Engine execution cannot be "
                    f"started from state "
                    f"{existing.status!r}: "
                    f"{engine}."
                )

            database.commit()

    def complete_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        output: object,
    ) -> None:
        with self.session_factory() as database:
            engine_run = (
                self._load_engine_run_for_update(
                    database,
                    claim.scan_id,
                    engine,
                )
            )

            if engine_run is None:
                raise RuntimeError(
                    "The running engine record "
                    f"does not exist: {engine}."
                )

            now = self.clock()

            tool_version = (
                getattr(
                    output,
                    "tool_version",
                    None,
                )
                or getattr(
                    output,
                    "scanner_version",
                    None,
                )
                or getattr(
                    output,
                    "version",
                    None,
                )
            )

            artifact_path = (
                getattr(
                    output,
                    "artifact_path",
                    None,
                )
                or getattr(
                    output,
                    "raw_output_path",
                    None,
                )
            )

            exit_code = getattr(
                output,
                "exit_code",
                0,
            )

            engine_run.status = "completed"

            engine_run.tool_version = (
                str(
                    tool_version
                )[:100]
                if tool_version is not None
                else engine_run.tool_version
            )

            engine_run.raw_output_path = (
                str(
                    artifact_path
                )
                if artifact_path is not None
                else engine_run.raw_output_path
            )

            engine_run.exit_code = (
                0
                if exit_code is None
                else int(
                    exit_code
                )
            )

            engine_run.error_message = None
            engine_run.failure_type = None
            engine_run.failure_message = None

            engine_run.last_heartbeat_at = (
                now
            )

            engine_run.completed_at = now

            database.commit()

    def fail_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        error: Exception,
    ) -> None:
        with self.session_factory() as database:
            engine_run = (
                self._load_engine_run_for_update(
                    database,
                    claim.scan_id,
                    engine,
                )
            )

            now = self.clock()

            if engine_run is None:
                engine_run = ScanToolRun(
                    scan_id=claim.scan_id,
                    tool_name=engine,
                    status="failed",
                    queued_at=now,
                    started_at=now,
                    attempt=1,
                    lease_token=str(
                        uuid4()
                    ),
                )

                database.add(
                    engine_run
                )

            message = str(
                error
            )[:2000]

            engine_run.status = "failed"

            engine_run.failure_type = (
                type(
                    error
                ).__name__[:100]
            )

            engine_run.failure_message = (
                message
            )

            engine_run.error_message = (
                message
            )

            return_code = getattr(
                error,
                "returncode",
                None,
            )

            if (
                isinstance(
                    return_code,
                    int,
                )
                and not isinstance(
                    return_code,
                    bool,
                )
            ):
                engine_run.exit_code = (
                    return_code
                )

            engine_run.last_heartbeat_at = (
                now
            )

            engine_run.completed_at = now

            database.commit()

    def cancel_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        reason: str,
    ) -> None:
        """Persist one running Engine-v2 execution as cancelled."""

        with self.session_factory() as database:
            engine_run = (
                self._load_engine_run_for_update(
                    database,
                    claim.scan_id,
                    engine,
                )
            )

            if engine_run is None:
                raise RuntimeError(
                    "The running engine record "
                    "does not exist for "
                    f"cancellation: {engine}."
                )

            status = str(
                engine_run.status
            ).strip().lower()

            if status == "cancelled":
                return

            if status not in {
                "pending",
                "queued",
                "running",
            }:
                raise RuntimeError(
                    "Engine execution cannot be "
                    "cancelled from state "
                    f"{engine_run.status!r}: "
                    f"{engine}."
                )

            now = self.clock()

            message = (
                reason[:2000]
            )

            engine_run.status = (
                "cancelled"
            )

            engine_run.cancelled_at = (
                now
            )

            engine_run.last_heartbeat_at = (
                now
            )

            engine_run.completed_at = (
                now
            )

            engine_run.failure_type = None

            engine_run.failure_message = (
                message
            )

            engine_run.error_message = (
                message
            )

            engine_run.skipped_reason = None

            engine_run.lease_token = None

            database.commit()

    def skip_engine(
        self,
        *,
        claim: AssessmentClaim,
        engine: str,
        reason: str,
    ) -> None:
        with self.session_factory() as database:
            engine_run = (
                self._load_engine_run_for_update(
                    database,
                    claim.scan_id,
                    engine,
                )
            )

            now = self.clock()

            if engine_run is None:
                engine_run = ScanToolRun(
                    scan_id=claim.scan_id,
                    tool_name=engine,
                    status="skipped",
                    queued_at=now,
                    started_at=now,
                    completed_at=now,
                    attempt=1,
                )

                database.add(
                    engine_run
                )
            elif engine_run.status in {
                "pending",
                "queued",
            }:
                engine_run.status = (
                    "skipped"
                )

                engine_run.started_at = (
                    engine_run.started_at
                    or now
                )

                engine_run.completed_at = (
                    now
                )
            else:
                raise RuntimeError(
                    "Engine execution cannot be "
                    f"skipped from state "
                    f"{engine_run.status!r}: "
                    f"{engine}."
                )

            engine_run.skipped_reason = (
                reason[:2000]
            )

            engine_run.error_message = (
                reason[:2000]
            )

            engine_run.lease_token = None

            database.commit()

    def finish_success(
        self,
        *,
        claim: AssessmentClaim,
        warnings: tuple[str, ...],
    ) -> None:
        with self.session_factory() as database:
            scan = (
                self._load_scan_for_update(
                    database,
                    claim.scan_id,
                )
            )

            if scan is None:
                raise RuntimeError(
                    "The assessment disappeared "
                    "before finalization."
                )

            scan.status = "completed"
            scan.progress = 100
            scan.completed_at = self.clock()
            scan.failure_reason = None

            scan.completed_with_warnings = (
                bool(
                    warnings
                )
            )

            if all(
                getattr(
                    scan,
                    field,
                    None,
                )
                is not None
                for field in (
                    "organization_id",
                    "user_id",
                    "target_id",
                )
            ):
                reconcile_terminal_scan(
                    database,
                    scan=scan,
                )

                complete_retests_for_terminal_scan(
                    database,
                    scan=scan,
                )

            database.commit()

    def finish_cancelled(
        self,
        *,
        claim: AssessmentClaim,
        reason: str,
    ) -> None:
        """Persist the assessment cancellation terminal state."""

        with self.session_factory() as database:
            scan = (
                self._load_scan_for_update(
                    database,
                    claim.scan_id,
                )
            )

            if scan is None:
                raise RuntimeError(
                    "The assessment disappeared "
                    "before cancellation could "
                    "be persisted."
                )

            scan.status = "cancelled"

            scan.failure_reason = (
                reason[:2000]
            )

            scan.completed_at = (
                self.clock()
            )

            if all(
                getattr(
                    scan,
                    field,
                    None,
                )
                is not None
                for field in (
                    "organization_id",
                    "user_id",
                    "target_id",
                )
            ):
                reconcile_terminal_scan(
                    database,
                    scan=scan,
                )

                complete_retests_for_terminal_scan(
                    database,
                    scan=scan,
                )

            database.commit()

    def finish_failure(
        self,
        *,
        claim: AssessmentClaim,
        reason: str,
    ) -> None:
        with self.session_factory() as database:
            scan = (
                self._load_scan_for_update(
                    database,
                    claim.scan_id,
                )
            )

            if scan is None:
                raise RuntimeError(
                    "The assessment disappeared "
                    "before failure state could "
                    "be persisted."
                )

            scan.status = "failed"

            scan.failure_reason = (
                reason[:2000]
            )

            scan.completed_at = (
                self.clock()
            )

            if all(
                getattr(
                    scan,
                    field,
                    None,
                )
                is not None
                for field in (
                    "organization_id",
                    "user_id",
                    "target_id",
                )
            ):
                reconcile_terminal_scan(
                    database,
                    scan=scan,
                )

                complete_retests_for_terminal_scan(
                    database,
                    scan=scan,
                )

            database.commit()


class ProductionStageRunner:
    """Production stage dispatcher for Engine v2.

    This cycle establishes the mandatory fail-closed
    control-plane gate. Concrete scanner execution is
    bound in the following Task 16 TDD cycle.
    """

    def __init__(
        self,
        *,
        clock=_utc_now,
        session_factory=SessionLocal,
        nmap_runner=run_nmap_discovery,
        httpx_runner=run_httpx_probe,
        katana_runner=run_katana_crawl,
        sslyze_runner=run_sslyze_assessment,
        nuclei_runner=run_nuclei_assessment,
        nuclei_snapshot_loader=None,
        zap_client_factory=ZapClient,
        nikto_runner=run_nikto_assessment,
        cancellation_service=None,
        resolver=None,
    ) -> None:
        self.clock = clock
        self.session_factory = (
            session_factory
        )

        self.nmap_runner = (
            nmap_runner
        )

        self.httpx_runner = (
            httpx_runner
        )

        self.katana_runner = (
            katana_runner
        )

        self.sslyze_runner = (
            sslyze_runner
        )

        self.nuclei_runner = (
            nuclei_runner
        )

        self.nuclei_snapshot_loader = (
            nuclei_snapshot_loader
        )

        self.zap_client_factory = (
            zap_client_factory
        )

        self.nikto_runner = (
            nikto_runner
        )

        self.cancellation_service = (
            cancellation_service
        )

        self.resolver = (
            resolver
            or self._resolve_addresses
        )

    @staticmethod
    def _lab_private_allowed(
        hostname: str,
    ) -> bool:
        if not settings.allow_lab_targets:
            return False

        allowed = {
            value.strip().lower().rstrip(
                "."
            )
            for value
            in settings.lab_allowed_hosts.split(
                ","
            )
            if value.strip()
        }

        normalized = (
            hostname.strip()
            .lower()
            .rstrip(
                "."
            )
        )

        return normalized in allowed

    def _validate_scope_authorization(
        self,
        claim: AssessmentClaim,
    ) -> dict[str, object]:
        plan = claim.plan

        if plan is None:
            raise RuntimeError(
                "Engine v2 requires an immutable "
                "assessment scan plan."
            )

        if (
            not claim.scan_profile
            or not claim.scan_profile_version
            or not claim.scan_assessment_mode
        ):
            raise RuntimeError(
                "Engine v2 scan metadata is "
                "incomplete."
            )

        if (
            plan.profile
            != claim.scan_profile
        ):
            raise RuntimeError(
                "Persisted immutable plan profile "
                "does not match the scan profile."
            )

        if (
            plan.profile_version
            != claim.scan_profile_version
        ):
            raise RuntimeError(
                "Persisted immutable plan profile "
                "version does not match the scan."
            )

        if (
            plan.assessment_mode
            != claim.scan_assessment_mode
        ):
            raise RuntimeError(
                "Persisted immutable plan mode "
                "does not match the scan."
            )

        if (
            claim.profile_name
            != plan.profile
            or claim.profile_version
            != plan.profile_version
            or claim.assessment_mode
            != plan.assessment_mode
        ):
            raise RuntimeError(
                "Claim metadata does not match "
                "the immutable assessment plan."
            )

        profile = get_assessment_profile(
            claim.profile_name
        )

        if (
            profile.version
            != plan.profile_version
        ):
            raise RuntimeError(
                "Runtime profile version does not "
                "match the immutable assessment plan."
            )

        if (
            claim.target_id is None
            or not claim.target_hostname
            or not claim.target_normalized_url
        ):
            raise RuntimeError(
                "The assessment target no longer "
                "exists."
            )

        if (
            claim.target_verification_status
            != "verified"
        ):
            raise RuntimeError(
                "The assessment target is not "
                "ownership-verified."
            )

        expires_at = (
            claim.target_verification_expires_at
        )

        if (
            expires_at is None
            or expires_at
            <= self.clock()
        ):
            raise RuntimeError(
                "The target ownership verification "
                "has expired."
            )

        authorized_scope = (
            plan.authorized_scope
            if isinstance(
                plan.authorized_scope,
                dict,
            )
            else {}
        )

        authorized_host = (
            authorized_scope.get(
                "fqdn"
            )
        )

        if (
            not isinstance(
                authorized_host,
                str,
            )
            or not authorized_host.strip()
        ):
            raise RuntimeError(
                "The immutable assessment plan "
                "does not contain an exact "
                "authorized FQDN."
            )

        if not host_is_within_exact_fqdn(
            claim.target_hostname,
            authorized_host,
        ):
            raise RuntimeError(
                "The assessment target does not "
                "match the exact authorized FQDN."
            )

        resolved_addresses = (
            plan.resolved_addresses
        )

        if (
            not isinstance(
                resolved_addresses,
                list,
            )
            or not resolved_addresses
            or not all(
                isinstance(
                    address,
                    str,
                )
                and address.strip()
                for address
                in resolved_addresses
            )
        ):
            raise RuntimeError(
                "The immutable assessment plan "
                "does not contain a valid resolved "
                "address snapshot."
            )

        validate_resolved_addresses(
            resolved_addresses,
            allow_private=(
                self._lab_private_allowed(
                    claim.target_hostname
                )
            ),
        )

        if profile.active_web_testing:
            if (
                claim.user_id is None
                or claim.active_testing_authorized_at
                is None
            ):
                raise RuntimeError(
                    "Active testing authorization "
                    "is missing from the assessment."
                )

            engine_versions = (
                plan.engine_policy_versions
                if isinstance(
                    plan.engine_policy_versions,
                    dict,
                )
                else {}
            )

            authorization_version = (
                engine_versions.get(
                    "authorization"
                )
            )

            if (
                not isinstance(
                    authorization_version,
                    str,
                )
                or not authorization_version.strip()
            ):
                raise RuntimeError(
                    "The immutable assessment plan "
                    "does not snapshot the active "
                    "authorization version."
                )

            validate_active_authorization(
                profile_name=(
                    claim.profile_name
                ),
                confirmation=(
                    ActiveAuthorizationConfirmation(
                        confirmed=True,
                        confirmed_by_user_id=(
                            claim.user_id
                        ),
                        confirmed_at=(
                            claim.active_testing_authorized_at
                        ),
                        authorization_version=(
                            authorization_version
                        ),
                    )
                ),
            )

        return {
            "authorized_host":
                authorized_host.strip(),
            "resolved_addresses":
                tuple(
                    resolved_addresses
                ),
            "active_testing":
                profile.active_web_testing,
            "profile":
                profile.name,
            "profile_version":
                profile.version,
            "assessment_mode":
                claim.assessment_mode,
        }

    @staticmethod
    def _resolve_addresses(
        hostname: str,
    ) -> tuple[str, ...]:
        try:
            records = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise RuntimeError(
                "Unable to re-resolve the "
                "assessment target."
            ) from exc

        addresses = sorted(
            {
                record[4][0]
                for record in records
            }
        )

        if not addresses:
            raise RuntimeError(
                "Target resolution returned "
                "no addresses."
            )

        return tuple(
            addresses
        )

    def _revalidate_resolution(
        self,
        claim: AssessmentClaim,
    ) -> tuple[str, ...]:
        plan = claim.plan

        if plan is None:
            raise RuntimeError(
                "Engine v2 scanner execution "
                "requires the immutable plan."
            )

        current = tuple(
            self.resolver(
                claim.target_hostname
            )
        )

        if not current:
            raise RuntimeError(
                "Target resolution returned "
                "no addresses."
            )

        validate_resolved_addresses(
            list(
                current
            ),
            allow_private=(
                self._lab_private_allowed(
                    claim.target_hostname
                )
            ),
        )

        snapshot = {
            str(
                address
            ).strip()
            for address
            in plan.resolved_addresses
        }

        if not set(
            current
        ).issubset(
            snapshot
        ):
            raise RuntimeError(
                "Target DNS resolution changed "
                "outside the immutable authorized "
                "address snapshot."
            )

        return current

    @staticmethod
    def _require_mapping(
        value: object,
        *,
        name: str,
    ) -> dict:
        if not isinstance(
            value,
            dict,
        ):
            raise RuntimeError(
                f"The immutable {name} "
                "snapshot is invalid."
            )

        return value

    @classmethod
    def _positive_integer(
        cls,
        mapping: object,
        key: str,
        *,
        section: str,
    ) -> int:
        values = cls._require_mapping(
            mapping,
            name=section,
        )

        value = values.get(
            key
        )

        if (
            not isinstance(
                value,
                int,
            )
            or isinstance(
                value,
                bool,
            )
            or value <= 0
        ):
            raise RuntimeError(
                f"The immutable {section} "
                f"snapshot is missing a valid "
                f"{key!r} value."
            )

        return value

    @staticmethod
    def _service_inventory(
        context: dict[str, object],
    ) -> ServiceInventory:
        nmap_result = context.get(
            "nmap"
        )

        inventory = getattr(
            nmap_result,
            "service_inventory",
            None,
        )

        if not isinstance(
            inventory,
            ServiceInventory,
        ):
            raise RuntimeError(
                "httpx/TLS stages require "
                "the typed Nmap "
                "ServiceInventory handoff."
            )

        return inventory

    @staticmethod
    def _http_inventory(
        context: dict[str, object],
    ) -> HTTPServiceInventory:
        inventory = context.get(
            "httpx"
        )

        if not isinstance(
            inventory,
            HTTPServiceInventory,
        ):
            raise RuntimeError(
                "Web scanner stages require "
                "the typed HTTPServiceInventory "
                "handoff."
            )

        return inventory

    @staticmethod
    def _web_inventory(
        context: dict[str, object],
    ) -> WebEndpointInventory:
        inventory = context.get(
            "katana"
        )

        if not isinstance(
            inventory,
            WebEndpointInventory,
        ):
            raise RuntimeError(
                "Web vulnerability stages require "
                "the typed WebEndpointInventory "
                "handoff."
            )

        return inventory

    def _authorized_web_inventory(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> WebEndpointInventory:
        authorized_host = (
            claim.target_hostname
            .strip()
            .lower()
            .rstrip(
                "."
            )
        )

        http_inventory = (
            self._http_inventory(
                context
            )
        )

        crawl_inventory = (
            self._web_inventory(
                context
            )
        )

        endpoints: list[
            WebEndpoint
        ] = []

        seen: set[
            tuple[
                str,
                str,
                tuple[str, ...],
            ]
        ] = set()

        def add_endpoint(
            endpoint: WebEndpoint,
        ) -> None:
            parsed = urlsplit(
                endpoint.url
            )

            if (
                parsed.scheme.lower()
                not in {
                    "http",
                    "https",
                }
                or parsed.hostname
                is None
                or parsed.username
                is not None
                or parsed.password
                is not None
                or not host_is_within_exact_fqdn(
                    parsed.hostname,
                    authorized_host,
                )
            ):
                return

            key = (
                endpoint.url,
                endpoint.method.upper(),
                tuple(
                    endpoint.parameter_names
                ),
            )

            if key in seen:
                return

            seen.add(
                key
            )

            endpoints.append(
                endpoint
            )

        for service in (
            http_inventory.services
        ):
            parsed = urlsplit(
                service.url
            )

            if (
                parsed.hostname
                is not None
                and host_is_within_exact_fqdn(
                    parsed.hostname,
                    authorized_host,
                )
            ):
                add_endpoint(
                    WebEndpoint(
                        url=service.url,
                        method="GET",
                        discovery_method=(
                            "httpx-service"
                        ),
                    )
                )

        for endpoint in (
            crawl_inventory.endpoints
        ):
            add_endpoint(
                endpoint
            )

        return WebEndpointInventory(
            endpoints=tuple(
                endpoints
            )
        )

    def _tls_inventory(
        self,
        context: dict[str, object],
    ) -> TLSServiceInventory:
        service_inventory = (
            self._service_inventory(
                context
            )
        )

        http_inventory = (
            self._http_inventory(
                context
            )
        )

        https_pairs = {
            (
                service.host
                .strip()
                .lower()
                .rstrip(
                    "."
                ),
                service.port,
            )
            for service
            in http_inventory.services
            if (
                service.scheme
                .strip()
                .lower()
                == "https"
            )
        }

        selected: list[
            TLSService
        ] = []

        seen: set[
            tuple[
                str,
                str,
                int,
            ]
        ] = set()

        for service in (
            service_inventory.services
        ):
            host_key = (
                service.host
                .strip()
                .lower()
                .rstrip(
                    "."
                )
            )

            if (
                not service.tls_hint
                and (
                    host_key,
                    service.port,
                )
                not in https_pairs
            ):
                continue

            key = (
                host_key,
                service.ip,
                service.port,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            selected.append(
                TLSService(
                    host=service.host,
                    ip=service.ip,
                    port=service.port,
                )
            )

        return TLSServiceInventory(
            services=tuple(
                selected
            )
        )

    def _load_nuclei_snapshot(
        self,
        snapshot_id: UUID,
    ) -> NucleiTemplateSnapshot:
        if (
            self.nuclei_snapshot_loader
            is not None
        ):
            snapshot = (
                self.nuclei_snapshot_loader(
                    snapshot_id
                )
            )
        else:
            with (
                self.session_factory()
                as database
            ):
                snapshot = database.get(
                    NucleiTemplateSnapshot,
                    snapshot_id,
                )

        if snapshot is None:
            raise RuntimeError(
                "The immutable Nuclei "
                "template snapshot no "
                "longer exists."
            )

        return snapshot

    def _active_confirmation(
        self,
        claim: AssessmentClaim,
    ) -> ActiveAuthorizationConfirmation | None:
        profile = get_assessment_profile(
            claim.profile_name
        )

        if not profile.active_web_testing:
            return None

        if (
            claim.user_id is None
            or claim.active_testing_authorized_at
            is None
            or claim.plan is None
        ):
            raise RuntimeError(
                "Active testing authorization "
                "is incomplete."
            )

        versions = (
            self._require_mapping(
                claim.plan
                .engine_policy_versions,
                name=(
                    "engine policy versions"
                ),
            )
        )

        version = versions.get(
            "authorization"
        )

        if (
            not isinstance(
                version,
                str,
            )
            or not version.strip()
        ):
            raise RuntimeError(
                "The immutable authorization "
                "policy version is missing."
            )

        confirmation = (
            ActiveAuthorizationConfirmation(
                confirmed=True,
                confirmed_by_user_id=(
                    claim.user_id
                ),
                confirmed_at=(
                    claim
                    .active_testing_authorized_at
                ),
                authorization_version=(
                    version
                ),
            )
        )

        validate_active_authorization(
            profile_name=(
                claim.profile_name
            ),
            confirmation=confirmation,
        )

        return confirmation

    # TASK23_INFRASTRUCTURE_EXECUTION

    @staticmethod
    def _infrastructure_state(
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> tuple[
        dict[str, object],
        InfrastructureScopeAuthorization,
    ] | None:
        """Return an explicitly enabled infrastructure authorization."""

        plan = claim.plan

        plan_scope = (
            getattr(
                plan,
                "infrastructure",
                None,
            )
            if plan is not None
            else None
        )

        claim_scope = getattr(
            claim,
            "infrastructure",
            None,
        )

        fallback_scope = (
            claim_scope
            if claim_scope is not None
            else plan_scope
        )

        scope = context.get(
            "infrastructure",
            fallback_scope,
        )

        if scope is None:
            return None

        if not isinstance(
            scope,
            dict,
        ):
            raise RuntimeError(
                "Infrastructure execution requires "
                "a valid immutable scope snapshot."
            )

        if (
            not scope.get(
                "enabled"
            )
            or not scope.get(
                "infrastructure_extension_enabled"
            )
        ):
            return None

        authorization = context.get(
            "infrastructure_authorization"
        )

        if authorization is None:
            authorization = getattr(
                claim,
                "infrastructure_authorization",
                None,
            )

        if (
            authorization is None
            and plan is not None
        ):
            authorization = getattr(
                plan,
                "infrastructure_authorization",
                None,
            )

        if not isinstance(
            authorization,
            InfrastructureScopeAuthorization,
        ):
            raise RuntimeError(
                "Infrastructure execution requires "
                "separate exact IP/CIDR authorization."
            )

        return (
            scope,
            authorization,
        )

    def _validated_infrastructure_addresses(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> tuple[
        tuple[str, ...],
        InfrastructureScopeAuthorization,
    ] | None:
        """Re-resolve and re-check exact infrastructure authorization."""

        state = self._infrastructure_state(
            claim,
            context,
        )

        if state is None:
            return None

        _scope, authorization = state

        current = (
            self._revalidate_resolution(
                claim
            )
        )

        validate_infrastructure_authorization(
            profile_name=(
                claim.profile_name
            ),
            authorization=authorization,
            requested_addresses=current,
        )

        return (
            current,
            authorization,
        )

    def _run_nmap(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        infrastructure = (
            self._validated_infrastructure_addresses(
                claim,
                context,
            )
        )

        profile = get_assessment_profile(
            claim.profile_name
        )

        policy = profile.engines[
            "nmap"
        ]

        if infrastructure is not None:
            current, _authorization = (
                infrastructure
            )

            if len(current) != 1:
                raise RuntimeError(
                    "Infrastructure full TCP discovery "
                    "requires exactly one revalidated "
                    "literal target address."
                )

            return self.nmap_runner(
                target=current[0],
                ports=(),
                full_tcp=True,
                timeout_seconds=(
                    policy.timeout_seconds
                ),
            )

        self._revalidate_resolution(
            claim
        )

        return self.nmap_runner(
            target=claim.target_hostname,
            ports=(
                80,
                443,
            ),
            full_tcp=False,
            timeout_seconds=(
                policy.timeout_seconds
            ),
        )


    def _run_httpx(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        current_addresses = {
            str(
                address
            ).strip()
            for address
            in self._revalidate_resolution(
                claim
            )
        }

        profile = get_assessment_profile(
            claim.profile_name
        )

        policy = profile.engines[
            "httpx"
        ]

        request_rate = (
            self._positive_integer(
                claim.plan.rate_budget,
                "requests_per_second",
                section="rate budget",
            )
        )

        max_output_bytes = (
            self._positive_integer(
                claim.plan.crawl_policy,
                "max_output_bytes",
                section="crawl policy",
            )
        )

        inventory = (
            self._service_inventory(
                context
            )
        )

        if (
            self._infrastructure_state(
                claim,
                context,
            )
            is not None
        ):
            original_addresses = {
                str(
                    address
                ).strip()
                for address
                in claim.plan.resolved_addresses
            }

            verified_web_addresses = (
                current_addresses
                & original_addresses
            )

            inventory = ServiceInventory(
                services=tuple(
                    replace(
                        service,
                        host=claim.target_hostname,
                    )
                    if (
                        str(
                            service.ip
                        ).strip()
                        in verified_web_addresses
                    )
                    else service
                    for service
                    in inventory.services
                )
            )

        return self.httpx_runner(
            inventory=inventory,
            timeout_seconds=(
                policy.timeout_seconds
            ),
            request_rate=(
                request_rate
            ),
            max_output_bytes=(
                max_output_bytes
            ),
        )
    def _run_katana(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        self._revalidate_resolution(
            claim
        )

        profile = get_assessment_profile(
            claim.profile_name
        )

        policy = profile.engines[
            "katana"
        ]

        crawl = claim.plan.crawl_policy

        return self.katana_runner(
            inventory=(
                self._http_inventory(
                    context
                )
            ),
            depth=(
                self._positive_integer(
                    crawl,
                    "depth",
                    section="crawl policy",
                )
            ),
            crawl_duration_seconds=(
                self._positive_integer(
                    crawl,
                    "crawl_duration_seconds",
                    section="crawl policy",
                )
            ),
            request_rate=(
                self._positive_integer(
                    claim.plan.rate_budget,
                    "requests_per_second",
                    section="rate budget",
                )
            ),
            max_response_bytes=(
                self._positive_integer(
                    crawl,
                    "max_response_bytes",
                    section="crawl policy",
                )
            ),
            max_output_bytes=(
                self._positive_integer(
                    crawl,
                    "max_output_bytes",
                    section="crawl policy",
                )
            ),
            timeout_seconds=(
                policy.timeout_seconds
            ),
        )

    def _run_sslyze(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        self._revalidate_resolution(
            claim
        )

        profile = get_assessment_profile(
            claim.profile_name
        )

        return self.sslyze_runner(
            inventory=(
                self._tls_inventory(
                    context
                )
            ),
            timeout_seconds=(
                profile
                .engines[
                    "sslyze"
                ]
                .timeout_seconds
            ),
            max_output_bytes=(
                self._positive_integer(
                    claim.plan.crawl_policy,
                    "max_output_bytes",
                    section="crawl policy",
                )
            ),
        )

    def _run_nuclei(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        infrastructure = (
            self._validated_infrastructure_addresses(
                claim,
                context,
            )
        )

        if infrastructure is None:
            self._revalidate_resolution(
                claim
            )

        snapshot_id = (
            claim.plan
            .nuclei_template_snapshot_id
        )

        if snapshot_id is None:
            raise RuntimeError(
                "Nuclei execution requires "
                "an immutable approved template "
                "snapshot."
            )

        snapshot = (
            self._load_nuclei_snapshot(
                snapshot_id
            )
        )

        targets: list[str] = []
        seen: set[str] = set()

        if infrastructure is not None:
            _current, authorization = (
                infrastructure
            )

            approved_groups: set[str] = set()

            for attribute in (
                "approved_groups",
                "approved_template_groups",
            ):
                values = getattr(
                    snapshot,
                    attribute,
                    (),
                )

                if isinstance(
                    values,
                    (
                        list,
                        tuple,
                        set,
                        frozenset,
                    ),
                ):
                    approved_groups.update(
                        str(value)
                        .strip()
                        .upper()
                        for value in values
                        if str(value).strip()
                    )

            if (
                "BEACON_INFRASTRUCTURE"
                not in approved_groups
            ):
                raise RuntimeError(
                    "Infrastructure Nuclei execution "
                    "requires the approved "
                    "BEACON_INFRASTRUCTURE "
                    "template group."
                )

            nmap_handoff = context.get(
                "nmap"
            )

            if isinstance(
                nmap_handoff,
                ServiceInventory,
            ):
                service_inventory = (
                    nmap_handoff
                )
            else:
                service_inventory = (
                    self._service_inventory(
                        context
                    )
                )

            for service in (
                service_inventory.services
            ):
                transport = (
                    str(
                        service.transport
                    )
                    .strip()
                    .lower()
                )

                if transport != "tcp":
                    continue

                address = (
                    str(
                        service.ip
                    ).strip()
                )

                port = service.port

                if (
                    not address
                    or not isinstance(
                        port,
                        int,
                    )
                    or isinstance(
                        port,
                        bool,
                    )
                    or port < 1
                    or port > 65535
                ):
                    raise RuntimeError(
                        "Infrastructure Nuclei received "
                        "an invalid discovered network "
                        "service."
                    )

                validate_infrastructure_authorization(
                    profile_name=(
                        claim.profile_name
                    ),
                    authorization=authorization,
                    requested_addresses=(
                        address,
                    ),
                )

                target = (
                    f"{address}:{port}"
                )

                if target in seen:
                    continue

                seen.add(
                    target
                )

                targets.append(
                    target
                )

        else:
            inventory = (
                self._authorized_web_inventory(
                    claim,
                    context,
                )
            )

            for endpoint in (
                inventory.endpoints
            ):
                if endpoint.url in seen:
                    continue

                seen.add(
                    endpoint.url
                )

                targets.append(
                    endpoint.url
                )

        profile = get_assessment_profile(
            claim.profile_name
        )

        with TemporaryDirectory(
            prefix="beacon-nuclei-",
        ) as directory:
            target_list = (
                Path(
                    directory
                )
                / "targets.txt"
            )

            target_list.write_text(
                "".join(
                    f"{target}\n"
                    for target
                    in targets
                ),
                encoding="utf-8",
            )

            return self.nuclei_runner(
                snapshot=snapshot,
                template_root=Path(
                    settings
                    .nuclei_template_root
                ),
                target_list_path=(
                    target_list
                ),
                allow_local_network_access=(
                    self._lab_private_allowed(
                        claim.target_hostname
                    )
                ),
                nuclei_binary=(
                    settings.nuclei_binary
                ),
                timeout_seconds=(
                    profile
                    .engines[
                        "nuclei"
                    ]
                    .timeout_seconds
                ),
                max_output_bytes=(
                    settings
                    .nuclei_max_output_bytes
                ),
            )


    def _run_zap(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        self._revalidate_resolution(
            claim
        )

        confirmation = (
            self._active_confirmation(
                claim
            )
        )

        policy = resolve_zap_policy(
            profile_name=(
                claim.profile_name
            ),
            active_confirmation=(
                confirmation
            ),
        )

        if (
            claim.plan
            .zap_policy_version
            != policy.policy_version
        ):
            raise RuntimeError(
                "The resolved ZAP policy "
                "does not match the immutable "
                "assessment plan policy."
            )

        versions = (
            self._require_mapping(
                claim.plan
                .engine_policy_versions,
                name=(
                    "engine policy versions"
                ),
            )
        )

        snapshotted_version = (
            versions.get(
                "zap"
            )
        )

        if (
            snapshotted_version
            != policy.policy_version
        ):
            raise RuntimeError(
                "The immutable ZAP engine "
                "policy version does not match "
                "the resolved locked policy."
            )

        inventory = (
            self._authorized_web_inventory(
                claim,
                context,
            )
        )

        request = ZapAssessmentRequest(
            authorized_host=(
                claim.target_hostname
            ),
            web_inventory=inventory,
            policy_version=(
                policy.policy_version
            ),
            active_scan_enabled=(
                policy.active_scan_enabled
            ),
            active_policy=(
                policy
                if policy.active_scan_enabled
                else None
            ),
            execution_id=(
                str(
                    claim.scan_id
                )
            ),
        )

        client = (
            self.zap_client_factory()
        )

        return client.run_assessment(
            request
        )

    def _run_nikto(
        self,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        self._revalidate_resolution(
            claim
        )

        inventory = (
            self._http_inventory(
                context
            )
        )

        if (
            self.cancellation_service
            is None
        ):
            return self.nikto_runner(
                profile_name=(
                    claim.profile_name
                ),
                inventory=inventory,
            )

        cancellation_service = (
            self.cancellation_service
        )

        def cancellation_callback(
        ) -> bool:
            return bool(
                cancellation_service
                .is_cancel_requested(
                    scan_id=(
                        claim.scan_id
                    )
                )
            )

        return self.nikto_runner(
            profile_name=(
                claim.profile_name
            ),
            inventory=inventory,
            cancellation_callback=(
                cancellation_callback
            ),
        )

    def run(
        self,
        *,
        stage: str,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        if stage == "scope_authorization":
            return (
                self._validate_scope_authorization(
                    claim
                )
            )

        scanner_handlers = {
            "nmap":
                lambda:
                    self._run_nmap(
                        claim,
                        context,
                    ),
            "httpx":
                lambda:
                    self._run_httpx(
                        claim,
                        context,
                    ),
            "katana":
                lambda:
                    self._run_katana(
                        claim,
                        context,
                    ),
            "sslyze":
                lambda:
                    self._run_sslyze(
                        claim,
                        context,
                    ),
            "nuclei":
                lambda:
                    self._run_nuclei(
                        claim,
                        context,
                    ),
            "zap":
                lambda:
                    self._run_zap(
                        claim,
                        context,
                    ),
            "nikto":
                lambda:
                    self._run_nikto(
                        claim,
                        context,
                    ),
        }

        handler = scanner_handlers.get(
            stage
        )

        if handler is not None:
            return handler()

        raise RuntimeError(
            "Engine v2 post-processing "
            f"binding is not complete yet: {stage}."
        )


@dataclass(frozen=True)
class NormalizedDetectionRecord:
    """Scanner-neutral Engine v2 detection before persistence."""

    engine: str
    engine_version: str | None
    rule_id: str | None
    rule_version: str | None

    title: str
    severity: str
    confidence: str | None

    asset_identity: str | None
    affected_service: str | None
    affected_port: int | None
    affected_location: str | None
    affected_parameter: str | None

    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]

    canonical_type: str | None

    description: str | None
    remediation: str | None

    evidence: dict[str, object]
    source_metadata: dict[str, object]
    raw_payload: dict[str, object]


def _json_safe(
    value: object,
) -> object:
    """Convert scanner values to deterministic JSON-safe values."""

    if value is None or isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return value

    if isinstance(
        value,
        bytes,
    ):
        return {
            "encoding":
                "base64",
            "data":
                base64.b64encode(
                    value
                ).decode(
                    "ascii"
                ),
        }

    if isinstance(
        value,
        (
            UUID,
            Path,
        ),
    ):
        return str(
            value
        )

    if isinstance(
        value,
        datetime,
    ):
        return value.isoformat()

    if is_dataclass(
        value
    ):
        return _json_safe(
            asdict(
                value
            )
        )

    if isinstance(
        value,
        dict,
    ):
        return {
            str(
                key
            ):
                _json_safe(
                    item
                )
            for key, item
            in value.items()
        }

    if isinstance(
        value,
        (
            list,
            tuple,
        ),
    ):
        return [
            _json_safe(
                item
            )
            for item in value
        ]

    if isinstance(
        value,
        (
            set,
            frozenset,
        ),
    ):
        return [
            _json_safe(
                item
            )
            for item
            in sorted(
                value,
                key=lambda item: repr(
                    item
                ),
            )
        ]

    attributes = getattr(
        value,
        "__dict__",
        None,
    )

    if isinstance(
        attributes,
        dict,
    ):
        return {
            str(
                key
            ):
                _json_safe(
                    item
                )
            for key, item
            in attributes.items()
            if not str(
                key
            ).startswith(
                "_"
            )
        }

    return str(
        value
    )


def _identifier_tuple(
    candidate: object,
    plural_name: str,
    singular_name: str,
) -> tuple[str, ...]:
    plural = getattr(
        candidate,
        plural_name,
        None,
    )

    if isinstance(
        plural,
        str,
    ):
        plural = (
            plural,
        )

    if isinstance(
        plural,
        (
            list,
            tuple,
            set,
            frozenset,
        ),
    ):
        values = tuple(
            str(
                value
            ).strip()
            for value in plural
            if str(
                value
            ).strip()
        )

        if values:
            return values

    singular = getattr(
        candidate,
        singular_name,
        None,
    )

    if singular is None:
        return ()

    normalized = str(
        singular
    ).strip()

    if not normalized:
        return ()

    return (
        normalized,
    )


def _candidate_payload(
    candidate: object,
) -> dict[str, object]:
    payload = _json_safe(
        candidate
    )

    if isinstance(
        payload,
        dict,
    ):
        return payload

    return {
        "value":
            payload,
    }


def normalize_engine_v2_output(
    engine: str,
    output: object,
) -> tuple[
    NormalizedDetectionRecord,
    ...
]:
    """Normalize scanner-specific candidates into one Engine v2 shape."""

    normalized_engine = (
        engine.strip()
        .lower()
    )

    candidates = getattr(
        output,
        "detections",
        None,
    )

    if candidates is None:
        candidates = getattr(
            output,
            "detection_candidates",
            (),
        )

    if candidates is None:
        candidates = ()

    engine_version = (
        getattr(
            output,
            "tool_version",
            None,
        )
        or getattr(
            output,
            "scanner_version",
            None,
        )
        or getattr(
            output,
            "version",
            None,
        )
    )

    records: list[
        NormalizedDetectionRecord
    ] = []

    for candidate in candidates:
        payload = _candidate_payload(
            candidate
        )

        affected_location = (
            getattr(
                candidate,
                "affected_url",
                None,
            )
            or getattr(
                candidate,
                "matched_at",
                None,
            )
        )

        parsed = urlsplit(
            str(
                affected_location
                or ""
            )
        )

        asset_identity = (
            parsed.hostname
            or getattr(
                candidate,
                "host",
                None,
            )
        )

        service = (
            parsed.scheme
            or getattr(
                candidate,
                "protocol",
                None,
            )
        )

        affected_port = getattr(
            candidate,
            "affected_port",
            None,
        )

        if affected_port is None:
            affected_port = getattr(
                candidate,
                "port",
                None,
            )

        if affected_port is None:
            try:
                affected_port = (
                    parsed.port
                )
            except ValueError:
                affected_port = None

        if (
            affected_port is None
            and parsed.scheme.lower()
            == "https"
        ):
            affected_port = 443

        if (
            affected_port is None
            and parsed.scheme.lower()
            == "http"
        ):
            affected_port = 80

        if (
            normalized_engine
            == "sslyze"
        ):
            service = "tls"

        rule_id = (
            getattr(
                candidate,
                "plugin_id",
                None,
            )
            or getattr(
                candidate,
                "template_id",
                None,
            )
            or getattr(
                candidate,
                "finding_id",
                None,
            )
            or getattr(
                candidate,
                "kind",
                None,
            )
        )

        rule_version = (
            getattr(
                candidate,
                "template_revision_or_digest",
                None,
            )
            or getattr(
                candidate,
                "rule_version",
                None,
            )
        )

        title = (
            getattr(
                candidate,
                "title",
                None,
            )
            or getattr(
                candidate,
                "template_name",
                None,
            )
            or getattr(
                candidate,
                "message",
                None,
            )
            or getattr(
                candidate,
                "kind",
                None,
            )
            or rule_id
            or f"{normalized_engine} detection"
        )

        severity = (
            getattr(
                candidate,
                "severity",
                None,
            )
            or getattr(
                candidate,
                "template_severity",
                None,
            )
            or "informational"
        )

        severity = str(
            severity
        ).strip().lower()

        if severity == "info":
            severity = (
                "informational"
            )

        confidence = getattr(
            candidate,
            "confidence",
            None,
        )

        cve_ids = _identifier_tuple(
            candidate,
            "cve_ids",
            "cve_id",
        )

        cwe_ids = _identifier_tuple(
            candidate,
            "cwe_ids",
            "cwe_id",
        )

        affected_parameter = (
            getattr(
                candidate,
                "parameter",
                None,
            )
            or getattr(
                candidate,
                "affected_parameter",
                None,
            )
        )

        description = (
            getattr(
                candidate,
                "description",
                None,
            )
            or getattr(
                candidate,
                "message",
                None,
            )
        )

        remediation = getattr(
            candidate,
            "remediation",
            None,
        )

        evidence_value = getattr(
            candidate,
            "evidence",
            None,
        )

        if isinstance(
            evidence_value,
            dict,
        ):
            evidence = _json_safe(
                evidence_value
            )
        elif evidence_value is not None:
            evidence = {
                "value":
                    _json_safe(
                        evidence_value
                    ),
            }
        else:
            evidence = {
                "candidate":
                    payload,
            }

        canonical_type: str | None = (
            None
        )

        source_metadata = dict(
            payload
        )

        if normalized_engine == "sslyze":
            canonical_type = "tls"

            source_metadata[
                "weakness"
            ] = str(
                getattr(
                    candidate,
                    "kind",
                    rule_id
                    or title,
                )
            )

        elif (
            normalized_engine == "zap"
            and "header"
            in str(
                title
            ).lower()
        ):
            canonical_type = (
                "http_header"
            )

            # TASK24_ZAP_HEADER_NORMALIZATION
            #
            # Preserve the existing ZAP HTTP-header
            # classification, but only assign canonical
            # missing-header identity when the scanner title
            # explicitly states that a named header is
            # missing, not set, or not present.
            zap_title = str(
                title
                or ""
            ).strip()

            normalized_zap_title = (
                zap_title.lower()
            )

            missing_header_suffixes = (
                " header missing",
                " header not set",
                " header not present",
            )

            header_name = None

            for suffix in (
                missing_header_suffixes
            ):
                if normalized_zap_title.endswith(
                    suffix
                ):
                    header_name = (
                        zap_title[
                            : -len(suffix)
                        ]
                        .strip()
                        .strip(":")
                        .strip()
                    )
                    break

            if header_name:
                source_metadata[
                    "header_name"
                ] = header_name

                source_metadata[
                    "weakness"
                ] = "missing"

            else:
                source_metadata[
                    "weakness"
                ] = (
                    str(
                        rule_id
                        or title
                    )
                )

        else:
            source_metadata[
                "weakness"
            ] = str(
                rule_id
                or title
            )

        method = (
            getattr(
                candidate,
                "http_method",
                None,
            )
            or getattr(
                candidate,
                "method",
                None,
            )
        )

        if method is not None:
            source_metadata[
                "http_method"
            ] = str(
                method
            )

        # TASK24_NIKTO_HEADER_NORMALIZATION
        #
        # Nikto emits explicit human-readable security-header
        # observations rather than structured canonical metadata.
        # Only classify deterministic missing-header language; do
        # not use title similarity or broad fuzzy matching.
        if (
            normalized_engine == "nikto"
            and canonical_type is None
        ):
            nikto_message = str(
                getattr(
                    candidate,
                    "message",
                    "",
                )
                or ""
            ).strip()

            normalized_message = (
                nikto_message.lower()
            )

            missing_header_suffixes = (
                " header is not present.",
                " header is not present",
                " header is missing.",
                " header is missing",
            )

            header_name = None

            for suffix in (
                missing_header_suffixes
            ):
                if normalized_message.endswith(
                    suffix
                ):
                    header_name = (
                        nikto_message[
                            : -len(suffix)
                        ]
                        .strip()
                        .strip(":")
                        .strip()
                    )
                    break

            if header_name:
                canonical_type = (
                    "http_header"
                )

                source_metadata[
                    "header_name"
                ] = header_name

                source_metadata[
                    "weakness"
                ] = "missing"

        if canonical_type is not None:
            source_metadata[
                "canonical_type"
            ] = canonical_type

        records.append(
            NormalizedDetectionRecord(
                engine=(
                    normalized_engine
                ),
                engine_version=(
                    str(
                        engine_version
                    )
                    if engine_version
                    is not None
                    else None
                ),
                rule_id=(
                    str(
                        rule_id
                    )
                    if rule_id
                    is not None
                    else None
                ),
                rule_version=(
                    str(
                        rule_version
                    )
                    if rule_version
                    is not None
                    else None
                ),
                title=str(
                    title
                ),
                severity=severity,
                confidence=(
                    str(
                        confidence
                    ).strip().lower()
                    if confidence
                    is not None
                    else None
                ),
                asset_identity=(
                    str(
                        asset_identity
                    )
                    if asset_identity
                    is not None
                    else None
                ),
                affected_service=(
                    str(
                        service
                    ).lower()
                    if service
                    else None
                ),
                affected_port=(
                    int(
                        affected_port
                    )
                    if affected_port
                    is not None
                    else None
                ),
                affected_location=(
                    str(
                        affected_location
                    )
                    if affected_location
                    else None
                ),
                affected_parameter=(
                    str(
                        affected_parameter
                    )
                    if affected_parameter
                    is not None
                    else None
                ),
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                canonical_type=(
                    canonical_type
                ),
                description=(
                    str(
                        description
                    )
                    if description
                    is not None
                    else None
                ),
                remediation=(
                    str(
                        remediation
                    )
                    if remediation
                    is not None
                    else None
                ),
                evidence=(
                    evidence
                    if isinstance(
                        evidence,
                        dict,
                    )
                    else {
                        "value":
                            evidence,
                    }
                ),
                source_metadata=(
                    source_metadata
                ),
                raw_payload=payload,
            )
        )

    return tuple(
        records
    )


class PersistedPostProcessingRunner:
    """Persist Engine v2 normalization, correlation, and coverage."""

    def __init__(
        self,
        *,
        session_factory=SessionLocal,
        clock=_utc_now,
    ) -> None:
        self.session_factory = (
            session_factory
        )
        self.clock = clock

    @staticmethod
    def _correlation_input(
        detection: Detection,
    ) -> CorrelationInput:
        metadata = (
            detection.source_metadata
            if isinstance(
                detection.source_metadata,
                dict,
            )
            else {}
        )

        canonical_type = (
            metadata.get(
                "canonical_type"
            )
        )

        return CorrelationInput(
            detection_id=str(
                detection.id
            ),
            engine=(
                detection.engine
            ),
            rule_id=(
                detection.rule_id
            ),
            title=(
                detection.title
            ),
            canonical_type=(
                str(
                    canonical_type
                )
                if canonical_type
                is not None
                else None
            ),
            asset_identity=(
                detection.asset_identity
            ),
            affected_service=(
                detection.affected_service
            ),
            affected_port=(
                detection.affected_port
            ),
            affected_location=(
                detection.affected_location
            ),
            affected_parameter=(
                detection.affected_parameter
            ),
            cve_ids=tuple(
                detection.cve_ids
                or ()
            ),
            cwe_ids=tuple(
                detection.cwe_ids
                or ()
            ),
            source_metadata=(
                metadata
            ),
        )

    def _persist_normalization(
        self,
        *,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> dict[str, object]:
        persisted_ids: list[
            str
        ] = []

        with self.session_factory() as database:
            for engine in ENGINE_ORDER:
                output = context.get(
                    engine
                )

                if output is None:
                    continue

                tool_run = database.scalar(
                    select(
                        ScanToolRun
                    )
                    .where(
                        ScanToolRun.scan_id
                        == claim.scan_id,
                        ScanToolRun.tool_name
                        == engine,
                    )
                    .order_by(
                        ScanToolRun
                        .created_at
                        .desc()
                    )
                    .limit(
                        1
                    )
                )

                records = (
                    normalize_engine_v2_output(
                        engine,
                        output,
                    )
                )

                for record in records:
                    raw_evidence = (
                        RawScannerEvidence(
                            scan_id=(
                                claim.scan_id
                            ),
                            tool_run_id=(
                                tool_run.id
                                if tool_run
                                is not None
                                else None
                            ),
                            engine=(
                                record.engine
                            ),
                            engine_version=(
                                record
                                .engine_version
                            ),
                            rule_id=(
                                record.rule_id
                            ),
                            rule_version=(
                                record
                                .rule_version
                            ),
                            payload=(
                                _json_safe(
                                    record
                                    .raw_payload
                                )
                            ),
                        )
                    )

                    database.add(
                        raw_evidence
                    )

                    database.flush()

                    detection = Detection(
                        scan_id=(
                            claim.scan_id
                        ),
                        tool_run_id=(
                            tool_run.id
                            if tool_run
                            is not None
                            else None
                        ),
                        raw_evidence_id=(
                            raw_evidence.id
                        ),
                        engine=(
                            record.engine
                        ),
                        engine_version=(
                            record
                            .engine_version
                        ),
                        rule_id=(
                            record.rule_id
                        ),
                        rule_version=(
                            record
                            .rule_version
                        ),
                        title=(
                            record.title
                        ),
                        severity=(
                            record.severity
                        ),
                        confidence=(
                            record.confidence
                        ),
                        asset_identity=(
                            record
                            .asset_identity
                        ),
                        affected_service=(
                            record
                            .affected_service
                        ),
                        affected_port=(
                            record
                            .affected_port
                        ),
                        affected_location=(
                            record
                            .affected_location
                        ),
                        affected_parameter=(
                            record
                            .affected_parameter
                        ),
                        cve_ids=list(
                            record.cve_ids
                        ),
                        cwe_ids=list(
                            record.cwe_ids
                        ),
                        evidence_strength=(
                            record.confidence
                        ),
                        source_metadata=(
                            _json_safe(
                                record
                                .source_metadata
                            )
                        ),
                    )

                    database.add(
                        detection
                    )

                    database.flush()

                    persisted_ids.append(
                        str(
                            detection.id
                        )
                    )

            database.commit()

        return {
            "detection_ids":
                persisted_ids,
            "detection_count":
                len(
                    persisted_ids
                ),
        }

    def _persist_correlation(
        self,
        *,
        claim: AssessmentClaim,
    ) -> dict[str, object]:
        finding_ids: list[
            str
        ] = []

        decision_count = 0

        with self.session_factory() as database:
            detections = list(
                database.scalars(
                    select(
                        Detection
                    )
                    .where(
                        Detection.scan_id
                        == claim.scan_id
                    )
                    .order_by(
                        Detection.created_at.asc(),
                        Detection.id.asc(),
                    )
                ).all()
            )

            for index, detection in enumerate(
                detections
            ):
                matched_finding_id = None

                for previous in detections[
                    :index
                ]:
                    result = (
                        decide_correlation(
                            self._correlation_input(
                                previous
                            ),
                            self._correlation_input(
                                detection
                            ),
                        )
                    )

                    decision = (
                        CorrelationDecision(
                            scan_id=(
                                claim.scan_id
                            ),
                            detection_a_id=(
                                previous.id
                            ),
                            detection_b_id=(
                                detection.id
                            ),
                            strategy_version=(
                                result
                                .strategy_version
                            ),
                            decision=(
                                result.decision
                            ),
                            reason=(
                                result.reason
                            ),
                            candidate_identity=(
                                result
                                .candidate_identity
                            ),
                            confidence=(
                                result.confidence
                            ),
                            details=(
                                _json_safe(
                                    result.details
                                )
                            ),
                        )
                    )

                    database.add(
                        decision
                    )

                    decision_count += 1

                    if (
                        result.decision
                        == "merge"
                        and previous
                        .finding_id
                        is not None
                    ):
                        matched_finding_id = (
                            previous
                            .finding_id
                        )

                        break

                if matched_finding_id is not None:
                    detection.finding_id = (
                        matched_finding_id
                    )
                    continue

                now = self.clock()

                fingerprint_source = "|".join(
                    (
                        detection.engine
                        or "",
                        detection.rule_id
                        or "",
                        detection.asset_identity
                        or "",
                        detection.affected_service
                        or "",
                        str(
                            detection
                            .affected_port
                            or ""
                        ),
                        detection.affected_location
                        or "",
                        detection.affected_parameter
                        or "",
                    )
                )

                fingerprint = (
                    hashlib.sha256(
                        fingerprint_source
                        .encode(
                            "utf-8"
                        )
                    ).hexdigest()
                )

                metadata = (
                    detection.source_metadata
                    if isinstance(
                        detection
                        .source_metadata,
                        dict,
                    )
                    else {}
                )

                finding = Finding(
                    scan_id=(
                        claim.scan_id
                    ),
                    target_id=(
                        claim.target_id
                    ),
                    tool_run_id=(
                        detection
                        .tool_run_id
                    ),
                    tool_name=(
                        detection.engine
                    ),
                    external_finding_id=(
                        detection.rule_id
                    ),
                    title=(
                        detection.title
                    ),
                    description=(
                        str(
                            metadata.get(
                                "description"
                            )
                        )
                        if metadata.get(
                            "description"
                        )
                        is not None
                        else None
                    ),
                    severity=(
                        detection.severity
                    ),
                    confidence=(
                        detection.confidence
                    ),
                    affected_url=(
                        detection
                        .affected_location
                    ),
                    affected_port=(
                        detection
                        .affected_port
                    ),
                    evidence={
                        "raw_evidence_id":
                            (
                                str(
                                    detection
                                    .raw_evidence_id
                                )
                                if detection
                                .raw_evidence_id
                                is not None
                                else None
                            ),
                        "source_metadata":
                            _json_safe(
                                metadata
                            ),
                    },
                    remediation=(
                        str(
                            metadata.get(
                                "remediation"
                            )
                        )
                        if metadata.get(
                            "remediation"
                        )
                        is not None
                        else None
                    ),
                    cwe_id=(
                        (
                            detection
                            .cwe_ids
                            or [
                            ]
                        )[0]
                        if detection
                        .cwe_ids
                        else None
                    ),
                    fingerprint=(
                        fingerprint
                    ),
                    asset_identity=(
                        detection
                        .asset_identity
                    ),
                    canonical_type=(
                        str(
                            metadata.get(
                                "canonical_type"
                            )
                        )
                        if metadata.get(
                            "canonical_type"
                        )
                        is not None
                        else None
                    ),
                    cve_ids=(
                        detection.cve_ids
                    ),
                    cwe_ids=(
                        detection.cwe_ids
                    ),
                    affected_service=(
                        detection
                        .affected_service
                    ),
                    affected_location=(
                        detection
                        .affected_location
                    ),
                    affected_parameter=(
                        detection
                        .affected_parameter
                    ),
                    first_seen=now,
                    last_seen=now,
                    source_count=1,
                    occurrence_count=1,
                )

                database.add(
                    finding
                )

                database.flush()

                detection.finding_id = (
                    finding.id
                )

                occurrence = (
                    FindingOccurrence(
                        finding_id=(
                            finding.id
                        ),
                        scan_id=(
                            claim.scan_id
                        ),
                        state="observed",
                        observed_at=now,
                    )
                )

                database.add(
                    occurrence
                )

                finding_ids.append(
                    str(
                        finding.id
                    )
                )

            database.commit()

        return {
            "finding_ids":
                finding_ids,
            "finding_count":
                len(
                    finding_ids
                ),
            "correlation_decision_count":
                decision_count,
        }

    def _persist_coverage(
        self,
        *,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> dict[str, object]:
        nmap_output = context.get(
            "nmap"
        )

        service_inventory = getattr(
            nmap_output,
            "service_inventory",
            None,
        )

        discovered_services = tuple(
            getattr(
                service_inventory,
                "services",
                (),
            )
            or ()
        )

        http_output = context.get(
            "httpx"
        )

        http_services = tuple(
            getattr(
                http_output,
                "services",
                (),
            )
            or ()
        )

        crawl_output = context.get(
            "katana"
        )

        endpoints = tuple(
            getattr(
                crawl_output,
                "endpoints",
                (),
            )
            or ()
        )

        tls_output = context.get(
            "sslyze"
        )

        tls_servers = tuple(
            getattr(
                tls_output,
                "servers",
                (),
            )
            or ()
        )

        http_services_discovered = len(
            [
                service
                for service
                in discovered_services
                if (
                    str(
                        getattr(
                            service,
                            "service_name",
                            "",
                        )
                    ).lower()
                    in {
                        "http",
                        "https",
                        "http-proxy",
                        "ssl/http",
                    }
                    or getattr(
                        service,
                        "port",
                        None,
                    )
                    in {
                        80,
                        443,
                        8080,
                        8443,
                    }
                )
            ]
        )

        http_services_discovered = max(
            http_services_discovered,
            len(
                http_services
            ),
        )

        http_services_assessed = min(
            len(
                http_services
            ),
            http_services_discovered,
        )

        urls_discovered = len(
            endpoints
        )

        urls_authorized = (
            urls_discovered
        )

        web_assessment_present = any(
            context.get(
                engine
            )
            is not None
            for engine in (
                "nuclei",
                "zap",
                "nikto",
            )
        )

        urls_assessed = (
            urls_authorized
            if web_assessment_present
            else 0
        )

        tls_services_discovered = len(
            [
                service
                for service
                in discovered_services
                if (
                    bool(
                        getattr(
                            service,
                            "tls_hint",
                            False,
                        )
                    )
                    or getattr(
                        service,
                        "port",
                        None,
                    )
                    in {
                        443,
                        8443,
                    }
                )
            ]
        )

        tls_services_discovered = max(
            tls_services_discovered,
            len(
                tls_servers
            ),
        )

        tls_services_assessed = min(
            len(
                tls_servers
            ),
            tls_services_discovered,
        )

        with self.session_factory() as database:
            tool_runs = list(
                database.scalars(
                    select(
                        ScanToolRun
                    )
                    .where(
                        ScanToolRun.scan_id
                        == claim.scan_id
                    )
                    .order_by(
                        ScanToolRun
                        .created_at
                        .desc()
                    )
                ).all()
            )

            latest_by_engine: dict[
                str,
                ScanToolRun,
            ] = {}

            for tool_run in tool_runs:
                latest_by_engine.setdefault(
                    tool_run.tool_name,
                    tool_run,
                )

            valid_statuses = {
                "completed",
                "failed",
                "timed_out",
                "skipped",
                "cancelled",
                "interrupted",
            }

            engine_states: list[
                EngineCoverageState
            ] = []

            for engine in ENGINE_ORDER:
                tool_run = (
                    latest_by_engine.get(
                        engine
                    )
                )

                if tool_run is None:
                    continue

                status = str(
                    tool_run.status
                ).lower()

                if status not in valid_statuses:
                    status = (
                        "interrupted"
                    )

                limitation = None

                if status != "completed":
                    limitation = (
                        tool_run
                        .failure_message
                        or tool_run
                        .error_message
                        or tool_run
                        .skipped_reason
                    )

                engine_states.append(
                    EngineCoverageState(
                        engine=engine,
                        status=status,
                        limitation=(
                            limitation
                        ),
                    )
                )

            coverage = calculate_coverage(
                http_services_discovered=(
                    http_services_discovered
                ),
                http_services_assessed=(
                    http_services_assessed
                ),
                urls_discovered=(
                    urls_discovered
                ),
                urls_authorized=(
                    urls_authorized
                ),
                urls_assessed=urls_assessed,
                tls_services_discovered=(
                    tls_services_discovered
                ),
                tls_services_assessed=(
                    tls_services_assessed
                ),
                engines=tuple(
                    engine_states
                ),
            )

            detections = list(
                database.scalars(
                    select(
                        Detection
                    )
                    .where(
                        Detection.scan_id
                        == claim.scan_id
                    )
                ).all()
            )

            contributions: list[
                EngineContributionInput
            ] = []

            for engine in ENGINE_ORDER:
                engine_detections = [
                    detection
                    for detection
                    in detections
                    if detection.engine
                    == engine
                ]

                canonical_ids = tuple(
                    sorted(
                        {
                            str(
                                detection
                                .finding_id
                            )
                            for detection
                            in engine_detections
                            if detection
                            .finding_id
                            is not None
                        }
                    )
                )

                discovery_items = 0

                if engine == "nmap":
                    discovery_items = len(
                        discovered_services
                    )
                elif engine == "httpx":
                    discovery_items = len(
                        http_services
                    )
                elif engine == "katana":
                    discovery_items = len(
                        endpoints
                    )
                elif engine == "sslyze":
                    discovery_items = len(
                        tls_servers
                    )

                contributions.append(
                    EngineContributionInput(
                        engine=engine,
                        discovery_items=(
                            discovery_items
                        ),
                        detections_generated=len(
                            engine_detections
                        ),
                        canonical_finding_ids=(
                            canonical_ids
                        ),
                    )
                )

            engine_contribution = (
                calculate_engine_contribution(
                    contributions
                )
            )

        return {
            "coverage":
                _json_safe(
                    coverage
                ),
            "engine_contribution":
                _json_safe(
                    engine_contribution
                ),
        }

    def run(
        self,
        *,
        stage: str,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        if stage == "normalization":
            return (
                self._persist_normalization(
                    claim=claim,
                    context=context,
                )
            )

        if stage == "correlation":
            return (
                self._persist_correlation(
                    claim=claim,
                )
            )

        if stage == "coverage":
            return (
                self._persist_coverage(
                    claim=claim,
                    context=context,
                )
            )

        raise RuntimeError(
            "Unsupported Engine v2 "
            "post-processing stage: "
            f"{stage}."
        )


class ProductionPipelineRunner:
    """Dispatch scanner and persisted post-processing stages."""

    def __init__(
        self,
        *,
        scanner_runner: StageRunner,
        post_processor: StageRunner,
    ) -> None:
        self.scanner_runner = (
            scanner_runner
        )
        self.post_processor = (
            post_processor
        )

    def run(
        self,
        *,
        stage: str,
        claim: AssessmentClaim,
        context: dict[str, object],
    ) -> object:
        if stage in POST_PROCESSING_STAGES:
            return self.post_processor.run(
                stage=stage,
                claim=claim,
                context=context,
            )

        return self.scanner_runner.run(
            stage=stage,
            claim=claim,
            context=context,
        )


def run_persisted_assessment_v2(
    scan_id: UUID,
) -> dict[str, object]:
    """Execute one persisted Engine v2 assessment."""

    store = DatabaseOrchestrationStore()

    cancellation_service = (
        AssessmentCancellationService()
    )

    scanner_runner = (
        ProductionStageRunner(
            cancellation_service=(
                cancellation_service
            ),
        )
    )

    post_processor = (
        PersistedPostProcessingRunner()
    )

    pipeline_runner = (
        ProductionPipelineRunner(
            scanner_runner=(
                scanner_runner
            ),
            post_processor=(
                post_processor
            ),
        )
    )

    orchestrator = (
        AssessmentOrchestrator(
            store=store,
            runner=(
                pipeline_runner
            ),
            cancellation_service=(
                cancellation_service
            ),
        )
    )

    return orchestrator.run(
        scan_id=scan_id,
    ).to_dict()
