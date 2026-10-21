from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

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
from app.models.target import Target
from app.models.user import User
from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
)
from app.routers import scans as scan_router


@compiles(JSONB, "sqlite")
def compile_jsonb_for_sqlite(
    _type,
    _compiler,
    **_kwargs,
):
    return "JSON"


class TestAssessmentAPI:
    def setup_method(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={
                "check_same_thread":
                    False,
            },
            poolclass=StaticPool,
        )

        User.__table__.create(
            self.engine
        )
        Organization.__table__.create(
            self.engine
        )
        OrganizationMembership.__table__.create(
            self.engine
        )

        Target.__table__.create(
            self.engine
        )

        NucleiTemplateSnapshot.__table__.create(
            self.engine
        )

        Scan.__table__.create(
            self.engine
        )

        AssessmentScanPlan.__table__.create(
            self.engine
        )

        InfrastructureAuthorization.__table__.create(
            self.engine
        )

        AuditLog.__table__.create(
            self.engine
        )

        self.database = Session(
            self.engine,
            expire_on_commit=False,
        )

        self.user = User(
            email="assessment-user@example.com",
            full_name="Assessment User",
            password_hash="not-used",
            role="user",
            is_active=True,
            is_email_verified=True,
        )

        self.demo_user = User(
            email="demo@beacon.example.com",
            full_name="BEACON Demo",
            password_hash="not-used",
            role="demo",
            is_active=True,
            is_email_verified=False,
        )

        self.database.add_all(
            [
                self.user,
                self.demo_user,
            ]
        )

        self.database.flush()

        self.organization, _ = (
            create_personal_organization(
                self.database,
                self.user,
                role=OrganizationRole.ADMIN,
                name="Assessment Workspace",
            )
        )

        self.demo_organization, _ = (
            create_personal_organization(
                self.database,
                self.demo_user,
                role=OrganizationRole.ANALYST,
                name="Demo Workspace",
            )
        )


        now = datetime.now(
            timezone.utc
        )

        expires_at = (
            now
            + timedelta(
                days=30
            )
        )

        self.target = Target(
            organization_id=self.organization.id,
            user_id=self.user.id,
            original_url=(
                "https://portal.example.com/"
            ),
            normalized_url=(
                "https://portal.example.com/"
            ),
            hostname="portal.example.com",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=now,
            verification_expires_at=(
                expires_at
            ),
        )

        self.demo_target = Target(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            original_url="http://lab-target/",
            normalized_url="http://lab-target/",
            hostname="lab-target",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=now,
            verification_expires_at=(
                expires_at
            ),
        )

        self.database.add_all(
            [
                self.target,
                self.demo_target,
            ]
        )

        self.database.flush()

        from app.assessment.nuclei_policy import (
            NucleiPolicyGroup,
            NucleiTemplateDefinition,
            build_nuclei_template_snapshot,
            resolve_nuclei_policy,
        )

        template = (
            NucleiTemplateDefinition(
                template_id=(
                    "http-missing-security-headers"
                ),
                template_revision_or_digest=(
                    "7f45803f73ac6810"
                    "b9b302df6be2c472"
                    "a82d9164a7807328"
                    "614efa83e6eac275"
                ),
                template_source=(
                    "projectdiscovery/"
                    "nuclei-templates"
                ),
                template_path=(
                    "http/misconfiguration/"
                    "http-missing-security-"
                    "headers.yaml"
                ),
                template_severity="info",
                template_tags=(
                    "misconfig",
                    "headers",
                    "generic",
                    "vuln",
                ),
                protocol="http",
                policy_group=(
                    NucleiPolicyGroup
                    .BEACON_SAFE
                ),
                approved_profiles=(
                    "quick",
                    "standard",
                    "deep",
                ),
                approved=True,
            )
        )

        snapshots = []

        for (
            snapshot_profile,
            infrastructure_authorized,
        ) in (
            (
                "quick",
                False,
            ),
            (
                "standard",
                False,
            ),
            (
                "deep",
                False,
            ),
            (
                "deep",
                True,
            ),
        ):
            policy = (
                resolve_nuclei_policy(
                    profile=(
                        snapshot_profile
                    ),
                    infrastructure_authorized=(
                        infrastructure_authorized
                    ),
                )
            )

            snapshots.append(
                build_nuclei_template_snapshot(
                    policy=policy,
                    nuclei_version=(
                        "3.11.1"
                    ),
                    template_source=(
                        "projectdiscovery/"
                        "nuclei-templates"
                    ),
                    template_source_revision=(
                        "83234ce456da3e90"
                        "dda86dfbc5e605e6"
                        "4a846df3"
                    ),
                    templates=(
                        template,
                    ),
                )
            )

        self.database.add_all(
            snapshots
        )

        self.database.commit()

    @pytest.mark.parametrize(
        "profile",
        (
            "quick",
            "standard",
            "deep",
        ),
    )
    def test_builder_native_nuclei_snapshot_is_selected_for_assessment_profile(
        self,
        profile,
    ):
        from app.assessment.nuclei_policy import (
            NucleiPolicyGroup,
            NucleiTemplateDefinition,
            build_nuclei_template_snapshot,
            resolve_nuclei_policy,
        )
        from app.models.nuclei_template_snapshot import (
            NucleiTemplateSnapshot,
        )
        from app.models.assessment_plan import (
            AssessmentScanPlan,
        )
        from app.routers import (
            assessments as assessment_router,
        )

        existing_snapshots = list(
            self.database.scalars(
                select(
                    NucleiTemplateSnapshot
                )
            ).all()
        )

        for snapshot in existing_snapshots:
            self.database.delete(
                snapshot
            )

        self.database.flush()

        template = (
            NucleiTemplateDefinition(
                template_id=(
                    "http-missing-security-headers"
                ),
                template_revision_or_digest=(
                    "7f45803f73ac6810"
                    "b9b302df6be2c472"
                    "a82d9164a7807328"
                    "614efa83e6eac275"
                ),
                template_source=(
                    "projectdiscovery/"
                    "nuclei-templates"
                ),
                template_path=(
                    "http/misconfiguration/"
                    "http-missing-security-"
                    "headers.yaml"
                ),
                template_severity="info",
                template_tags=(
                    "misconfig",
                    "headers",
                    "generic",
                    "vuln",
                ),
                protocol="http",
                policy_group=(
                    NucleiPolicyGroup
                    .BEACON_SAFE
                ),
                approved_profiles=(
                    "quick",
                    "standard",
                    "deep",
                ),
                approved=True,
            )
        )

        snapshots_by_profile = {}

        for candidate_profile in (
            "quick",
            "standard",
            "deep",
        ):
            policy = (
                resolve_nuclei_policy(
                    profile=(
                        candidate_profile
                    ),
                    infrastructure_authorized=(
                        False
                    ),
                )
            )

            snapshot = (
                build_nuclei_template_snapshot(
                    policy=policy,
                    nuclei_version=(
                        "3.11.1"
                    ),
                    template_source=(
                        "projectdiscovery/"
                        "nuclei-templates"
                    ),
                    template_source_revision=(
                        "83234ce456da3e90"
                        "dda86dfbc5e605e6"
                        "4a846df3"
                    ),
                    templates=(
                        template,
                    ),
                )
            )

            self.database.add(
                snapshot
            )

            self.database.flush()

            snapshots_by_profile[
                candidate_profile
            ] = snapshot

        self.database.commit()

        expected_snapshot = (
            snapshots_by_profile[
                profile
            ]
        )

        request = self._request(
            target_id=self.target.id,
            profile=profile,
            active_testing_confirmed=(
                profile
                in {
                    "standard",
                    "deep",
                }
            ),
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            return_value=[
                "203.0.113.10",
            ],
        ):
            with patch.object(
                assessment_router
                .run_assessment_v2,
                "delay",
                return_value=(
                    SimpleNamespace(
                        id=(
                            "task25-native-"
                            f"{profile}"
                        ),
                    )
                ),
            ):
                scan = (
                    assessment_router
                    .create_assessment(
                        request,
                        self.user,
                        self.database,
                    )
                )

        plan = self.database.scalar(
            select(
                AssessmentScanPlan
            ).where(
                AssessmentScanPlan
                .scan_id
                == scan.id
            )
        )

        assert plan is not None

        assert (
            plan
            .nuclei_template_snapshot_id
            == expected_snapshot.id
        )

        assert (
            plan
            .engine_policy_versions[
                "nuclei"
            ]
            == "nuclei-policy-v1"
        )

        assert (
            expected_snapshot
            .approved_groups
            == [
                group.value
                for group
                in resolve_nuclei_policy(
                    profile=profile,
                    infrastructure_authorized=(
                        False
                    ),
                ).allowed_groups
            ]
        )


    def teardown_method(self):
        self.database.rollback()
        self.database.close()
        self.engine.dispose()

    @staticmethod
    def _request(
        *,
        target_id,
        profile,
        active_testing_confirmed=False,
        infrastructure=None,
    ):
        from app.schemas.assessments import (
            AssessmentCreate,
        )

        return AssessmentCreate(
            target_id=target_id,
            profile=profile,
            assessment_mode="web",
            active_testing_confirmed=(
                active_testing_confirmed
            ),
            infrastructure=infrastructure,
        )

    @staticmethod
    def _infra_request(
        *,
        authorized_ips,
        authorized_cidrs=None,
        broad=True,
        active=True,
        exclude_third_party=True,
    ):
        from app.schemas.assessments import (
            InfrastructureAuthorizationRequest,
        )

        return InfrastructureAuthorizationRequest(
            authorized_ips=(
                authorized_ips
            ),
            authorized_cidrs=(
                authorized_cidrs
                or []
            ),
            broad_port_scan_allowed=(
                broad
            ),
            network_active_checks_allowed=(
                active
            ),
            third_party_infrastructure_attested_excluded=(
                exclude_third_party
            ),
        )

    def test_profile_metadata_exposes_quick_standard_deep(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        result = (
            assessment_router
            .list_assessment_profiles(
                self.user
            )
        )

        by_name = {
            item.name:
                item
            for item in result
        }

        assert set(
            by_name
        ) == {
            "quick",
            "standard",
            "deep",
        }

        assert (
            by_name[
                "quick"
            ].active_web_testing
            is False
        )

        assert (
            by_name[
                "standard"
            ].active_web_testing
            is True
        )

        assert (
            by_name[
                "deep"
            ].infrastructure_extension_allowed
            is True
        )

        assert (
            by_name[
                "standard"
            ].active_authorization_version
        )

    def test_standard_requires_explicit_active_authorization(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        request = self._request(
            target_id=self.target.id,
            profile="standard",
            active_testing_confirmed=False,
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            return_value=[
                "203.0.113.10",
            ],
        ):
            with patch.object(
                assessment_router
                .run_assessment_v2,
                "delay",
            ) as delay:
                with pytest.raises(
                    HTTPException
                ) as exc:
                    assessment_router.create_assessment(
                        request,
                        self.user,
                        self.database,
                    )

        assert (
            exc.value.status_code
            == 403
        )

        delay.assert_not_called()

    def test_quick_creation_snapshots_nuclei_and_zap(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        request = self._request(
            target_id=self.target.id,
            profile="quick",
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            return_value=[
                "203.0.113.10",
            ],
        ):
            with patch.object(
                assessment_router
                .run_assessment_v2,
                "delay",
                return_value=(
                    SimpleNamespace(
                        id="task18-quick",
                    )
                ),
            ):
                scan = (
                    assessment_router
                    .create_assessment(
                        request,
                        self.user,
                        self.database,
                    )
                )

        assert scan.profile == "quick"
        assert scan.profile_version == (
            "quick-v1"
        )
        assert scan.assessment_mode == "web"
        assert scan.engine_version == "v2"
        assert scan.status == "queued"
        assert scan.celery_task_id == (
            "task18-quick"
        )

        plan = self.database.scalar(
            select(
                AssessmentScanPlan
            ).where(
                AssessmentScanPlan.scan_id
                == scan.id
            )
        )

        assert plan is not None

        assert (
            plan.authorized_scope
            == {
                "fqdn":
                    "portal.example.com",
            }
        )

        assert (
            plan.resolved_addresses
            == [
                "203.0.113.10",
            ]
        )

        assert (
            plan
            .nuclei_template_snapshot_id
            is not None
        )

        assert (
            plan.engine_policy_versions[
                "nuclei"
            ]
            == "nuclei-policy-v1"
        )

        assert (
            plan.zap_policy_version
            == "beacon-quick-v1"
        )

        assert (
            plan.engine_policy_versions[
                "zap"
            ]
            == "beacon-quick-v1"
        )

    def test_deep_infrastructure_rejects_uncovered_resolved_address(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        request = self._request(
            target_id=self.target.id,
            profile="deep",
            active_testing_confirmed=True,
            infrastructure=(
                self._infra_request(
                    authorized_ips=[
                        "198.51.100.20",
                    ]
                )
            ),
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            return_value=[
                "203.0.113.10",
            ],
        ):
            with pytest.raises(
                HTTPException
            ) as exc:
                assessment_router.create_assessment(
                    request,
                    self.user,
                    self.database,
                )

        assert (
            exc.value.status_code
            == 400
        )

    def test_deep_infrastructure_authorization_is_persisted(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        request = self._request(
            target_id=self.target.id,
            profile="deep",
            active_testing_confirmed=True,
            infrastructure=(
                self._infra_request(
                    authorized_ips=[
                        "203.0.113.10",
                    ]
                )
            ),
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            return_value=[
                "203.0.113.10",
            ],
        ):
            with patch.object(
                assessment_router
                .run_assessment_v2,
                "delay",
                return_value=(
                    SimpleNamespace(
                        id="task18-deep",
                    )
                ),
            ):
                scan = (
                    assessment_router
                    .create_assessment(
                        request,
                        self.user,
                        self.database,
                    )
                )

        authorization = (
            self.database.scalar(
                select(
                    InfrastructureAuthorization
                ).where(
                    InfrastructureAuthorization
                    .scan_id
                    == scan.id
                )
            )
        )

        assert authorization is not None

        assert (
            authorization
            .authorized_ips
            == [
                "203.0.113.10",
            ]
        )

        assert (
            authorization
            .resolved_target_ips
            == [
                "203.0.113.10",
            ]
        )

        assert (
            authorization
            .broad_port_scan_allowed
            is True
        )

        assert (
            authorization
            .network_active_checks_allowed
            is True
        )

        assert (
            authorization
            .third_party_infrastructure_attested_excluded
            is True
        )

        assert (
            len(
                authorization
                .authorization_text_hash
            )
            == 64
        )

    def test_cancel_assessment_is_owned_and_cooperative(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        scan = Scan(
            organization_id=self.organization.id,
            user_id=self.user.id,
            target_id=self.target.id,
            scan_level="standard",
            status="running",
            progress=25,
            profile="standard",
            profile_version="standard-v1",
            assessment_mode="web",
            engine_version="v2",
            active_testing_authorized_at=(
                datetime.now(
                    timezone.utc
                )
            ),
        )

        self.database.add(
            scan
        )

        self.database.commit()

        with patch.object(
            assessment_router,
            "request_assessment_v2_cancellation",
            return_value={
                "scan_id":
                    str(
                        scan.id
                    ),
                "cancellation_requested":
                    True,
            },
        ) as cancel:
            response = (
                assessment_router
                .cancel_assessment(
                    scan.id,
                    self.user,
                    self.database,
                )
            )

        cancel.assert_called_once_with(
            scan.id
        )

        assert (
            response.assessment_id
            == scan.id
        )

        assert (
            response
            .cancellation_requested
            is True
        )

        assert (
            response.status
            == "cancelling"
        )

        refreshed = self.database.get(
            Scan,
            scan.id,
        )

        assert (
            refreshed.cancel_requested
            is True
        )

        assert (
            refreshed.status
            == "cancelling"
        )

    def test_demo_cannot_launch_engine_v2_profile(
        self,
    ):
        from app.routers import (
            assessments as assessment_router,
        )

        request = self._request(
            target_id=(
                self.demo_target.id
            ),
            profile="quick",
        )

        with patch.object(
            assessment_router,
            "validate_target_destination",
            side_effect=AssertionError(
                "Demo Engine v2 request "
                "must be blocked before "
                "destination scanning."
            ),
        ):
            with pytest.raises(
                HTTPException
            ) as exc:
                assessment_router.create_assessment(
                    request,
                    self.demo_user,
                    self.database,
                )

        assert (
            exc.value.status_code
            == 403
        )

    def test_task18_routes_are_registered(
        self,
    ):
        from app.main import app

        paths = set(
            app.openapi()[
                "paths"
            ]
        )

        assert (
            "/api/v1/assessment-profiles"
            in paths
        )

        assert (
            "/api/v1/assessments"
            in paths
        )

        assert (
            "/api/v1/assessments/{assessment_id}"
            in paths
        )

        assert (
            "/api/v1/assessments/{assessment_id}/cancel"
            in paths
        )

        assert (
            "/api/v1/scanner-health"
            in paths
        )

    def test_existing_legacy_scan_remains_readable(
        self,
    ):
        legacy_scan = Scan(
            organization_id=self.organization.id,
            user_id=self.user.id,
            target_id=self.target.id,
            scan_level="basic",
            status="completed",
            progress=100,
            profile=None,
            profile_version=None,
            assessment_mode=None,
            engine_version=None,
        )

        self.database.add(
            legacy_scan
        )

        self.database.commit()

        result = (
            scan_router.read_scan(
                legacy_scan.id,
                self.user,
                self.database,
            )
        )

        assert result.id == (
            legacy_scan.id
        )

        assert result.scan_level == (
            "basic"
        )

        assert result.profile is None


class TestAssessmentLiveExecutionAPI(
    TestAssessmentAPI
):
    """Task 22 Engine v2 live-detail contracts."""

    def setup_method(self):
        super().setup_method()

        from app.models.tool_run import (
            ScanToolRun,
        )

        ScanToolRun.__table__.create(
            self.engine
        )

    def test_engine_v2_detail_serializes_real_engine_state_without_fake_percentage(
        self,
    ):
        import json

        from app.models.tool_run import (
            ScanToolRun,
        )
        from app.routers import (
            assessments as assessment_router,
        )

        now = datetime.now(
            timezone.utc
        )

        scan = Scan(
            organization_id=self.organization.id,
            user_id=self.user.id,
            target_id=self.target.id,
            scan_level="standard",
            status="running",
            progress=37,
            profile="standard",
            profile_version="standard-v1",
            assessment_mode="web",
            engine_version="v2",
            active_testing_authorized_at=now,
            started_at=(
                now
                - timedelta(
                    seconds=45
                )
            ),
        )

        self.database.add(
            scan
        )

        self.database.flush()

        self.database.add_all(
            [
                ScanToolRun(
                    scan_id=scan.id,
                    tool_name="nmap",
                    status="completed",
                    queued_at=(
                        now
                        - timedelta(
                            seconds=42
                        )
                    ),
                    started_at=(
                        now
                        - timedelta(
                            seconds=40
                        )
                    ),
                    last_heartbeat_at=(
                        now
                        - timedelta(
                            seconds=31
                        )
                    ),
                    completed_at=(
                        now
                        - timedelta(
                            seconds=30
                        )
                    ),
                    tool_version="7.95",
                    exit_code=0,
                    attempt=1,
                ),
                ScanToolRun(
                    scan_id=scan.id,
                    tool_name="katana",
                    status="running",
                    queued_at=(
                        now
                        - timedelta(
                            seconds=20
                        )
                    ),
                    started_at=(
                        now
                        - timedelta(
                            seconds=18
                        )
                    ),
                    last_heartbeat_at=(
                        now
                        - timedelta(
                            seconds=2
                        )
                    ),
                    attempt=1,
                ),
            ]
        )

        self.database.commit()

        result = (
            assessment_router
            .read_assessment(
                scan.id,
                self.user,
                self.database,
            )
        )

        payload = result.model_dump(
            mode="json"
        )

        assert (
            payload[
                "current_stage"
            ]
            == "katana"
        )

        assert (
            payload[
                "current_stage_label"
            ]
            == "Katana application discovery"
        )

        assert isinstance(
            payload[
                "elapsed_seconds"
            ],
            int,
        )

        engines = {
            item[
                "engine"
            ]:
                item
            for item
            in payload[
                "engine_executions"
            ]
        }

        assert set(
            engines
        ) == {
            "nmap",
            "httpx",
            "katana",
            "sslyze",
            "nuclei",
            "zap",
            "nikto",
        }

        assert (
            engines[
                "nmap"
            ][
                "status"
            ]
            == "completed"
        )

        assert (
            engines[
                "nmap"
            ][
                "tool_version"
            ]
            == "7.95"
        )

        assert (
            engines[
                "katana"
            ][
                "status"
            ]
            == "running"
        )

        assert (
            engines[
                "httpx"
            ][
                "status"
            ]
            == "pending"
        )

        coverage = payload[
            "coverage"
        ]

        assert (
            coverage[
                "engines_total"
            ]
            == 7
        )

        assert (
            coverage[
                "engines_completed"
            ]
            == 1
        )

        assert (
            coverage[
                "engines_incomplete"
            ]
            == 0
        )

        assert (
            coverage[
                "detailed_metrics_available"
            ]
            is False
        )

        assert (
            coverage[
                "urls_discovered"
            ]
            is None
        )

        assert (
            coverage[
                "http_services_discovered"
            ]
            is None
        )

        serialized = json.dumps(
            payload
        )

        assert (
            "workflow_progress"
            not in serialized
        )

        assert (
            "progress_percent"
            not in serialized
        )

    def test_engine_v2_detail_reports_persisted_coverage_limitations(
        self,
    ):
        from app.models.tool_run import (
            ScanToolRun,
        )
        from app.routers import (
            assessments as assessment_router,
        )

        now = datetime.now(
            timezone.utc
        )

        scan = Scan(
            organization_id=self.organization.id,
            user_id=self.user.id,
            target_id=self.target.id,
            scan_level="standard",
            status="completed",
            progress=100,
            profile="standard",
            profile_version="standard-v1",
            assessment_mode="web",
            engine_version="v2",
            active_testing_authorized_at=now,
            started_at=(
                now
                - timedelta(
                    minutes=3
                )
            ),
            completed_at=now,
            completed_with_warnings=True,
        )

        self.database.add(
            scan
        )

        self.database.flush()

        completed_engines = (
            "nmap",
            "httpx",
            "katana",
            "sslyze",
            "zap",
        )

        for engine in completed_engines:
            self.database.add(
                ScanToolRun(
                    scan_id=scan.id,
                    tool_name=engine,
                    status="completed",
                    queued_at=(
                        now
                        - timedelta(
                            minutes=2
                        )
                    ),
                    started_at=(
                        now
                        - timedelta(
                            minutes=2
                        )
                    ),
                    completed_at=(
                        now
                        - timedelta(
                            seconds=10
                        )
                    ),
                    last_heartbeat_at=(
                        now
                        - timedelta(
                            seconds=10
                        )
                    ),
                    exit_code=0,
                    attempt=1,
                )
            )

        self.database.add(
            ScanToolRun(
                scan_id=scan.id,
                tool_name="nuclei",
                status="failed",
                queued_at=(
                    now
                    - timedelta(
                        minutes=2
                    )
                ),
                started_at=(
                    now
                    - timedelta(
                        minutes=1
                    )
                ),
                completed_at=(
                    now
                    - timedelta(
                        seconds=20
                    )
                ),
                last_heartbeat_at=(
                    now
                    - timedelta(
                        seconds=20
                    )
                ),
                failure_type=(
                    "RuntimeError"
                ),
                failure_message=(
                    "Nuclei template "
                    "execution failed."
                ),
                error_message=(
                    "Nuclei template "
                    "execution failed."
                ),
                exit_code=1,
                attempt=1,
            )
        )

        self.database.add(
            ScanToolRun(
                scan_id=scan.id,
                tool_name="nikto",
                status="skipped",
                queued_at=(
                    now
                    - timedelta(
                        minutes=1
                    )
                ),
                started_at=(
                    now
                    - timedelta(
                        minutes=1
                    )
                ),
                completed_at=(
                    now
                    - timedelta(
                        seconds=5
                    )
                ),
                last_heartbeat_at=(
                    now
                    - timedelta(
                        seconds=5
                    )
                ),
                skipped_reason=(
                    "Optional scanner "
                    "intentionally skipped."
                ),
                attempt=1,
            )
        )

        self.database.commit()

        result = (
            assessment_router
            .read_assessment(
                scan.id,
                self.user,
                self.database,
            )
        )

        assert (
            result.current_stage
            == "completed_with_warnings"
        )

        assert (
            result.coverage
            is not None
        )

        assert (
            result.coverage
            .engines_incomplete
            == 1
        )

        assert (
            result.coverage
            .engines_failed
            == 1
        )

        assert (
            result.coverage
            .engines_skipped
            == 1
        )

        joined = " | ".join(
            result.coverage.limitations
        ).lower()

        assert (
            "nuclei"
            in joined
        )

        assert (
            "template execution failed"
            in joined
        )

        assert (
            "nikto"
            in joined
        )

        assert (
            "intentionally skipped"
            in joined
        )
