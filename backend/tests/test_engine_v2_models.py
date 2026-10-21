from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB


def test_scan_has_legacy_safe_engine_v2_metadata_columns():
    from app.models.scan import Scan

    table = Scan.__table__

    nullable_columns = {
        "profile",
        "profile_version",
        "assessment_mode",
        "engine_version",
        "active_testing_authorized_at",
    }

    for column_name in nullable_columns:
        assert column_name in table.c
        assert table.c[column_name].nullable is True

    assert "cancel_requested" in table.c
    assert isinstance(
        table.c.cancel_requested.type,
        Boolean,
    )
    assert table.c.cancel_requested.nullable is False
    assert table.c.cancel_requested.server_default is not None

    assert "completed_with_warnings" in table.c
    assert isinstance(
        table.c.completed_with_warnings.type,
        Boolean,
    )
    assert table.c.completed_with_warnings.nullable is False
    assert (
        table.c.completed_with_warnings.server_default
        is not None
    )


def test_scan_profile_columns_are_bounded_strings():
    from app.models.scan import Scan

    table = Scan.__table__

    for column_name in (
        "profile",
        "profile_version",
        "assessment_mode",
        "engine_version",
    ):
        assert isinstance(
            table.c[column_name].type,
            String,
        )


def test_tool_run_supports_engine_execution_lifecycle_metadata():
    from app.models.tool_run import ScanToolRun

    table = ScanToolRun.__table__

    datetime_columns = (
        "queued_at",
        "last_heartbeat_at",
        "cancelled_at",
    )

    for column_name in datetime_columns:
        assert column_name in table.c
        assert isinstance(
            table.c[column_name].type,
            DateTime,
        )
        assert table.c[column_name].nullable is True

    assert "failure_type" in table.c
    assert isinstance(
        table.c.failure_type.type,
        String,
    )
    assert table.c.failure_type.nullable is True

    assert "failure_message" in table.c
    assert table.c.failure_message.nullable is True

    assert "attempt" in table.c
    assert isinstance(
        table.c.attempt.type,
        Integer,
    )
    assert table.c.attempt.nullable is False
    assert table.c.attempt.server_default is not None

    assert "lease_token" in table.c
    assert isinstance(
        table.c.lease_token.type,
        String,
    )
    assert table.c.lease_token.nullable is True

    assert "skipped_reason" in table.c
    assert table.c.skipped_reason.nullable is True


def test_assessment_scan_plan_is_one_to_one_with_scan():
    from app.models.assessment_plan import AssessmentScanPlan

    table = AssessmentScanPlan.__table__

    assert "scan_id" in table.c
    assert table.c.scan_id.nullable is False
    assert table.c.scan_id.unique is True

    foreign_keys = list(
        table.c.scan_id.foreign_keys
    )

    assert len(foreign_keys) == 1
    assert foreign_keys[0].target_fullname == "scans.id"
    assert foreign_keys[0].ondelete == "CASCADE"


def test_assessment_scan_plan_snapshots_required_policy_data():
    from app.models.assessment_plan import AssessmentScanPlan

    table = AssessmentScanPlan.__table__

    expected_json_columns = (
        "authorized_scope",
        "resolved_addresses",
        "engine_policy_versions",
        "crawl_policy",
        "rate_budget",
        "timeout_budget",
    )

    for column_name in expected_json_columns:
        assert column_name in table.c
        assert isinstance(
            table.c[column_name].type,
            JSONB,
        )
        assert table.c[column_name].nullable is False

    assert "profile" in table.c
    assert "profile_version" in table.c
    assert "assessment_mode" in table.c
    assert "nuclei_template_snapshot_id" in table.c
    assert "zap_policy_version" in table.c


def test_assessment_scan_plan_accepts_snapshot_values():
    from app.models.assessment_plan import AssessmentScanPlan

    scan_id = uuid4()

    plan = AssessmentScanPlan(
        scan_id=scan_id,
        profile="standard",
        profile_version="standard-v1",
        assessment_mode="web",
        authorized_scope={
            "fqdn": "portal.example.com",
        },
        resolved_addresses=[
            "203.0.113.10",
        ],
        engine_policy_versions={
            "zap": "beacon-standard-v1",
            "nuclei": "standard-v1",
        },
        crawl_policy={
            "depth": 5,
        },
        rate_budget={
            "requests_per_second": 10,
        },
        timeout_budget={
            "assessment_seconds": 3600,
        },
        nuclei_template_snapshot_id=None,
        zap_policy_version="beacon-standard-v1",
    )

    assert plan.scan_id == scan_id
    assert plan.profile == "standard"
    assert plan.authorized_scope == {
        "fqdn": "portal.example.com",
    }


def test_infrastructure_authorization_is_one_to_one_with_scan():
    from app.models.infrastructure_authorization import (
        InfrastructureAuthorization,
    )

    table = InfrastructureAuthorization.__table__

    assert table.c.scan_id.nullable is False
    assert table.c.scan_id.unique is True

    foreign_keys = list(
        table.c.scan_id.foreign_keys
    )

    assert len(foreign_keys) == 1
    assert foreign_keys[0].target_fullname == "scans.id"
    assert foreign_keys[0].ondelete == "CASCADE"


def test_infrastructure_authorization_records_exact_scope_and_attestation():
    from app.models.infrastructure_authorization import (
        InfrastructureAuthorization,
    )

    table = InfrastructureAuthorization.__table__

    for column_name in (
        "authorized_ips",
        "authorized_cidrs",
        "resolved_target_ips",
    ):
        assert column_name in table.c
        assert isinstance(
            table.c[column_name].type,
            JSONB,
        )
        assert table.c[column_name].nullable is False

    for column_name in (
        "broad_port_scan_allowed",
        "network_active_checks_allowed",
        "third_party_infrastructure_attested_excluded",
    ):
        assert isinstance(
            table.c[column_name].type,
            Boolean,
        )
        assert table.c[column_name].nullable is False

    assert isinstance(
        table.c.confirmed_at.type,
        DateTime,
    )
    assert table.c.confirmed_at.nullable is False

    assert table.c.confirmed_by_user_id.nullable is False
    assert table.c.authorization_version.nullable is False
    assert table.c.authorization_text_hash.nullable is False


def test_infrastructure_authorization_accepts_exact_ip_scope():
    from app.models.infrastructure_authorization import (
        InfrastructureAuthorization,
    )

    confirmed_at = datetime.now(timezone.utc)

    authorization = InfrastructureAuthorization(
        scan_id=uuid4(),
        confirmed_by_user_id=uuid4(),
        authorization_version="infra-v1",
        authorization_text_hash="a" * 64,
        confirmed_at=confirmed_at,
        source_ip="198.51.100.25",
        authorized_ips=[
            "203.0.113.10",
        ],
        authorized_cidrs=[],
        resolved_target_ips=[
            "203.0.113.10",
        ],
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    assert authorization.authorized_ips == [
        "203.0.113.10",
    ]
    assert authorization.confirmed_at == confirmed_at


def test_new_models_are_exported_from_app_models():
    from app.models import (
        AssessmentScanPlan,
        InfrastructureAuthorization,
    )

    assert AssessmentScanPlan.__tablename__ == (
        "assessment_scan_plans"
    )
    assert InfrastructureAuthorization.__tablename__ == (
        "infrastructure_authorizations"
    )
