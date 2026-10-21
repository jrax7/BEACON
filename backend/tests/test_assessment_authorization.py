from datetime import datetime, timezone

import pytest


def test_quick_does_not_require_active_confirmation():
    from app.assessment.authorization import (
        validate_active_authorization,
    )

    validate_active_authorization(
        profile_name="quick",
        confirmation=None,
    )


def test_standard_requires_active_confirmation():
    from app.assessment.authorization import (
        validate_active_authorization,
    )

    with pytest.raises(
        ValueError,
        match="active testing authorization",
    ):
        validate_active_authorization(
            profile_name="standard",
            confirmation=None,
        )


def test_deep_requires_active_confirmation():
    from app.assessment.authorization import (
        validate_active_authorization,
    )

    with pytest.raises(
        ValueError,
        match="active testing authorization",
    ):
        validate_active_authorization(
            profile_name="deep",
            confirmation=None,
        )


def test_standard_accepts_valid_active_confirmation():
    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
        validate_active_authorization,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    validate_active_authorization(
        profile_name="standard",
        confirmation=confirmation,
    )


def test_infrastructure_extension_requires_deep_profile():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=("203.0.113.10",),
        authorized_cidrs=(),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    with pytest.raises(
        ValueError,
        match="Deep",
    ):
        validate_infrastructure_authorization(
            profile_name="standard",
            authorization=authorization,
            requested_addresses=("203.0.113.10",),
        )


def test_infrastructure_extension_requires_exact_ip_or_cidr():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=(),
        authorized_cidrs=(),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    with pytest.raises(
        ValueError,
        match="IP address or CIDR",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=("203.0.113.10",),
        )


def test_infrastructure_extension_requires_broad_scan_consent():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=("203.0.113.10",),
        authorized_cidrs=(),
        broad_port_scan_allowed=False,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    with pytest.raises(
        ValueError,
        match="broad port scan",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=("203.0.113.10",),
        )


def test_infrastructure_extension_requires_third_party_attestation():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=("203.0.113.10",),
        authorized_cidrs=(),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=False,
    )

    with pytest.raises(
        ValueError,
        match="third-party",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=("203.0.113.10",),
        )


def test_requested_ip_must_be_inside_explicit_authorized_scope():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=("203.0.113.10",),
        authorized_cidrs=(),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    with pytest.raises(
        ValueError,
        match="outside authorized infrastructure scope",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=("203.0.113.11",),
        )


def test_requested_ip_inside_authorized_cidr_is_allowed():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=(),
        authorized_cidrs=("203.0.113.0/28",),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    validate_infrastructure_authorization(
        profile_name="deep",
        authorization=authorization,
        requested_addresses=("203.0.113.7",),
    )


def test_domain_verification_is_not_infrastructure_authorization():
    from app.assessment.authorization import (
        validate_infrastructure_authorization,
    )

    with pytest.raises(
        ValueError,
        match="separate infrastructure authorization",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=None,
            requested_addresses=("203.0.113.10",),
        )


def test_infrastructure_extension_requires_network_check_consent():
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
        validate_infrastructure_authorization,
    )

    authorization = InfrastructureScopeAuthorization(
        authorized_ips=("203.0.113.10",),
        authorized_cidrs=(),
        broad_port_scan_allowed=True,
        network_active_checks_allowed=False,
        third_party_infrastructure_attested_excluded=True,
    )

    with pytest.raises(
        ValueError,
        match="network active checks",
    ):
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=("203.0.113.10",),
        )


def test_standard_accepts_uuid_active_confirmation():
    from datetime import datetime, timezone
    from uuid import uuid4

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
        validate_active_authorization,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=uuid4(),
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    validate_active_authorization(
        profile_name="standard",
        confirmation=confirmation,
    )


def test_standard_rejects_nil_uuid_active_confirmation():
    from datetime import datetime, timezone
    from uuid import UUID

    import pytest

    from app.assessment.authorization import (
        ActiveAuthorizationConfirmation,
        validate_active_authorization,
    )

    confirmation = ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=UUID(int=0),
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )

    with pytest.raises(
        ValueError,
        match="valid user",
    ):
        validate_active_authorization(
            profile_name="standard",
            confirmation=confirmation,
        )
