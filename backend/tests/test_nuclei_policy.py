import pytest


def test_nuclei_policy_groups_are_explicit():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
    )

    assert {
        group.value
        for group in NucleiPolicyGroup
    } == {
        "BEACON_SAFE",
        "BEACON_STANDARD",
        "BEACON_DEEP",
        "BEACON_INFRASTRUCTURE",
        "BLOCKED",
    }


def test_quick_profile_allows_only_safe_group():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="quick",
        infrastructure_authorized=False,
    )

    assert policy.allowed_groups == (
        NucleiPolicyGroup.BEACON_SAFE,
    )


def test_standard_profile_adds_standard_group():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="standard",
        infrastructure_authorized=False,
    )

    assert policy.allowed_groups == (
        NucleiPolicyGroup.BEACON_SAFE,
        NucleiPolicyGroup.BEACON_STANDARD,
    )


def test_deep_profile_adds_deep_group():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=False,
    )

    assert policy.allowed_groups == (
        NucleiPolicyGroup.BEACON_SAFE,
        NucleiPolicyGroup.BEACON_STANDARD,
        NucleiPolicyGroup.BEACON_DEEP,
    )


def test_deep_infrastructure_authorization_adds_infrastructure_group():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=True,
    )

    assert policy.allowed_groups == (
        NucleiPolicyGroup.BEACON_SAFE,
        NucleiPolicyGroup.BEACON_STANDARD,
        NucleiPolicyGroup.BEACON_DEEP,
        NucleiPolicyGroup.BEACON_INFRASTRUCTURE,
    )


@pytest.mark.parametrize(
    "profile",
    [
        "quick",
        "standard",
    ],
)
def test_infrastructure_policy_is_deep_only(
    profile,
):
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
        resolve_nuclei_policy,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="infrastructure",
    ):
        resolve_nuclei_policy(
            profile=profile,
            infrastructure_authorized=True,
        )


def test_unknown_profile_is_rejected():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
        resolve_nuclei_policy,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="profile",
    ):
        resolve_nuclei_policy(
            profile="aggressive",
            infrastructure_authorized=False,
        )


def test_policy_disables_public_oast():
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    for profile in (
        "quick",
        "standard",
        "deep",
    ):
        policy = resolve_nuclei_policy(
            profile=profile,
            infrastructure_authorized=False,
        )

        assert policy.allow_public_oast is False


def test_policy_disables_code_templates():
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=False,
    )

    assert policy.allow_code is False


def test_policy_disables_headless_templates():
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=False,
    )

    assert policy.allow_headless is False


def test_policy_disables_dast_templates():
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=False,
    )

    assert policy.allow_dast is False


def test_blocked_group_is_never_executable():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=True,
    )

    assert (
        NucleiPolicyGroup.BLOCKED
        not in policy.allowed_groups
    )


def test_policy_is_immutable():
    from dataclasses import FrozenInstanceError

    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="quick",
        infrastructure_authorized=False,
    )

    with pytest.raises(
        FrozenInstanceError,
    ):
        policy.allow_public_oast = True


def test_template_must_be_explicitly_approved():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        NucleiTemplateApproval,
        is_template_allowed,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="standard",
        infrastructure_authorized=False,
    )

    template = NucleiTemplateApproval(
        template_id="CVE-2026-12345",
        policy_group=(
            NucleiPolicyGroup.BEACON_STANDARD
        ),
        approved=False,
    )

    assert (
        is_template_allowed(
            policy,
            template,
        )
        is False
    )


def test_approved_template_in_allowed_group_is_executable():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        NucleiTemplateApproval,
        is_template_allowed,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="standard",
        infrastructure_authorized=False,
    )

    template = NucleiTemplateApproval(
        template_id="http-missing-security-headers",
        policy_group=(
            NucleiPolicyGroup.BEACON_STANDARD
        ),
        approved=True,
    )

    assert (
        is_template_allowed(
            policy,
            template,
        )
        is True
    )


def test_approved_template_outside_profile_is_not_executable():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        NucleiTemplateApproval,
        is_template_allowed,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="quick",
        infrastructure_authorized=False,
    )

    template = NucleiTemplateApproval(
        template_id="active-template",
        policy_group=(
            NucleiPolicyGroup.BEACON_STANDARD
        ),
        approved=True,
    )

    assert (
        is_template_allowed(
            policy,
            template,
        )
        is False
    )


def test_blocked_template_is_never_executable_even_if_marked_approved():
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        NucleiTemplateApproval,
        is_template_allowed,
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="deep",
        infrastructure_authorized=True,
    )

    template = NucleiTemplateApproval(
        template_id="dangerous-template",
        policy_group=NucleiPolicyGroup.BLOCKED,
        approved=True,
    )

    assert (
        is_template_allowed(
            policy,
            template,
        )
        is False
    )


def test_policy_has_versioned_identity():
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    policy = resolve_nuclei_policy(
        profile="standard",
        infrastructure_authorized=False,
    )

    assert policy.version == "nuclei-policy-v1"
