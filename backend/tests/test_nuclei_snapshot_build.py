import hashlib
import json

import pytest


def _template(
    *,
    template_id="http-missing-security-headers",
    digest="b" * 64,
    source=(
        "projectdiscovery/nuclei-templates"
    ),
    template_path=(
        "http/misconfiguration/"
        "http-missing-security-headers.yaml"
    ),
    severity="info",
    tags=("headers", "misconfig"),
    protocol="http",
    policy_group="BEACON_STANDARD",
    approved_profiles=("standard", "deep"),
    approved=True,
):
    from app.assessment.nuclei_policy import (
        NucleiPolicyGroup,
        NucleiTemplateDefinition,
    )

    return NucleiTemplateDefinition(
        template_id=template_id,
        template_revision_or_digest=digest,
        template_source=source,
        template_path=template_path,
        template_severity=severity,
        template_tags=tags,
        protocol=protocol,
        policy_group=NucleiPolicyGroup(
            policy_group
        ),
        approved_profiles=approved_profiles,
        approved=approved,
    )


def _policy(
    profile="standard",
    *,
    infrastructure_authorized=False,
):
    from app.assessment.nuclei_policy import (
        resolve_nuclei_policy,
    )

    return resolve_nuclei_policy(
        profile=profile,
        infrastructure_authorized=(
            infrastructure_authorized
        ),
    )


def _build(
    templates,
    *,
    profile="standard",
    infrastructure_authorized=False,
):
    from app.assessment.nuclei_policy import (
        build_nuclei_template_snapshot,
    )

    return build_nuclei_template_snapshot(
        policy=_policy(
            profile,
            infrastructure_authorized=(
                infrastructure_authorized
            ),
        ),
        nuclei_version="3.11.1",
        template_source=(
            "projectdiscovery/nuclei-templates"
        ),
        template_source_revision="v10.4.7",
        templates=templates,
    )


def test_snapshot_contains_policy_and_source_identity():
    snapshot = _build(
        (
            _template(),
        )
    )

    assert snapshot.policy_version == (
        "nuclei-policy-v1"
    )

    assert snapshot.nuclei_version == "3.11.1"

    assert snapshot.template_source == (
        "projectdiscovery/nuclei-templates"
    )

    assert snapshot.template_source_revision == (
        "v10.4.7"
    )

    assert snapshot.approved_groups == [
        "BEACON_SAFE",
        "BEACON_STANDARD",
    ]

    assert snapshot.template_count == 1


def test_snapshot_manifest_records_required_provenance():
    snapshot = _build(
        (
            _template(),
        )
    )

    entry = snapshot.template_manifest[0]

    assert entry == {
        "template_id": (
            "http-missing-security-headers"
        ),
        "template_revision_or_digest": (
            "b" * 64
        ),
        "template_source": (
            "projectdiscovery/nuclei-templates"
        ),
        "template_path": (
            "http/misconfiguration/"
            "http-missing-security-headers.yaml"
        ),
        "template_severity": "info",
        "template_tags": [
            "headers",
            "misconfig",
        ],
        "protocol": "http",
        "policy_group": (
            "BEACON_STANDARD"
        ),
        "approved_profiles": [
            "deep",
            "standard",
        ],
    }


def test_snapshot_manifest_is_sorted_by_template_id():
    snapshot = _build(
        (
            _template(
                template_id="z-last",
                digest="c" * 64,
            ),
            _template(
                template_id="a-first",
                digest="d" * 64,
            ),
        )
    )

    assert [
        entry["template_id"]
        for entry in snapshot.template_manifest
    ] == [
        "a-first",
        "z-last",
    ]


def test_snapshot_normalizes_tags_and_profiles():
    snapshot = _build(
        (
            _template(
                tags=(
                    "misconfig",
                    "headers",
                    "headers",
                ),
                approved_profiles=(
                    "standard",
                    "deep",
                    "standard",
                ),
            ),
        )
    )

    entry = snapshot.template_manifest[0]

    assert entry["template_tags"] == [
        "headers",
        "misconfig",
    ]

    assert entry["approved_profiles"] == [
        "deep",
        "standard",
    ]


def test_snapshot_digest_is_sha256_of_canonical_payload():
    snapshot = _build(
        (
            _template(),
        )
    )

    payload = {
        "policy_version": (
            snapshot.policy_version
        ),
        "nuclei_version": (
            snapshot.nuclei_version
        ),
        "template_source": (
            snapshot.template_source
        ),
        "template_source_revision": (
            snapshot.template_source_revision
        ),
        "approved_groups": (
            snapshot.approved_groups
        ),
        "template_manifest": (
            snapshot.template_manifest
        ),
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    expected = hashlib.sha256(
        canonical
    ).hexdigest()

    assert snapshot.snapshot_digest == expected


def test_snapshot_digest_is_stable_across_input_order():
    first = _template(
        template_id="template-a",
        digest="a" * 64,
    )

    second = _template(
        template_id="template-b",
        digest="b" * 64,
    )

    snapshot_one = _build(
        (
            first,
            second,
        )
    )

    snapshot_two = _build(
        (
            second,
            first,
        )
    )

    assert (
        snapshot_one.snapshot_digest
        == snapshot_two.snapshot_digest
    )

    assert (
        snapshot_one.template_manifest
        == snapshot_two.template_manifest
    )


def test_new_template_changes_new_snapshot_without_mutating_old_snapshot():
    first = _template(
        template_id="template-a",
        digest="a" * 64,
    )

    second = _template(
        template_id="template-b",
        digest="b" * 64,
    )

    original = _build(
        (
            first,
        )
    )

    original_digest = (
        original.snapshot_digest
    )

    expanded = _build(
        (
            first,
            second,
        )
    )

    assert original.template_count == 1

    assert [
        item["template_id"]
        for item in original.template_manifest
    ] == [
        "template-a",
    ]

    assert (
        original.snapshot_digest
        == original_digest
    )

    assert expanded.template_count == 2

    assert (
        expanded.snapshot_digest
        != original.snapshot_digest
    )


def test_unapproved_template_is_rejected():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        approved=False,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="approved",
    ):
        _build(
            (
                template,
            )
        )


def test_blocked_template_is_rejected():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        policy_group="BLOCKED",
        approved=True,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="BLOCKED",
    ):
        _build(
            (
                template,
            )
        )


def test_template_outside_profile_policy_is_rejected():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        policy_group="BEACON_DEEP",
        approved_profiles=("deep",),
    )

    with pytest.raises(
        NucleiPolicyError,
        match="policy",
    ):
        _build(
            (
                template,
            ),
            profile="standard",
        )


def test_template_must_approve_current_profile():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        approved_profiles=("deep",),
    )

    with pytest.raises(
        NucleiPolicyError,
        match="profile",
    ):
        _build(
            (
                template,
            ),
            profile="standard",
        )


def test_infrastructure_template_requires_infrastructure_policy():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        policy_group=(
            "BEACON_INFRASTRUCTURE"
        ),
        approved_profiles=("deep",),
    )

    with pytest.raises(
        NucleiPolicyError,
        match="policy",
    ):
        _build(
            (
                template,
            ),
            profile="deep",
            infrastructure_authorized=False,
        )


def test_infrastructure_template_allowed_when_separately_authorized():
    snapshot = _build(
        (
            _template(
                policy_group=(
                    "BEACON_INFRASTRUCTURE"
                ),
                approved_profiles=("deep",),
            ),
        ),
        profile="deep",
        infrastructure_authorized=True,
    )

    assert snapshot.template_count == 1

    assert snapshot.template_manifest[0][
        "policy_group"
    ] == "BEACON_INFRASTRUCTURE"


def test_duplicate_template_id_is_rejected():
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    first = _template(
        template_id="same-template",
        digest="a" * 64,
    )

    second = _template(
        template_id="same-template",
        digest="b" * 64,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="duplicate",
    ):
        _build(
            (
                first,
                second,
            )
        )


@pytest.mark.parametrize(
    (
        "field",
        "value",
    ),
    [
        (
            "template_id",
            "",
        ),
        (
            "digest",
            "",
        ),
        (
            "source",
            "",
        ),
        (
            "severity",
            "",
        ),
        (
            "protocol",
            "",
        ),
    ],
)
def test_template_required_metadata_cannot_be_empty(
    field,
    value,
):
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    kwargs = {
        field: value,
    }

    template = _template(
        **kwargs,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="metadata",
    ):
        _build(
            (
                template,
            )
        )


@pytest.mark.parametrize(
    (
        "field",
        "value",
    ),
    [
        (
            "nuclei_version",
            "",
        ),
        (
            "template_source",
            "",
        ),
        (
            "template_source_revision",
            "",
        ),
    ],
)
def test_snapshot_identity_cannot_be_empty(
    field,
    value,
):
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
        build_nuclei_template_snapshot,
    )

    kwargs = {
        "policy": _policy(),
        "nuclei_version": "3.11.1",
        "template_source": (
            "projectdiscovery/"
            "nuclei-templates"
        ),
        "template_source_revision": (
            "v10.4.7"
        ),
        "templates": (
            _template(),
        ),
    }

    kwargs[field] = value

    with pytest.raises(
        NucleiPolicyError,
        match="snapshot",
    ):
        build_nuclei_template_snapshot(
            **kwargs,
        )

@pytest.mark.parametrize(
    "template_path",
    [
        "",
        "/absolute/template.yaml",
        "../escape.yaml",
        "http/../../escape.yaml",
        "http\\windows-style.yaml",
        "http//double-slash.yaml",
    ],
)
def test_snapshot_rejects_unsafe_template_path(
    template_path,
):
    from app.assessment.nuclei_policy import (
        NucleiPolicyError,
    )

    template = _template(
        template_path=template_path,
    )

    with pytest.raises(
        NucleiPolicyError,
        match="template path",
    ):
        _build(
            (
                template,
            )
        )


def test_template_path_changes_snapshot_digest():
    first = _build(
        (
            _template(
                template_path=(
                    "http/template-a.yaml"
                ),
            ),
        )
    )

    second = _build(
        (
            _template(
                template_path=(
                    "http/template-b.yaml"
                ),
            ),
        )
    )

    assert (
        first.snapshot_digest
        != second.snapshot_digest
    )


def test_template_path_is_preserved_in_manifest():
    snapshot = _build(
        (
            _template(
                template_path=(
                    "http/cves/"
                    "2026/CVE-2026-12345.yaml"
                ),
            ),
        )
    )

    assert snapshot.template_manifest[0][
        "template_path"
    ] == (
        "http/cves/"
        "2026/CVE-2026-12345.yaml"
    )
