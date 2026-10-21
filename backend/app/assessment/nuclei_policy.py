from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json


class NucleiPolicyError(ValueError):
    """Raised when a Nuclei policy cannot be resolved safely."""


class NucleiPolicyGroup(str, Enum):
    """Explicit BEACON trust groups for Nuclei templates."""

    BEACON_SAFE = "BEACON_SAFE"
    BEACON_STANDARD = "BEACON_STANDARD"
    BEACON_DEEP = "BEACON_DEEP"
    BEACON_INFRASTRUCTURE = "BEACON_INFRASTRUCTURE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class NucleiTemplatePolicy:
    """Immutable Nuclei execution policy for one assessment."""

    version: str
    profile: str
    allowed_groups: tuple[NucleiPolicyGroup, ...]
    infrastructure_authorized: bool

    allow_public_oast: bool = False
    allow_code: bool = False
    allow_headless: bool = False
    allow_dast: bool = False


@dataclass(frozen=True)
class NucleiTemplateApproval:
    """Explicit trust decision for one template."""

    template_id: str
    policy_group: NucleiPolicyGroup
    approved: bool


@dataclass(frozen=True)
class NucleiTemplateDefinition:
    """Approved template metadata eligible for snapshotting."""

    template_id: str
    template_revision_or_digest: str
    template_source: str
    template_path: str
    template_severity: str
    template_tags: tuple[str, ...]
    protocol: str
    policy_group: NucleiPolicyGroup
    approved_profiles: tuple[str, ...]
    approved: bool


_POLICY_VERSION = "nuclei-policy-v1"


def resolve_nuclei_policy(
    *,
    profile: str,
    infrastructure_authorized: bool,
) -> NucleiTemplatePolicy:
    """Resolve the immutable Nuclei policy for an assessment."""

    if profile == "quick":
        if infrastructure_authorized:
            raise NucleiPolicyError(
                "Nuclei infrastructure policy requires "
                "the deep assessment profile."
            )

        allowed_groups = (
            NucleiPolicyGroup.BEACON_SAFE,
        )

    elif profile == "standard":
        if infrastructure_authorized:
            raise NucleiPolicyError(
                "Nuclei infrastructure policy requires "
                "the deep assessment profile."
            )

        allowed_groups = (
            NucleiPolicyGroup.BEACON_SAFE,
            NucleiPolicyGroup.BEACON_STANDARD,
        )

    elif profile == "deep":
        allowed_groups = (
            NucleiPolicyGroup.BEACON_SAFE,
            NucleiPolicyGroup.BEACON_STANDARD,
            NucleiPolicyGroup.BEACON_DEEP,
        )

        if infrastructure_authorized:
            allowed_groups += (
                NucleiPolicyGroup.BEACON_INFRASTRUCTURE,
            )

    else:
        raise NucleiPolicyError(
            f"Unknown Nuclei assessment profile: {profile!r}."
        )

    return NucleiTemplatePolicy(
        version=_POLICY_VERSION,
        profile=profile,
        allowed_groups=allowed_groups,
        infrastructure_authorized=(
            infrastructure_authorized
        ),
    )


def is_template_allowed(
    policy: NucleiTemplatePolicy,
    template: NucleiTemplateApproval,
) -> bool:
    """Return whether an explicitly classified template may execute."""

    if not template.approved:
        return False

    if template.policy_group is NucleiPolicyGroup.BLOCKED:
        return False

    return template.policy_group in policy.allowed_groups

def _required_template_text(
    value: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise NucleiPolicyError(
            "Nuclei template metadata cannot be empty."
        )

    return normalized


def _required_snapshot_text(
    value: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise NucleiPolicyError(
            "Nuclei snapshot identity cannot be empty."
        )

    return normalized


def _required_template_path(
    value: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise NucleiPolicyError(
            "Nuclei template path cannot be empty."
        )

    if "\\" in normalized:
        raise NucleiPolicyError(
            "Nuclei template path must use POSIX separators."
        )

    if normalized.startswith("/"):
        raise NucleiPolicyError(
            "Nuclei template path must be relative."
        )

    if "//" in normalized:
        raise NucleiPolicyError(
            "Nuclei template path is ambiguous."
        )

    parts = normalized.split("/")

    if any(
        part in {
            "",
            ".",
            "..",
        }
        for part in parts
    ):
        raise NucleiPolicyError(
            "Nuclei template path contains unsafe traversal."
        )

    return normalized


def _build_template_manifest_entry(
    *,
    policy: NucleiTemplatePolicy,
    template: NucleiTemplateDefinition,
) -> dict:
    if not template.approved:
        raise NucleiPolicyError(
            "Template must be explicitly approved "
            "before snapshot inclusion."
        )

    if (
        template.policy_group
        is NucleiPolicyGroup.BLOCKED
    ):
        raise NucleiPolicyError(
            "BLOCKED templates cannot enter "
            "an approved snapshot."
        )

    if (
        template.policy_group
        not in policy.allowed_groups
    ):
        raise NucleiPolicyError(
            "Template policy group is not allowed "
            "by the resolved policy."
        )

    approved_profiles = sorted(
        {
            profile.strip()
            for profile in template.approved_profiles
            if profile.strip()
        }
    )

    if policy.profile not in approved_profiles:
        raise NucleiPolicyError(
            "Template is not approved for "
            "the current profile."
        )

    template_id = _required_template_text(
        template.template_id
    )

    revision = _required_template_text(
        template.template_revision_or_digest
    )

    source = _required_template_text(
        template.template_source
    )

    template_path = _required_template_path(
        template.template_path
    )

    severity = _required_template_text(
        template.template_severity
    )

    protocol = _required_template_text(
        template.protocol
    )

    tags = sorted(
        {
            tag.strip()
            for tag in template.template_tags
            if tag.strip()
        }
    )

    return {
        "template_id": template_id,
        "template_revision_or_digest": revision,
        "template_source": source,
        "template_path": template_path,
        "template_severity": severity,
        "template_tags": tags,
        "protocol": protocol,
        "policy_group": (
            template.policy_group.value
        ),
        "approved_profiles": approved_profiles,
    }


def build_nuclei_template_snapshot(
    *,
    policy: NucleiTemplatePolicy,
    nuclei_version: str,
    template_source: str,
    template_source_revision: str,
    templates: tuple[NucleiTemplateDefinition, ...],
):
    """Build one deterministic immutable template snapshot."""

    normalized_nuclei_version = (
        _required_snapshot_text(
            nuclei_version
        )
    )

    normalized_template_source = (
        _required_snapshot_text(
            template_source
        )
    )

    normalized_source_revision = (
        _required_snapshot_text(
            template_source_revision
        )
    )

    manifest = []
    seen_template_ids: set[str] = set()

    for template in templates:
        entry = _build_template_manifest_entry(
            policy=policy,
            template=template,
        )

        template_id = entry["template_id"]

        if template_id in seen_template_ids:
            raise NucleiPolicyError(
                "duplicate Nuclei template id "
                f"in snapshot: {template_id!r}"
            )

        seen_template_ids.add(
            template_id
        )

        manifest.append(
            entry
        )

    manifest.sort(
        key=lambda entry: entry["template_id"]
    )

    approved_groups = [
        group.value
        for group in policy.allowed_groups
    ]

    digest_payload = {
        "policy_version": policy.version,
        "nuclei_version": (
            normalized_nuclei_version
        ),
        "template_source": (
            normalized_template_source
        ),
        "template_source_revision": (
            normalized_source_revision
        ),
        "approved_groups": approved_groups,
        "template_manifest": manifest,
    }

    canonical_payload = json.dumps(
        digest_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )

    snapshot_digest = hashlib.sha256(
        canonical_payload
    ).hexdigest()

    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    return NucleiTemplateSnapshot(
        policy_version=policy.version,
        nuclei_version=(
            normalized_nuclei_version
        ),
        template_source=(
            normalized_template_source
        ),
        template_source_revision=(
            normalized_source_revision
        ),
        snapshot_digest=snapshot_digest,
        approved_groups=approved_groups,
        template_manifest=manifest,
        template_count=len(
            manifest
        ),
    )
