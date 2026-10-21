from sqlalchemy import Integer, String
from sqlalchemy.dialects.postgresql import JSONB


def test_nuclei_template_snapshot_has_auditable_identity():
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    table = NucleiTemplateSnapshot.__table__

    assert table.name == "nuclei_template_snapshots"

    required_columns = {
        "id",
        "policy_version",
        "nuclei_version",
        "template_source",
        "template_source_revision",
        "snapshot_digest",
        "approved_groups",
        "template_manifest",
        "template_count",
        "created_at",
    }

    assert required_columns.issubset(
        set(table.c.keys())
    )


def test_nuclei_template_snapshot_metadata_is_required():
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    table = NucleiTemplateSnapshot.__table__

    for name in (
        "policy_version",
        "nuclei_version",
        "template_source",
        "template_source_revision",
        "snapshot_digest",
        "approved_groups",
        "template_manifest",
        "template_count",
    ):
        assert table.c[name].nullable is False


def test_nuclei_template_snapshot_uses_structured_manifest_fields():
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    table = NucleiTemplateSnapshot.__table__

    assert isinstance(
        table.c.approved_groups.type,
        JSONB,
    )

    assert isinstance(
        table.c.template_manifest.type,
        JSONB,
    )

    assert isinstance(
        table.c.template_count.type,
        Integer,
    )


def test_nuclei_template_snapshot_identity_fields_are_bounded():
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    table = NucleiTemplateSnapshot.__table__

    for name in (
        "policy_version",
        "nuclei_version",
        "template_source",
        "template_source_revision",
        "snapshot_digest",
    ):
        assert isinstance(
            table.c[name].type,
            String,
        )

    assert table.c.snapshot_digest.unique is True


def test_nuclei_template_snapshot_accepts_approved_manifest():
    from app.models.nuclei_template_snapshot import (
        NucleiTemplateSnapshot,
    )

    snapshot = NucleiTemplateSnapshot(
        policy_version="nuclei-policy-v1",
        nuclei_version="3.11.1",
        template_source=(
            "projectdiscovery/nuclei-templates"
        ),
        template_source_revision="v10.4.7",
        snapshot_digest="a" * 64,
        approved_groups=[
            "BEACON_SAFE",
            "BEACON_STANDARD",
        ],
        template_manifest=[
            {
                "template_id": (
                    "http-missing-security-headers"
                ),
                "template_revision_or_digest": (
                    "b" * 64
                ),
                "template_source": (
                    "projectdiscovery/"
                    "nuclei-templates"
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
                    "standard",
                    "deep",
                ],
            }
        ],
        template_count=1,
    )

    assert snapshot.policy_version == (
        "nuclei-policy-v1"
    )
    assert snapshot.nuclei_version == "3.11.1"
    assert snapshot.template_source_revision == (
        "v10.4.7"
    )
    assert snapshot.snapshot_digest == "a" * 64
    assert snapshot.template_count == 1

    assert snapshot.template_manifest[0][
        "template_id"
    ] == "http-missing-security-headers"


def test_nuclei_template_snapshot_is_exported():
    from app.models import (
        NucleiTemplateSnapshot,
    )

    assert (
        NucleiTemplateSnapshot.__tablename__
        == "nuclei_template_snapshots"
    )


def test_assessment_plan_snapshot_id_is_real_foreign_key():
    from app.models.assessment_plan import (
        AssessmentScanPlan,
    )

    column = (
        AssessmentScanPlan
        .__table__
        .c
        .nuclei_template_snapshot_id
    )

    foreign_keys = list(
        column.foreign_keys
    )

    assert len(foreign_keys) == 1

    foreign_key = foreign_keys[0]

    assert foreign_key.target_fullname == (
        "nuclei_template_snapshots.id"
    )

    # Snapshot history must not disappear because an
    # assessment plan still references it.
    assert foreign_key.ondelete == "RESTRICT"


def test_assessment_plan_snapshot_reference_remains_nullable_for_history():
    from app.models.assessment_plan import (
        AssessmentScanPlan,
    )

    column = (
        AssessmentScanPlan
        .__table__
        .c
        .nuclei_template_snapshot_id
    )

    # Older assessments legitimately have no Nuclei snapshot.
    assert column.nullable is True
