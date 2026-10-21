from importlib import import_module
import importlib.util
from pathlib import Path
import runpy

from sqlalchemy import UniqueConstraint


def _load_model(
    module_name: str,
    class_name: str,
):
    try:
        spec = importlib.util.find_spec(
            module_name
        )
    except ModuleNotFoundError:
        spec = None

    assert spec is not None, (
        f"{module_name} does not exist yet"
    )

    module = import_module(
        module_name
    )

    assert hasattr(
        module,
        class_name,
    ), (
        f"{class_name} does not exist yet"
    )

    return getattr(
        module,
        class_name,
    )


def _foreign_key_targets(
    column,
) -> set[str]:
    return {
        foreign_key.target_fullname
        for foreign_key
        in column.foreign_keys
    }


def test_raw_scanner_evidence_model_contract():
    model = _load_model(
        "app.models.scanner_evidence",
        "RawScannerEvidence",
    )

    table = model.__table__

    assert table.name == "scanner_evidence"

    expected = {
        "id",
        "scan_id",
        "tool_run_id",
        "engine",
        "engine_version",
        "rule_id",
        "rule_version",
        "captured_at",
        "payload",
        "request_metadata",
        "response_metadata",
        "command_metadata",
        "artifact_path",
        "artifact_sha256",
        "created_at",
        "updated_at",
    }

    assert expected <= set(
        table.c.keys()
    )

    assert _foreign_key_targets(
        table.c.scan_id
    ) == {
        "scans.id",
    }

    assert _foreign_key_targets(
        table.c.tool_run_id
    ) == {
        "scan_tool_runs.id",
    }

    assert table.c.scan_id.nullable is False
    assert table.c.tool_run_id.nullable is True
    assert table.c.engine.nullable is False
    assert table.c.captured_at.nullable is False


def test_detection_model_contract():
    model = _load_model(
        "app.models.detection",
        "Detection",
    )

    table = model.__table__

    assert table.name == "detections"

    expected = {
        "id",
        "scan_id",
        "tool_run_id",
        "raw_evidence_id",
        "finding_id",
        "engine",
        "engine_version",
        "rule_id",
        "rule_version",
        "title",
        "severity",
        "confidence",
        "asset_identity",
        "affected_service",
        "affected_port",
        "affected_location",
        "affected_parameter",
        "cve_ids",
        "cwe_ids",
        "evidence_strength",
        "source_metadata",
        "created_at",
        "updated_at",
    }

    assert expected <= set(
        table.c.keys()
    )

    assert _foreign_key_targets(
        table.c.scan_id
    ) == {
        "scans.id",
    }

    assert _foreign_key_targets(
        table.c.tool_run_id
    ) == {
        "scan_tool_runs.id",
    }

    assert _foreign_key_targets(
        table.c.raw_evidence_id
    ) == {
        "scanner_evidence.id",
    }

    assert _foreign_key_targets(
        table.c.finding_id
    ) == {
        "findings.id",
    }

    assert table.c.scan_id.nullable is False
    assert table.c.raw_evidence_id.nullable is True
    assert table.c.finding_id.nullable is True
    assert table.c.engine.nullable is False
    assert table.c.title.nullable is False
    assert table.c.severity.nullable is False


def test_finding_occurrence_model_contract():
    model = _load_model(
        "app.models.finding_occurrence",
        "FindingOccurrence",
    )

    table = model.__table__

    assert table.name == (
        "finding_occurrences"
    )

    assert {
        "id",
        "finding_id",
        "scan_id",
        "state",
        "observed_at",
        "created_at",
        "updated_at",
    } <= set(
        table.c.keys()
    )

    assert _foreign_key_targets(
        table.c.finding_id
    ) == {
        "findings.id",
    }

    assert _foreign_key_targets(
        table.c.scan_id
    ) == {
        "scans.id",
    }

    unique_sets = {
        frozenset(
            column.name
            for column in constraint.columns
        )
        for constraint in table.constraints
        if isinstance(
            constraint,
            UniqueConstraint,
        )
    }

    assert frozenset(
        {
            "finding_id",
            "scan_id",
        }
    ) in unique_sets

    assert table.c.state.nullable is False
    assert table.c.observed_at.nullable is False


def test_correlation_decision_model_contract():
    model = _load_model(
        "app.models.correlation_decision",
        "CorrelationDecision",
    )

    table = model.__table__

    assert table.name == (
        "correlation_decisions"
    )

    assert {
        "id",
        "scan_id",
        "detection_a_id",
        "detection_b_id",
        "strategy_version",
        "decision",
        "reason",
        "candidate_identity",
        "confidence",
        "details",
        "created_at",
        "updated_at",
    } <= set(
        table.c.keys()
    )

    assert _foreign_key_targets(
        table.c.scan_id
    ) == {
        "scans.id",
    }

    assert _foreign_key_targets(
        table.c.detection_a_id
    ) == {
        "detections.id",
    }

    assert _foreign_key_targets(
        table.c.detection_b_id
    ) == {
        "detections.id",
    }

    assert table.c.strategy_version.nullable is False
    assert table.c.decision.nullable is False
    assert table.c.reason.nullable is False


def test_finding_has_nullable_engine_v2_canonical_metadata():
    from app.models.finding import Finding

    table = Finding.__table__

    legacy_columns = {
        "scan_id",
        "tool_run_id",
        "tool_name",
        "external_finding_id",
        "title",
        "severity",
        "evidence",
        "fingerprint",
        "status",
    }

    assert legacy_columns <= set(
        table.c.keys()
    )

    new_columns = {
        "target_id",
        "asset_identity",
        "canonical_type",
        "cve_ids",
        "cwe_ids",
        "affected_service",
        "affected_location",
        "affected_parameter",
        "impact",
        "first_seen",
        "last_seen",
        "source_count",
        "occurrence_count",
    }

    assert new_columns <= set(
        table.c.keys()
    )

    for column_name in new_columns:
        assert (
            table.c[
                column_name
            ].nullable
            is True
        )

    assert _foreign_key_targets(
        table.c.target_id
    ) == {
        "targets.id",
    }


def test_task12_models_are_registered_with_base_metadata():
    from app import models

    expected_classes = {
        "RawScannerEvidence",
        "Detection",
        "FindingOccurrence",
        "CorrelationDecision",
    }

    assert expected_classes <= {
        name
        for name in dir(models)
    }

    metadata_tables = set(
        models.Base.metadata.tables
    )

    assert {
        "scanner_evidence",
        "detections",
        "finding_occurrences",
        "correlation_decisions",
    } <= metadata_tables


def test_task12_migration_contract():
    path = Path(
        "alembic/versions/"
        "e6a1c4b92f37_add_detection_evidence_models.py"
    )

    assert path.is_file(), (
        "Task 12 Alembic migration does not exist yet"
    )

    namespace = runpy.run_path(
        str(path)
    )

    assert namespace[
        "revision"
    ] == "e6a1c4b92f37"

    assert namespace[
        "down_revision"
    ] == "7bdf4ab5b6d4"

    source = path.read_text(
        encoding="utf-8",
    )

    for table_name in (
        "scanner_evidence",
        "detections",
        "finding_occurrences",
        "correlation_decisions",
    ):
        assert table_name in source

    for column_name in (
        "target_id",
        "asset_identity",
        "canonical_type",
        "cve_ids",
        "cwe_ids",
        "affected_service",
        "affected_location",
        "affected_parameter",
        "impact",
        "first_seen",
        "last_seen",
        "source_count",
        "occurrence_count",
    ):
        assert column_name in source
