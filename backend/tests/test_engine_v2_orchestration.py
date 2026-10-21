from uuid import uuid4

import pytest


def _orchestration():
    try:
        from app.assessment import orchestration
    except ImportError as exc:
        pytest.fail(
            "Engine v2 orchestration module does not exist yet: "
            f"{exc}"
        )

    return orchestration


class FakeStore:
    def __init__(
        self,
        claim,
    ):
        self.claim_result = claim
        self.events = []
        self.failed_engines = []
        self.skipped_engines = []
        self.success_warnings = None
        self.failure_reason = None

    def claim(
        self,
        *,
        scan_id,
        celery_task_id,
    ):
        self.events.append(
            (
                "claim",
                scan_id,
                celery_task_id,
            )
        )

        return self.claim_result

    def start_engine(
        self,
        *,
        claim,
        engine,
    ):
        self.events.append(
            (
                "start_engine",
                engine,
            )
        )

    def complete_engine(
        self,
        *,
        claim,
        engine,
        output,
    ):
        self.events.append(
            (
                "complete_engine",
                engine,
            )
        )

    def fail_engine(
        self,
        *,
        claim,
        engine,
        error,
    ):
        self.failed_engines.append(
            engine
        )

        self.events.append(
            (
                "fail_engine",
                engine,
                str(error),
            )
        )

    def skip_engine(
        self,
        *,
        claim,
        engine,
        reason,
    ):
        self.skipped_engines.append(
            (
                engine,
                reason,
            )
        )

        self.events.append(
            (
                "skip_engine",
                engine,
                reason,
            )
        )

    def finish_success(
        self,
        *,
        claim,
        warnings,
    ):
        self.success_warnings = (
            tuple(
                warnings
            )
        )

        self.events.append(
            (
                "finish_success",
                self.success_warnings,
            )
        )

    def finish_failure(
        self,
        *,
        claim,
        reason,
    ):
        self.failure_reason = (
            reason
        )

        self.events.append(
            (
                "finish_failure",
                reason,
            )
        )


class RecordingRunner:
    def __init__(
        self,
        *,
        failures=(),
    ):
        self.failures = set(
            failures
        )
        self.calls = []

    def run(
        self,
        *,
        stage,
        claim,
        context,
    ):
        self.calls.append(
            stage
        )

        if stage in self.failures:
            raise RuntimeError(
                f"{stage} exploded"
            )

        return {
            "stage":
                stage,
        }


def _claim(
    orchestration,
    *,
    profile_name="standard",
    profile_version="standard-v1",
):
    return orchestration.AssessmentClaim(
        scan_id=uuid4(),
        profile_name=profile_name,
        profile_version=profile_version,
        assessment_mode="web",
        target_hostname="portal.example.com",
        plan=None,
    )


def test_standard_pipeline_runs_in_deterministic_engine_order():
    orchestration = _orchestration()

    claim = _claim(
        orchestration
    )

    store = FakeStore(
        claim
    )

    runner = RecordingRunner()

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=claim.scan_id,
            celery_task_id="celery-1",
        )
    )

    assert runner.calls == [
        "scope_authorization",
        "nmap",
        "httpx",
        "katana",
        "sslyze",
        "nuclei",
        "zap",
        "nikto",
        "normalization",
        "correlation",
        "coverage",
    ]

    assert result.status == "completed"
    assert result.duplicate is False

    assert (
        result.completed_with_warnings
        is False
    )

    assert result.failed_stage is None
    assert store.failure_reason is None
    assert store.success_warnings == ()


def test_optional_engine_failure_completes_with_warnings_and_continues():
    orchestration = _orchestration()

    claim = _claim(
        orchestration
    )

    store = FakeStore(
        claim
    )

    runner = RecordingRunner(
        failures={
            "nikto",
        }
    )

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=claim.scan_id,
            celery_task_id="celery-2",
        )
    )

    assert result.status == "completed"

    assert (
        result.completed_with_warnings
        is True
    )

    assert store.failed_engines == [
        "nikto",
    ]

    assert (
        "normalization"
        in runner.calls
    )

    assert (
        "correlation"
        in runner.calls
    )

    assert (
        "coverage"
        in runner.calls
    )

    assert any(
        "nikto" in warning.lower()
        for warning in result.warnings
    )


def test_required_engine_failure_stops_pipeline_and_skips_dependents():
    orchestration = _orchestration()

    claim = _claim(
        orchestration
    )

    store = FakeStore(
        claim
    )

    runner = RecordingRunner(
        failures={
            "httpx",
        }
    )

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=claim.scan_id,
            celery_task_id="celery-3",
        )
    )

    assert runner.calls == [
        "scope_authorization",
        "nmap",
        "httpx",
    ]

    assert result.status == "failed"
    assert result.failed_stage == "httpx"

    assert store.failed_engines == [
        "httpx",
    ]

    skipped_names = {
        engine
        for engine, _reason
        in store.skipped_engines
    }

    assert skipped_names == {
        "katana",
        "sslyze",
        "nuclei",
        "zap",
        "nikto",
    }

    assert store.failure_reason is not None

    assert (
        "required engine httpx failed"
        in store.failure_reason.lower()
    )


def test_duplicate_delivery_performs_zero_scanner_calls():
    orchestration = _orchestration()

    scan_id = uuid4()

    store = FakeStore(
        None
    )

    runner = RecordingRunner()

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=scan_id,
            celery_task_id="duplicate-delivery",
        )
    )

    assert result.status == "duplicate"
    assert result.duplicate is True

    assert runner.calls == []

    assert store.events == [
        (
            "claim",
            scan_id,
            "duplicate-delivery",
        ),
    ]


def test_quick_profile_records_nikto_as_disabled_without_running_it():
    orchestration = _orchestration()

    claim = _claim(
        orchestration,
        profile_name="quick",
        profile_version="quick-v1",
    )

    store = FakeStore(
        claim
    )

    runner = RecordingRunner()

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=claim.scan_id,
            celery_task_id="celery-quick",
        )
    )

    assert result.status == "completed"

    assert "nikto" not in runner.calls

    assert (
        "nikto",
        "disabled_by_profile",
    ) in store.skipped_engines


def test_profile_snapshot_version_mismatch_fails_before_scanner_execution():
    orchestration = _orchestration()

    claim = _claim(
        orchestration,
        profile_name="standard",
        profile_version="standard-v0-stale",
    )

    store = FakeStore(
        claim
    )

    runner = RecordingRunner()

    result = (
        orchestration.AssessmentOrchestrator(
            store=store,
            runner=runner,
        ).run(
            scan_id=claim.scan_id,
            celery_task_id="celery-stale",
        )
    )

    assert result.status == "failed"
    assert runner.calls == []

    assert store.failure_reason is not None

    assert (
        "profile version"
        in store.failure_reason.lower()
    )



def test_celery_configuration_declares_engine_v2_logical_queues():
    from app.celery_app import celery_app

    assert (
        celery_app.conf.worker_prefetch_multiplier
        == 1
    )

    queue_names = {
        queue.name
        for queue
        in celery_app.conf.task_queues
    }

    assert {
        "control",
        "discovery",
        "scanner",
        "report",
    }.issubset(
        queue_names
    )

    routes = celery_app.conf.task_routes

    assert routes[
        "beacon.run_assessment_v2"
    ][
        "queue"
    ] == "scanner"

    assert routes[
        "beacon.run_basic_scan"
    ][
        "queue"
    ] == "scanner"

    assert routes[
        "beacon.generate_scan_report"
    ][
        "queue"
    ] == "report"

    assert routes[
        "beacon.test_task"
    ][
        "queue"
    ] == "control"


def test_engine_v2_celery_entry_parses_uuid_and_delegates(
    monkeypatch,
):
    from app import tasks_v2

    scan_id = uuid4()

    observed = {}

    def fake_run_persisted(
        parsed_scan_id,
    ):
        observed[
            "scan_id"
        ] = parsed_scan_id

        return {
            "status":
                "completed",
        }

    monkeypatch.setattr(
        tasks_v2,
        "run_persisted_assessment_v2",
        fake_run_persisted,
    )

    result = (
        tasks_v2
        .run_assessment_v2
        .run(
            str(
                scan_id
            )
        )
    )

    assert observed[
        "scan_id"
    ] == scan_id

    assert result == {
        "status":
            "completed",
    }


def test_engine_v2_celery_entry_rejects_invalid_uuid_before_orchestration(
    monkeypatch,
):
    from app import tasks_v2

    called = False

    def fake_run_persisted(
        parsed_scan_id,
    ):
        nonlocal called
        called = True

        return {}

    monkeypatch.setattr(
        tasks_v2,
        "run_persisted_assessment_v2",
        fake_run_persisted,
    )

    with pytest.raises(
        ValueError,
        match="valid UUID",
    ):
        (
            tasks_v2
            .run_assessment_v2
            .run(
                "definitely-not-a-uuid"
            )
        )

    assert called is False



def test_existing_celery_tasks_declare_explicit_logical_queues():
    from app.tasks import (
        run_basic_scan,
        test_task,
    )

    assert test_task.queue == "control"
    assert run_basic_scan.queue == "scanner"


class _RecordingDatabase:
    def __init__(self):
        self.added = []
        self.commit_count = 0

    def add(self, value):
        self.added.append(
            value
        )

    def commit(self):
        self.commit_count += 1


class _FakeSessionContext:
    def __init__(self, database):
        self.database = database

    def __enter__(self):
        return self.database

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ):
        return False


def _database_store(
    monkeypatch,
    *,
    database,
    now,
    scan=None,
    plan=None,
    target=None,
    engine_run=None,
):
    from app.assessment.orchestration import (
        DatabaseOrchestrationStore,
    )

    store = DatabaseOrchestrationStore(
        session_factory=(
            lambda:
                _FakeSessionContext(
                    database
                )
        ),
        clock=lambda: now,
    )

    if scan is not None:
        monkeypatch.setattr(
            store,
            "_load_scan_for_update",
            lambda database, scan_id:
                scan,
        )

    monkeypatch.setattr(
        store,
        "_load_plan",
        lambda database, scan_id:
            plan,
    )

    monkeypatch.setattr(
        store,
        "_load_target",
        lambda database, target_id:
            target,
    )

    monkeypatch.setattr(
        store,
        "_load_engine_run_for_update",
        lambda database, scan_id, engine:
            engine_run,
    )

    return store


def test_database_store_claims_queued_scan_and_preserves_snapshot(
    monkeypatch,
):
    from datetime import (
        datetime,
        timedelta,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()
    target_id = uuid4()
    user_id = uuid4()
    organization_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        organization_id=organization_id,
        target_id=target_id,
        user_id=user_id,
        status="queued",
        profile="standard",
        profile_version="standard-v1",
        assessment_mode="web",
        active_testing_authorized_at=now,
        celery_task_id=None,
        engine_version=None,
        progress=0,
        started_at=None,
        completed_at=None,
        failure_reason="old failure",
        completed_with_warnings=True,
    )

    plan = SimpleNamespace(
        scan_id=scan_id,
        profile="standard",
        profile_version="standard-v1",
        assessment_mode="web",
        authorized_scope={
            "fqdn":
                "portal.example.com",
        },
        resolved_addresses=[
            "93.184.216.34",
        ],
        engine_policy_versions={
            "authorization":
                "active-v1",
            "zap":
                "beacon-standard-v1",
            "nuclei":
                "standard-v1",
        },
        crawl_policy={
            "depth":
                5,
        },
        rate_budget={
            "requests_per_second":
                10,
        },
        timeout_budget={
            "assessment_seconds":
                3600,
        },
        nuclei_template_snapshot_id=None,
        zap_policy_version=(
            "beacon-standard-v1"
        ),
    )

    target = SimpleNamespace(
        id=target_id,
        organization_id=organization_id,
        hostname=(
            "portal.example.com"
        ),
        normalized_url=(
            "https://portal.example.com"
        ),
        verification_status=(
            "verified"
        ),
        verification_expires_at=(
            now
            + timedelta(
                hours=1
            )
        ),
    )

    database = _RecordingDatabase()

    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        scan=scan,
        plan=plan,
        target=target,
    )

    claim = store.claim(
        scan_id=scan_id,
        celery_task_id=(
            "celery-delivery-1"
        ),
    )

    assert claim is not None

    assert claim.scan_id == scan_id
    assert claim.plan is plan
    assert claim.user_id == user_id
    assert claim.target_id == target_id

    assert (
        claim.target_hostname
        == "portal.example.com"
    )

    assert (
        claim.target_normalized_url
        == "https://portal.example.com"
    )

    assert (
        claim.scan_profile
        == "standard"
    )

    assert (
        claim.scan_profile_version
        == "standard-v1"
    )

    assert (
        claim.scan_assessment_mode
        == "web"
    )

    assert scan.status == "running"
    assert scan.started_at == now
    assert scan.completed_at is None

    assert (
        scan.failure_reason
        is None
    )

    assert (
        scan.completed_with_warnings
        is False
    )

    assert (
        scan.engine_version
        == "v2"
    )

    assert scan.progress >= 1

    assert (
        scan.celery_task_id
        == "celery-delivery-1"
    )

    assert database.commit_count == 1


def test_database_store_duplicate_running_delivery_is_noop(
    monkeypatch,
):
    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        status="running",
    )

    database = _RecordingDatabase()

    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        scan=scan,
    )

    claim = store.claim(
        scan_id=scan_id,
        celery_task_id=(
            "duplicate"
        ),
    )

    assert claim is None
    assert database.commit_count == 0
    assert database.added == []


def test_database_store_persists_engine_start_and_completion(
    monkeypatch,
):
    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )

    now = datetime.now(
        timezone.utc
    )

    database = _RecordingDatabase()

    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
    )

    claim = AssessmentClaim(
        scan_id=uuid4(),
        profile_name="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=object(),
    )

    store.start_engine(
        claim=claim,
        engine="nmap",
    )

    assert len(
        database.added
    ) == 1

    engine_run = (
        database.added[0]
    )

    assert (
        engine_run.scan_id
        == claim.scan_id
    )

    assert (
        engine_run.tool_name
        == "nmap"
    )

    assert (
        engine_run.status
        == "running"
    )

    assert (
        engine_run.queued_at
        == now
    )

    assert (
        engine_run.started_at
        == now
    )

    assert (
        engine_run.last_heartbeat_at
        == now
    )

    assert engine_run.lease_token

    monkeypatch.setattr(
        store,
        "_load_engine_run_for_update",
        lambda database, scan_id, engine:
            engine_run,
    )

    output = SimpleNamespace(
        scanner_version=(
            "nmap-7.95"
        ),
        artifact_path=(
            "scan/raw/nmap.xml"
        ),
        exit_code=0,
    )

    store.complete_engine(
        claim=claim,
        engine="nmap",
        output=output,
    )

    assert (
        engine_run.status
        == "completed"
    )

    assert (
        engine_run.tool_version
        == "nmap-7.95"
    )

    assert (
        engine_run.raw_output_path
        == "scan/raw/nmap.xml"
    )

    assert engine_run.exit_code == 0
    assert engine_run.completed_at == now
    assert database.commit_count == 2


def test_database_store_persists_engine_failure_without_losing_original_error(
    monkeypatch,
):
    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )

    now = datetime.now(
        timezone.utc
    )

    engine_run = SimpleNamespace(
        scan_id=uuid4(),
        tool_name="httpx",
        status="running",
        tool_version=None,
        exit_code=None,
        raw_output_path=None,
        error_message=None,
        failure_type=None,
        failure_message=None,
        started_at=now,
        queued_at=now,
        last_heartbeat_at=now,
        completed_at=None,
        lease_token="lease",
        skipped_reason=None,
        attempt=1,
    )

    database = _RecordingDatabase()

    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        engine_run=engine_run,
    )

    claim = AssessmentClaim(
        scan_id=engine_run.scan_id,
        profile_name="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=object(),
    )

    failure = RuntimeError(
        "probe exploded"
    )

    store.fail_engine(
        claim=claim,
        engine="httpx",
        error=failure,
    )

    assert (
        engine_run.status
        == "failed"
    )

    assert (
        engine_run.failure_type
        == "RuntimeError"
    )

    assert (
        engine_run.failure_message
        == "probe exploded"
    )

    assert (
        engine_run.error_message
        == "probe exploded"
    )

    assert (
        engine_run.completed_at
        == now
    )

    assert database.commit_count == 1


def test_database_store_persists_assessment_success_and_failure(
    monkeypatch,
):
    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )

    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        status="running",
        progress=50,
        completed_at=None,
        failure_reason="old",
        completed_with_warnings=False,
    )

    database = _RecordingDatabase()

    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        scan=scan,
    )

    claim = AssessmentClaim(
        scan_id=scan_id,
        profile_name="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=object(),
    )

    store.finish_success(
        claim=claim,
        warnings=(
            "Nikto failed",
        ),
    )

    assert scan.status == "completed"
    assert scan.progress == 100
    assert scan.completed_at == now

    assert (
        scan.completed_with_warnings
        is True
    )

    assert scan.failure_reason is None

    scan.status = "running"
    scan.progress = 70
    scan.completed_at = None
    scan.completed_with_warnings = False

    store.finish_failure(
        claim=claim,
        reason=(
            "Required engine failed"
        ),
    )

    assert scan.status == "failed"
    assert scan.completed_at == now

    assert (
        scan.failure_reason
        == "Required engine failed"
    )


def test_database_store_uses_short_sessions_and_row_locks():
    import inspect

    from app.assessment.orchestration import (
        DatabaseOrchestrationStore,
    )

    source = inspect.getsource(
        DatabaseOrchestrationStore
    )

    assert (
        "with self.session_factory() as database"
        in source
    )

    assert ".with_for_update()" in source


def test_production_scope_gate_rejects_missing_immutable_plan():
    from app.assessment.orchestration import (
        AssessmentClaim,
        ProductionStageRunner,
    )

    claim = AssessmentClaim(
        scan_id=uuid4(),
        profile_name="quick",
        profile_version="quick-v1",
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=None,
    )

    runner = ProductionStageRunner()

    with pytest.raises(
        RuntimeError,
        match="immutable",
    ):
        runner.run(
            stage=(
                "scope_authorization"
            ),
            claim=claim,
            context={},
        )


def test_production_scope_gate_accepts_matching_standard_snapshot():
    from datetime import (
        datetime,
        timedelta,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
        ProductionStageRunner,
    )

    now = datetime.now(
        timezone.utc
    )

    user_id = uuid4()
    target_id = uuid4()

    plan = SimpleNamespace(
        profile="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        authorized_scope={
            "fqdn":
                "portal.example.com",
        },
        resolved_addresses=[
            "93.184.216.34",
        ],
        engine_policy_versions={
            "authorization":
                "active-v1",
            "zap":
                "beacon-standard-v1",
            "nuclei":
                "standard-v1",
        },
    )

    claim = AssessmentClaim(
        scan_id=uuid4(),
        profile_name="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=plan,
        user_id=user_id,
        target_id=target_id,
        target_normalized_url=(
            "https://portal.example.com"
        ),
        target_verification_status=(
            "verified"
        ),
        target_verification_expires_at=(
            now
            + timedelta(
                hours=1
            )
        ),
        active_testing_authorized_at=now,
        scan_profile="standard",
        scan_profile_version=(
            "standard-v1"
        ),
        scan_assessment_mode="web",
    )

    runner = ProductionStageRunner(
        clock=lambda: now,
    )

    result = runner.run(
        stage="scope_authorization",
        claim=claim,
        context={},
    )

    assert result[
        "authorized_host"
    ] == "portal.example.com"

    assert result[
        "resolved_addresses"
    ] == (
        "93.184.216.34",
    )

    assert result[
        "active_testing"
    ] is True


def test_production_scope_gate_rejects_scan_plan_profile_mismatch():
    from datetime import (
        datetime,
        timedelta,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
        ProductionStageRunner,
    )

    now = datetime.now(
        timezone.utc
    )

    plan = SimpleNamespace(
        profile="quick",
        profile_version="quick-v1",
        assessment_mode="web",
        authorized_scope={
            "fqdn":
                "portal.example.com",
        },
        resolved_addresses=[
            "93.184.216.34",
        ],
        engine_policy_versions={},
    )

    claim = AssessmentClaim(
        scan_id=uuid4(),
        profile_name="standard",
        profile_version=(
            "standard-v1"
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=plan,
        user_id=uuid4(),
        target_id=uuid4(),
        target_normalized_url=(
            "https://portal.example.com"
        ),
        target_verification_status=(
            "verified"
        ),
        target_verification_expires_at=(
            now
            + timedelta(
                hours=1
            )
        ),
        active_testing_authorized_at=now,
        scan_profile="standard",
        scan_profile_version=(
            "standard-v1"
        ),
        scan_assessment_mode="web",
    )

    runner = ProductionStageRunner(
        clock=lambda: now,
    )

    with pytest.raises(
        RuntimeError,
        match="does not match",
    ):
        runner.run(
            stage=(
                "scope_authorization"
            ),
            claim=claim,
            context={},
        )


def _binding_claim(
    *,
    profile_name="standard",
    nuclei_snapshot_id=None,
):
    from datetime import (
        datetime,
        timedelta,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )

    now = datetime.now(
        timezone.utc
    )

    if nuclei_snapshot_id is None:
        nuclei_snapshot_id = uuid4()

    zap_versions = {
        "quick":
            "beacon-quick-v1",
        "standard":
            "beacon-standard-v1",
        "deep":
            "beacon-deep-v1",
    }

    profile_versions = {
        "quick":
            "quick-v1",
        "standard":
            "standard-v1",
        "deep":
            "deep-v1",
    }

    profile_version = (
        profile_versions[
            profile_name
        ]
    )

    plan = SimpleNamespace(
        profile=profile_name,
        profile_version=(
            profile_version
        ),
        assessment_mode="web",
        authorized_scope={
            "fqdn":
                "portal.example.com",
        },
        resolved_addresses=[
            "93.184.216.34",
        ],
        engine_policy_versions={
            "authorization":
                "active-v1",
            "nmap":
                f"{profile_name}-v1",
            "httpx":
                f"{profile_name}-v1",
            "katana":
                f"{profile_name}-v1",
            "sslyze":
                f"{profile_name}-v1",
            "nuclei":
                f"{profile_name}-v1",
            "zap":
                zap_versions[
                    profile_name
                ],
            "nikto":
                f"{profile_name}-v1",
        },
        crawl_policy={
            "depth":
                5,
            "crawl_duration_seconds":
                120,
            "max_response_bytes":
                1_000_000,
            "max_output_bytes":
                10_000_000,
        },
        rate_budget={
            "requests_per_second":
                10,
        },
        timeout_budget={
            "assessment_seconds":
                3600,
        },
        nuclei_template_snapshot_id=(
            nuclei_snapshot_id
        ),
        zap_policy_version=(
            zap_versions[
                profile_name
            ]
        ),
    )

    return AssessmentClaim(
        scan_id=uuid4(),
        profile_name=profile_name,
        profile_version=(
            profile_version
        ),
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=plan,
        user_id=uuid4(),
        target_id=uuid4(),
        target_normalized_url=(
            "https://portal.example.com"
        ),
        target_verification_status=(
            "verified"
        ),
        target_verification_expires_at=(
            now
            + timedelta(
                hours=1
            )
        ),
        active_testing_authorized_at=(
            now
            if profile_name
            in {
                "standard",
                "deep",
            }
            else None
        ),
        scan_profile=profile_name,
        scan_profile_version=(
            profile_version
        ),
        scan_assessment_mode="web",
    )


def _public_resolver(hostname):
    assert hostname == (
        "portal.example.com"
    )

    return (
        "93.184.216.34",
    )


def test_production_runner_binds_nmap_with_locked_web_policy():
    from types import SimpleNamespace

    from app.assessment.handoff import (
        DiscoveredService,
        ServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    calls = []

    inventory = ServiceInventory(
        services=(
            DiscoveredService(
                host=(
                    "portal.example.com"
                ),
                ip=(
                    "93.184.216.34"
                ),
                port=443,
                transport="tcp",
                service="https",
                tls_hint=True,
            ),
        )
    )

    def fake_nmap(**kwargs):
        calls.append(
            kwargs
        )

        return SimpleNamespace(
            scanner_version="7.95",
            command_summary="nmap",
            raw_xml=b"<nmaprun />",
            service_inventory=(
                inventory
            ),
        )

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    result = runner.run(
        stage="nmap",
        claim=claim,
        context={
            "scope_authorization": {
                "authorized_host":
                    "portal.example.com",
            },
        },
    )

    assert (
        result.service_inventory
        == inventory
    )

    assert len(calls) == 1

    assert calls[0] == {
        "target":
            "portal.example.com",
        "ports":
            (80, 443),
        "full_tcp":
            False,
        "timeout_seconds":
            600,
    }


def test_production_runner_rejects_dns_rebinding_before_nmap():
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    called = []

    def fake_nmap(**kwargs):
        called.append(
            kwargs
        )

        raise AssertionError(
            "Nmap must not run after "
            "resolution leaves the "
            "authorized snapshot."
        )

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=lambda hostname: (
            "127.0.0.1",
        ),
    )

    claim = _binding_claim()

    with pytest.raises(
        (
            ValueError,
            RuntimeError,
        ),
    ):
        runner.run(
            stage="nmap",
            claim=claim,
            context={},
        )

    assert called == []


def test_production_runner_httpx_consumes_only_nmap_inventory():
    from types import SimpleNamespace

    from app.assessment.handoff import (
        DiscoveredService,
        HTTPService,
        HTTPServiceInventory,
        ServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    service_inventory = ServiceInventory(
        services=(
            DiscoveredService(
                host=(
                    "portal.example.com"
                ),
                ip=(
                    "93.184.216.34"
                ),
                port=443,
                transport="tcp",
                service="https",
                tls_hint=True,
            ),
        )
    )

    expected = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    calls = []

    def fake_httpx(**kwargs):
        calls.append(
            kwargs
        )

        return expected

    runner = ProductionStageRunner(
        httpx_runner=fake_httpx,
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    result = runner.run(
        stage="httpx",
        claim=claim,
        context={
            "nmap":
                SimpleNamespace(
                    service_inventory=(
                        service_inventory
                    ),
                ),
        },
    )

    assert result == expected
    assert len(calls) == 1

    assert (
        calls[0][
            "inventory"
        ]
        == service_inventory
    )

    assert (
        calls[0][
            "timeout_seconds"
        ]
        == 300
    )

    assert (
        calls[0][
            "request_rate"
        ]
        == 10
    )

    assert (
        calls[0][
            "max_output_bytes"
        ]
        == 10_000_000
    )


def test_production_runner_katana_uses_immutable_crawl_budget():
    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    expected = WebEndpointInventory(
        endpoints=(
            WebEndpoint(
                url=(
                    "https://portal.example.com/login"
                ),
                method="GET",
            ),
        )
    )

    calls = []

    def fake_katana(**kwargs):
        calls.append(
            kwargs
        )

        return expected

    runner = ProductionStageRunner(
        katana_runner=fake_katana,
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    result = runner.run(
        stage="katana",
        claim=claim,
        context={
            "httpx":
                http_inventory,
        },
    )

    assert result == expected
    assert len(calls) == 1

    assert (
        calls[0][
            "inventory"
        ]
        == http_inventory
    )

    assert calls[0][
        "depth"
    ] == 5

    assert calls[0][
        "crawl_duration_seconds"
    ] == 120

    assert calls[0][
        "request_rate"
    ] == 10

    assert calls[0][
        "max_response_bytes"
    ] == 1_000_000

    assert calls[0][
        "max_output_bytes"
    ] == 10_000_000

    assert calls[0][
        "timeout_seconds"
    ] == 900


def test_production_runner_sslyze_receives_only_tls_capable_services():
    from types import SimpleNamespace

    from app.assessment.handoff import (
        DiscoveredService,
        HTTPService,
        HTTPServiceInventory,
        ServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    service_inventory = ServiceInventory(
        services=(
            DiscoveredService(
                host=(
                    "portal.example.com"
                ),
                ip=(
                    "93.184.216.34"
                ),
                port=80,
                transport="tcp",
                service="http",
                tls_hint=False,
            ),
            DiscoveredService(
                host=(
                    "portal.example.com"
                ),
                ip=(
                    "93.184.216.34"
                ),
                port=443,
                transport="tcp",
                service="https",
                tls_hint=True,
            ),
        )
    )

    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "http://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=80,
                scheme="http",
            ),
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    calls = []

    expected = SimpleNamespace(
        scanner_version="6",
        raw_json=b"{}",
        servers=(),
        detection_candidates=(),
    )

    def fake_sslyze(**kwargs):
        calls.append(
            kwargs
        )

        return expected

    runner = ProductionStageRunner(
        sslyze_runner=fake_sslyze,
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    result = runner.run(
        stage="sslyze",
        claim=claim,
        context={
            "nmap":
                SimpleNamespace(
                    service_inventory=(
                        service_inventory
                    ),
                ),
            "httpx":
                http_inventory,
        },
    )

    assert result is expected
    assert len(calls) == 1

    tls_inventory = (
        calls[0][
            "inventory"
        ]
    )

    assert len(
        tls_inventory.services
    ) == 1

    assert (
        tls_inventory
        .services[0]
        .port
        == 443
    )

    assert calls[0][
        "timeout_seconds"
    ] == 600

    assert calls[0][
        "max_output_bytes"
    ] == 10_000_000


def test_production_runner_nuclei_uses_snapshotted_template_set_and_authorized_urls():
    from types import SimpleNamespace

    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    snapshot = SimpleNamespace(
        id="snapshot",
    )

    calls = []

    def fake_nuclei(**kwargs):
        target_list = (
            kwargs[
                "target_list_path"
            ]
            .read_text(
                encoding="utf-8",
            )
            .splitlines()
        )

        calls.append(
            {
                **kwargs,
                "target_list":
                    target_list,
            }
        )

        return SimpleNamespace(
            raw_jsonl=b"",
            detection_candidates=(),
        )

    runner = ProductionStageRunner(
        nuclei_runner=fake_nuclei,
        nuclei_snapshot_loader=(
            lambda snapshot_id:
                snapshot
        ),
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    web_inventory = WebEndpointInventory(
        endpoints=(
            WebEndpoint(
                url=(
                    "https://portal.example.com/login"
                ),
                method="GET",
            ),
            WebEndpoint(
                url=(
                    "https://other.example.net/escape"
                ),
                method="GET",
            ),
        )
    )

    result = runner.run(
        stage="nuclei",
        claim=claim,
        context={
            "httpx":
                http_inventory,
            "katana":
                web_inventory,
        },
    )

    assert result.detection_candidates == ()
    assert len(calls) == 1

    assert calls[0][
        "snapshot"
    ] is snapshot

    assert calls[0][
        "target_list"
    ] == [
        "https://portal.example.com/",
        "https://portal.example.com/login",
    ]

    assert (
        calls[0][
            "allow_local_network_access"
        ]
        is False
    )

    assert calls[0][
        "timeout_seconds"
    ] == 1800

    assert calls[0][
        "max_output_bytes"
    ] == 10_000_000


def test_production_runner_nuclei_rejects_missing_snapshot_before_network():
    from types import SimpleNamespace

    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    calls = []

    def fake_nuclei(**kwargs):
        calls.append(
            kwargs
        )

        raise AssertionError(
            "Nuclei must not run "
            "without an immutable "
            "template snapshot."
        )

    claim = _binding_claim()

    claim.plan.nuclei_template_snapshot_id = (
        None
    )

    runner = ProductionStageRunner(
        nuclei_runner=fake_nuclei,
        nuclei_snapshot_loader=(
            lambda snapshot_id:
                None
        ),
        resolver=_public_resolver,
    )

    with pytest.raises(
        RuntimeError,
        match="snapshot",
    ):
        runner.run(
            stage="nuclei",
            claim=claim,
            context={
                "httpx":
                    SimpleNamespace(
                        services=(),
                    ),
                "katana":
                    SimpleNamespace(
                        endpoints=(),
                    ),
            },
        )

    assert calls == []


def test_production_runner_zap_uses_locked_policy_and_exact_fqdn_inventory():
    from types import SimpleNamespace

    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    requests = []

    class FakeZapClient:
        def run_assessment(
            self,
            request,
        ):
            requests.append(
                request
            )

            return SimpleNamespace(
                version="2.17.0",
                policy_version=(
                    request.policy_version
                ),
                active_scan_enabled=(
                    request.active_scan_enabled
                ),
                included_endpoint_count=(
                    len(
                        request
                        .web_inventory
                        .endpoints
                    )
                ),
                excluded_endpoint_count=0,
                spider_scan_ids=(),
                raw_alerts=(),
                detections=(),
            )

    runner = ProductionStageRunner(
        zap_client_factory=(
            FakeZapClient
        ),
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    web_inventory = WebEndpointInventory(
        endpoints=(
            WebEndpoint(
                url=(
                    "https://portal.example.com/login"
                ),
                method="POST",
                parameter_names=(
                    "username",
                ),
            ),
            WebEndpoint(
                url=(
                    "https://evil.example.net/"
                ),
                method="GET",
            ),
        )
    )

    result = runner.run(
        stage="zap",
        claim=claim,
        context={
            "httpx":
                http_inventory,
            "katana":
                web_inventory,
        },
    )

    assert result.active_scan_enabled is True

    assert len(requests) == 1

    request = requests[0]

    assert (
        request.authorized_host
        == "portal.example.com"
    )

    assert (
        request.policy_version
        == "beacon-standard-v1"
    )

    assert (
        request.active_scan_enabled
        is True
    )

    assert (
        request.execution_id
        == str(
            claim.scan_id
        )
    )

    urls = [
        endpoint.url
        for endpoint
        in request
        .web_inventory
        .endpoints
    ]

    assert urls == [
        "https://portal.example.com/",
        "https://portal.example.com/login",
    ]


def test_production_runner_rejects_zap_policy_snapshot_mismatch():
    from types import SimpleNamespace

    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    claim = _binding_claim()

    claim.plan.zap_policy_version = (
        "wrong-policy-v1"
    )

    runner = ProductionStageRunner(
        zap_client_factory=(
            lambda:
                SimpleNamespace(
                    run_assessment=(
                        lambda request:
                            None
                    ),
                )
        ),
        resolver=_public_resolver,
    )

    with pytest.raises(
        RuntimeError,
        match="policy",
    ):
        runner.run(
            stage="zap",
            claim=claim,
            context={
                "httpx":
                    SimpleNamespace(
                        services=(),
                    ),
                "katana":
                    SimpleNamespace(
                        endpoints=(),
                    ),
            },
        )


def test_production_runner_nikto_receives_only_http_inventory():
    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )

    calls = []

    def fake_nikto(**kwargs):
        calls.append(
            kwargs
        )

        return SimpleNamespace(
            scan_results=(),
            raw_evidence=(),
            detection_candidates=(),
        )

    from types import SimpleNamespace

    runner = ProductionStageRunner(
        nikto_runner=fake_nikto,
        resolver=_public_resolver,
    )

    claim = _binding_claim()

    result = runner.run(
        stage="nikto",
        claim=claim,
        context={
            "httpx":
                http_inventory,
        },
    )

    assert result.detection_candidates == ()

    assert calls == [
        {
            "profile_name":
                "standard",
            "inventory":
                http_inventory,
        }
    ]

# TASK16_FINAL_POSTPROCESSING_TESTS


def test_task16_final_json_safe_encodes_bytes():
    from app.assessment.orchestration import (
        _json_safe,
    )

    result = _json_safe(
        {
            "raw": b"\x00\x01BEACON",
        }
    )

    assert result == {
        "raw": {
            "encoding": "base64",
            "data": "AAFCRUFDT04=",
        }
    }


def test_task16_final_normalizer_maps_zap_candidate():
    from types import SimpleNamespace

    from app.assessment.orchestration import (
        normalize_engine_v2_output,
    )

    output = SimpleNamespace(
        version="2.16.1",
        detections=(
            SimpleNamespace(
                plugin_id="10020",
                title=(
                    "X-Frame-Options "
                    "Header Not Set"
                ),
                severity="medium",
                confidence="medium",
                affected_url=(
                    "https://"
                    "portal.example.com/login"
                ),
                cwe_id="CWE-1021",
                http_method="GET",
                parameter=None,
                evidence="missing header",
                attack=None,
                description=(
                    "Header is absent."
                ),
                remediation=(
                    "Set an appropriate "
                    "frame policy."
                ),
                reference=None,
                message_id="1",
                source_id="3",
                wasc_id="15",
            ),
        ),
    )

    records = (
        normalize_engine_v2_output(
            "zap",
            output,
        )
    )

    assert len(records) == 1

    record = records[0]

    assert record.engine == "zap"
    assert record.engine_version == "2.16.1"
    assert record.rule_id == "10020"
    assert record.severity == "medium"
    assert record.asset_identity == (
        "portal.example.com"
    )
    assert record.affected_service == "https"
    assert record.affected_port == 443
    assert record.affected_location == (
        "https://portal.example.com/login"
    )
    assert record.cwe_ids == (
        "CWE-1021",
    )


def test_task16_final_pipeline_runner_delegates_by_stage():
    from types import SimpleNamespace

    from app.assessment.orchestration import (
        ProductionPipelineRunner,
    )

    calls = []

    scanner = SimpleNamespace(
        run=lambda **kwargs: (
            calls.append(
                (
                    "scanner",
                    kwargs["stage"],
                )
            )
            or "scanner-result"
        )
    )

    postprocessor = SimpleNamespace(
        run=lambda **kwargs: (
            calls.append(
                (
                    "post",
                    kwargs["stage"],
                )
            )
            or "post-result"
        )
    )

    runner = ProductionPipelineRunner(
        scanner_runner=scanner,
        post_processor=postprocessor,
    )

    assert runner.run(
        stage="nmap",
        claim=object(),
        context={},
    ) == "scanner-result"

    assert runner.run(
        stage="normalization",
        claim=object(),
        context={},
    ) == "post-result"

    assert calls == [
        (
            "scanner",
            "nmap",
        ),
        (
            "post",
            "normalization",
        ),
    ]


def test_task16_final_postprocessor_preserves_pipeline_order():
    import inspect

    from app.assessment.orchestration import (
        PersistedPostProcessingRunner,
    )

    source = inspect.getsource(
        PersistedPostProcessingRunner
    )

    assert "RawScannerEvidence(" in source
    assert "Detection(" in source
    assert "decide_correlation(" in source
    assert "CorrelationDecision(" in source
    assert "Finding(" in source
    assert "FindingOccurrence(" in source
    assert "calculate_coverage(" in source

    assert source.index(
        "RawScannerEvidence("
    ) < source.index(
        "Detection("
    )

    assert "urls_assessed=" in source
    assert "urls_actively_assessed=" not in source


def test_task16_final_persisted_runner_is_fully_wired():
    import inspect

    from app.assessment.orchestration import (
        run_persisted_assessment_v2,
    )

    source = inspect.getsource(
        run_persisted_assessment_v2
    )

    assert "not complete yet" not in source

    assert (
        "DatabaseOrchestrationStore("
        in source
    )

    assert "ProductionStageRunner(" in source

    assert (
        "PersistedPostProcessingRunner("
        in source
    )

    assert "ProductionPipelineRunner(" in source

    assert "AssessmentOrchestrator(" in source

    assert ".to_dict()" in source


# TASK27_LIVE_CANCEL_RED_BEGIN
def test_production_nikto_binds_assessment_cancellation_callback():
    """Production Nikto must query the same persisted cancellation service."""

    from types import SimpleNamespace

    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )


    claim = _binding_claim()


    http_inventory = HTTPServiceInventory(
        services=(
            HTTPService(
                url=(
                    "https://portal.example.com/"
                ),
                host=(
                    "portal.example.com"
                ),
                port=443,
                scheme="https",
            ),
        )
    )


    class Cancellation:
        def __init__(self):
            self.calls = []

        def is_cancel_requested(
            self,
            *,
            scan_id,
        ):
            self.calls.append(
                scan_id
            )

            return True


    cancellation = Cancellation()

    captured = []


    def fake_nikto(**kwargs):
        captured.append(
            kwargs
        )

        return SimpleNamespace(
            scan_results=(),
            raw_evidence=(),
            detection_candidates=(),
        )


    runner = ProductionStageRunner(
        nikto_runner=fake_nikto,
        resolver=_public_resolver,
        cancellation_service=(
            cancellation
        ),
    )


    result = runner.run(
        stage="nikto",
        claim=claim,
        context={
            "httpx":
                http_inventory,
        },
    )


    assert (
        result.detection_candidates
        == ()
    )

    assert len(
        captured
    ) == 1

    callback = captured[
        0
    ][
        "cancellation_callback"
    ]


    assert callable(
        callback
    )

    assert callback() is True

    assert cancellation.calls == [
        claim.scan_id,
    ]


def test_database_store_persists_assessment_cancelled_terminal_state(
    monkeypatch,
):
    """Celery cancellation and PostgreSQL cancellation must agree."""

    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )


    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()


    scan = SimpleNamespace(
        id=scan_id,
        status="cancelling",
        progress=1,
        completed_at=None,
        failure_reason=None,
        completed_with_warnings=False,
    )


    database = _RecordingDatabase()


    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        scan=scan,
    )


    claim = AssessmentClaim(
        scan_id=scan_id,
        profile_name="deep",
        profile_version="deep-v1",
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=object(),
    )


    store.finish_cancelled(
        claim=claim,
        reason=(
            "Assessment cancellation "
            "was requested."
        ),
    )


    assert scan.status == "cancelled"

    assert (
        scan.failure_reason
        == "Assessment cancellation was requested."
    )

    assert scan.completed_at == now

    assert database.commit_count == 1


def test_database_store_persists_running_engine_cancelled_terminal_state(
    monkeypatch,
):
    """The engine interrupted by cancellation must be marked cancelled."""

    from datetime import (
        datetime,
        timezone,
    )
    from types import SimpleNamespace
    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
    )


    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()


    engine_run = SimpleNamespace(
        id=uuid4(),
        scan_id=scan_id,
        tool_name="nikto",
        status="running",
        queued_at=now,
        started_at=now,
        last_heartbeat_at=now,
        completed_at=None,
        cancelled_at=None,
        lease_token="lease",
        exit_code=None,
        error_message=None,
        failure_type=None,
        failure_message=None,
        skipped_reason=None,
        attempt=1,
    )


    database = _RecordingDatabase()


    store = _database_store(
        monkeypatch,
        database=database,
        now=now,
        engine_run=engine_run,
    )


    claim = AssessmentClaim(
        scan_id=scan_id,
        profile_name="deep",
        profile_version="deep-v1",
        assessment_mode="web",
        target_hostname=(
            "portal.example.com"
        ),
        plan=object(),
    )


    store.cancel_engine(
        claim=claim,
        engine="nikto",
        reason=(
            "Assessment cancellation "
            "was requested."
        ),
    )


    assert engine_run.status == "cancelled"

    assert engine_run.cancelled_at == now

    assert engine_run.completed_at == now

    assert engine_run.last_heartbeat_at == now

    assert engine_run.lease_token is None

    assert (
        engine_run.failure_message
        == "Assessment cancellation was requested."
    )

    assert (
        engine_run.error_message
        == "Assessment cancellation was requested."
    )

    assert database.commit_count == 1
# TASK27_LIVE_CANCEL_RED_END


# TASK27_LIVE_CANCEL_BRIDGE_RED_BEGIN
def test_persisted_runner_shares_cancellation_service_with_scanner():
    """The scanner runner and orchestrator must observe the same service."""

    import inspect

    from app.assessment.orchestration import (
        run_persisted_assessment_v2,
    )


    source = inspect.getsource(
        run_persisted_assessment_v2
    )


    service_index = source.index(
        "cancellation_service ="
    )

    scanner_index = source.index(
        "scanner_runner ="
    )


    assert (
        service_index
        < scanner_index
    )


    scanner_end = source.index(
        "post_processor =",
        scanner_index,
    )

    scanner_binding = source[
        scanner_index:
        scanner_end
    ]


    assert (
        "cancellation_service"
        in scanner_binding
    )
# TASK27_LIVE_CANCEL_BRIDGE_RED_END
