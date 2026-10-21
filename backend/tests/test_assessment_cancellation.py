from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4


def test_cancel_before_next_stage_stops_orchestration():
    from app.assessment.orchestration import (
        AssessmentClaim,
        AssessmentOrchestrator,
    )
    from app.assessment.profiles import (
        get_assessment_profile,
    )

    profile = get_assessment_profile(
        "standard"
    )

    scan_id = uuid4()

    claim = AssessmentClaim(
        scan_id=scan_id,
        profile_name=profile.name,
        profile_version=profile.version,
        assessment_mode="standard",
        target_hostname="example.com",
        plan=object(),
    )

    class Store:
        def __init__(self):
            self.cancelled = False

        def claim(
            self,
            *,
            scan_id,
            celery_task_id,
        ):
            return claim

        def finish_cancelled(
            self,
            *,
            claim,
            reason,
        ):
            self.cancelled = True
            self.reason = reason

    class Runner:
        def __init__(self):
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

            return {
                "stage":
                    stage,
            }

    class Cancellation:
        def __init__(self):
            self.calls = 0

        def is_cancel_requested(
            self,
            *,
            scan_id,
        ):
            self.calls += 1

            # Scope authorization may execute.
            # Cancellation is observed immediately
            # before the first scanner stage.
            return self.calls >= 2

        def heartbeat(
            self,
            *,
            scan_id,
            engine,
        ):
            raise AssertionError(
                "No scanner should start after "
                "cancellation is observed."
            )

    store = Store()
    runner = Runner()

    orchestrator = AssessmentOrchestrator(
        store=store,
        runner=runner,
        cancellation_service=(
            Cancellation()
        ),
    )

    result = orchestrator.run(
        scan_id=scan_id
    )

    assert result.status == "cancelled"
    assert result.duplicate is False

    assert store.cancelled is True

    assert runner.calls == [
        "scope_authorization",
    ]


def test_process_cancellation_is_graceful_then_forced():
    import subprocess

    from app.assessment.cancellation import (
        AssessmentCancellationService,
    )

    calls = []

    class Process:
        def terminate(self):
            calls.append(
                "terminate"
            )

        def wait(
            self,
            timeout=None,
        ):
            calls.append(
                (
                    "wait",
                    timeout,
                )
            )

            wait_count = sum(
                1
                for call in calls
                if isinstance(
                    call,
                    tuple,
                )
                and call[0] == "wait"
            )

            if wait_count == 1:
                raise subprocess.TimeoutExpired(
                    cmd="scanner",
                    timeout=timeout,
                )

            return 0

        def kill(self):
            calls.append(
                "kill"
            )

    service = (
        AssessmentCancellationService()
    )

    result = service.terminate_process(
        Process(),
        grace_seconds=0.01,
    )

    assert result == "killed"

    assert calls == [
        "terminate",
        (
            "wait",
            0.01,
        ),
        "kill",
        (
            "wait",
            None,
        ),
    ]


def test_stale_heartbeat_marks_execution_interrupted():
    from app.assessment.cancellation import (
        AssessmentCancellationService,
    )

    now = datetime(
        2026,
        8,
        31,
        7,
        0,
        tzinfo=timezone.utc,
    )

    run = SimpleNamespace(
        id=uuid4(),
        scan_id=uuid4(),
        tool_name="nuclei",
        status="running",
        last_heartbeat_at=(
            now
            - timedelta(
                minutes=10
            )
        ),
        completed_at=None,
        failure_type=None,
        failure_message=None,
        error_message=None,
        lease_token="lease-token",
    )

    class ScalarResult:
        def all(self):
            return [
                run,
            ]

    class Session:
        def __init__(self):
            self.commits = 0

        def __enter__(self):
            return self

        def __exit__(
            self,
            exc_type,
            exc,
            tb,
        ):
            return False

        def scalars(
            self,
            statement,
        ):
            return ScalarResult()

        def commit(self):
            self.commits += 1

    session = Session()

    service = AssessmentCancellationService(
        session_factory=lambda: session,
        clock=lambda: now,
        stale_after_seconds=60,
    )

    recovered = (
        service.recover_stale_executions()
    )

    assert recovered == (
        str(
            run.id
        ),
    )

    assert run.status == "interrupted"

    assert (
        run.failure_type
        == "stale_heartbeat"
    )

    assert run.completed_at == now
    assert run.lease_token is None

    assert session.commits == 1


# TASK27_LIVE_CANCEL_RED_BEGIN
def test_running_engine_exception_after_cancel_is_classified_cancelled():
    """Cancellation during a scanner must outrank generic engine failure."""

    from uuid import uuid4

    from app.assessment.orchestration import (
        AssessmentClaim,
        AssessmentOrchestrator,
    )


    scan_id = uuid4()


    claim = AssessmentClaim(
        scan_id=scan_id,
        profile_name="standard",
        profile_version="standard-v1",
        assessment_mode="web",
        target_hostname="example.com",
        plan=object(),
    )


    class Cancellation:
        def __init__(self):
            self.requested = False

        def is_cancel_requested(
            self,
            *,
            scan_id,
        ):
            return self.requested

        def heartbeat(
            self,
            *,
            scan_id,
            engine,
        ):
            return True


    cancellation = Cancellation()


    class Store:
        def __init__(self):
            self.events = []

        def claim(
            self,
            *,
            scan_id,
            celery_task_id,
        ):
            return claim

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
            self.events.append(
                (
                    "fail_engine",
                    engine,
                )
            )

        def cancel_engine(
            self,
            *,
            claim,
            engine,
            reason,
        ):
            self.events.append(
                (
                    "cancel_engine",
                    engine,
                )
            )

        def skip_engine(
            self,
            *,
            claim,
            engine,
            reason,
        ):
            self.events.append(
                (
                    "skip_engine",
                    engine,
                )
            )

        def finish_success(
            self,
            *,
            claim,
            warnings,
        ):
            self.events.append(
                (
                    "finish_success",
                    None,
                )
            )

        def finish_failure(
            self,
            *,
            claim,
            reason,
        ):
            self.events.append(
                (
                    "finish_failure",
                    None,
                )
            )

        def finish_cancelled(
            self,
            *,
            claim,
            reason,
        ):
            self.events.append(
                (
                    "finish_cancelled",
                    None,
                )
            )


    class Runner:
        def run(
            self,
            *,
            stage,
            claim,
            context,
        ):
            if stage == "scope_authorization":
                return {
                    "authorized":
                        True,
                }

            if stage == "nmap":
                cancellation.requested = True

                raise RuntimeError(
                    "scanner stopped after "
                    "observing cancellation"
                )

            raise AssertionError(
                "No later stage should run "
                "after cancellation."
            )


    store = Store()


    result = AssessmentOrchestrator(
        store=store,
        runner=Runner(),
        cancellation_service=(
            cancellation
        ),
    ).run(
        scan_id=scan_id
    )


    assert result.status == "cancelled"

    assert (
        "cancel_engine",
        "nmap",
    ) in store.events

    assert not any(
        event[
            0
        ] == "fail_engine"
        for event
        in store.events
    )

    assert not any(
        event[
            0
        ] == "finish_failure"
        for event
        in store.events
    )

    assert (
        "finish_cancelled",
        None,
    ) in store.events
# TASK27_LIVE_CANCEL_RED_END
