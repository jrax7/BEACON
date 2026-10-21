from uuid import UUID

from app.assessment.orchestration import (
    run_persisted_assessment_v2,
)
from app.celery_app import celery_app


@celery_app.task(
    name="beacon.run_assessment_v2",
    queue="scanner",
)
def run_assessment_v2(
    scan_id: str,
) -> dict[str, object]:
    """Thin Celery transport boundary for Engine v2 assessments."""

    try:
        scan_uuid = UUID(
            scan_id
        )
    except (
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        raise ValueError(
            "Engine v2 scan_id must be a valid UUID."
        ) from exc

    return (
        run_persisted_assessment_v2(
            scan_uuid
        )
    )

# TASK17_CANCELLATION_ENTRY_POINTS

from uuid import UUID as _Task17UUID

from app.assessment.cancellation import (
    AssessmentCancellationService as _Task17CancellationService,
)


def request_assessment_v2_cancellation(
    scan_id: _Task17UUID,
) -> dict[str, object]:
    """Request cooperative cancellation for one Engine v2 scan."""

    requested = (
        _Task17CancellationService()
        .request_cancel(
            scan_id=scan_id
        )
    )

    return {
        "scan_id":
            str(
                scan_id
            ),
        "cancellation_requested":
            requested,
    }


def recover_stale_assessment_v2_executions(
) -> dict[str, object]:
    """Recover stale Engine v2 tool executions."""

    recovered = (
        _Task17CancellationService()
        .recover_stale_executions()
    )

    return {
        "recovered_execution_ids":
            list(
                recovered
            ),
        "recovered_count":
            len(
                recovered
            ),
    }
