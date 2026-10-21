from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)
import subprocess
from uuid import UUID

from sqlalchemy import select

from app.database import SessionLocal
from app.models.scan import Scan
from app.models.tool_run import ScanToolRun


TERMINAL_SCAN_STATUSES = {
    "completed",
    "failed",
    "cancelled",
}


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


class AssessmentCancellationService:
    """Cancellation, heartbeat, and stale execution recovery."""

    def __init__(
        self,
        *,
        session_factory=SessionLocal,
        clock=_utc_now,
        stale_after_seconds: int = 300,
    ) -> None:
        if stale_after_seconds <= 0:
            raise ValueError(
                "stale_after_seconds "
                "must be positive."
            )

        self.session_factory = (
            session_factory
        )

        self.clock = clock

        self.stale_after = timedelta(
            seconds=stale_after_seconds
        )

    def request_cancel(
        self,
        *,
        scan_id: UUID,
    ) -> bool:
        """Persist one idempotent cancellation request."""

        with self.session_factory() as database:
            scan = database.get(
                Scan,
                scan_id,
            )

            if scan is None:
                raise RuntimeError(
                    "The assessment does not exist."
                )

            status = str(
                scan.status
            ).strip().lower()

            if status in TERMINAL_SCAN_STATUSES:
                return False

            scan.status = "cancelling"

            database.commit()

            return True

    def is_cancel_requested(
        self,
        *,
        scan_id: UUID,
    ) -> bool:
        """Return whether cancellation has been requested."""

        with self.session_factory() as database:
            scan = database.get(
                Scan,
                scan_id,
            )

            if scan is None:
                raise RuntimeError(
                    "The assessment does not exist."
                )

            return (
                str(
                    scan.status
                ).strip().lower()
                in {
                    "cancelling",
                    "cancelled",
                }
            )

    def heartbeat(
        self,
        *,
        scan_id: UUID,
        engine: str,
    ) -> bool:
        """Refresh the latest running tool execution heartbeat."""

        with self.session_factory() as database:
            tool_run = database.scalar(
                select(
                    ScanToolRun
                )
                .where(
                    ScanToolRun.scan_id
                    == scan_id,
                    ScanToolRun.tool_name
                    == engine,
                    ScanToolRun.status
                    == "running",
                )
                .order_by(
                    ScanToolRun
                    .created_at
                    .desc()
                )
                .limit(
                    1
                )
            )

            if tool_run is None:
                return False

            tool_run.last_heartbeat_at = (
                self.clock()
            )

            database.commit()

            return True

    def terminate_process(
        self,
        process,
        *,
        grace_seconds: float = 5.0,
    ) -> str:
        """Terminate a subprocess gracefully, then force if needed."""

        if grace_seconds < 0:
            raise ValueError(
                "grace_seconds cannot "
                "be negative."
            )

        process.terminate()

        try:
            process.wait(
                timeout=grace_seconds
            )
        except subprocess.TimeoutExpired:
            process.kill()

            process.wait()

            return "killed"

        return "terminated"

    def recover_stale_executions(
        self,
    ) -> tuple[str, ...]:
        """Mark stale running tool executions interrupted."""

        now = self.clock()

        stale_before = (
            now
            - self.stale_after
        )

        recovered: list[str] = []

        with self.session_factory() as database:
            runs = list(
                database.scalars(
                    select(
                        ScanToolRun
                    )
                    .where(
                        ScanToolRun.status
                        == "running"
                    )
                ).all()
            )

            for tool_run in runs:
                heartbeat = (
                    tool_run.last_heartbeat_at
                )

                if heartbeat is None:
                    continue

                if heartbeat > stale_before:
                    continue

                tool_run.status = (
                    "interrupted"
                )

                tool_run.failure_type = (
                    "stale_heartbeat"
                )

                tool_run.failure_message = (
                    "Engine execution was "
                    "interrupted after its "
                    "heartbeat became stale."
                )

                tool_run.error_message = (
                    tool_run.failure_message
                )

                tool_run.completed_at = now
                tool_run.lease_token = None

                recovered.append(
                    str(
                        tool_run.id
                    )
                )

            if recovered:
                database.commit()

        return tuple(
            recovered
        )
