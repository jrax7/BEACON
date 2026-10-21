from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass


ENGINE_STATUSES = frozenset(
    {
        "completed",
        "failed",
        "timed_out",
        "skipped",
        "cancelled",
        "interrupted",
    }
)


@dataclass(frozen=True)
class EngineCoverageState:
    """One engine's final contribution to assessment coverage."""

    engine: str
    status: str
    limitation: str | None = None


@dataclass(frozen=True)
class CoverageSummaryData:
    """Transparent coverage measurements for one assessment."""

    http_services_discovered: int
    http_services_assessed: int
    http_services_unassessed: int

    urls_discovered: int
    urls_authorized: int
    urls_assessed: int
    urls_unassessed: int

    tls_services_discovered: int
    tls_services_assessed: int
    tls_services_unassessed: int

    engines_total: int
    engines_completed: int
    engines_failed: int
    engines_timed_out: int
    engines_skipped: int
    engines_cancelled: int
    engines_interrupted: int
    engines_incomplete: int

    limitations: tuple[str, ...]


def _require_non_negative(
    **counts: int,
) -> None:
    for name, value in counts.items():
        if value < 0:
            raise ValueError(
                f"{name} must be non-negative."
            )


def _clean_limitations(
    values: Iterable[str],
) -> tuple[str, ...]:
    cleaned: list[str] = []
    seen: set[str] = set()

    for value in values:
        normalized = str(
            value
        ).strip()

        if (
            not normalized
            or normalized in seen
        ):
            continue

        seen.add(
            normalized
        )
        cleaned.append(
            normalized
        )

    return tuple(
        cleaned
    )


def calculate_coverage(
    *,
    http_services_discovered: int,
    http_services_assessed: int,
    urls_discovered: int,
    urls_authorized: int,
    urls_assessed: int,
    tls_services_discovered: int,
    tls_services_assessed: int,
    engines: Iterable[
        EngineCoverageState
    ] = (),
    limitations: Iterable[str] = (),
) -> CoverageSummaryData:
    """Calculate transparent assessment coverage without persistence."""

    _require_non_negative(
        http_services_discovered=(
            http_services_discovered
        ),
        http_services_assessed=(
            http_services_assessed
        ),
        urls_discovered=(
            urls_discovered
        ),
        urls_authorized=(
            urls_authorized
        ),
        urls_assessed=(
            urls_assessed
        ),
        tls_services_discovered=(
            tls_services_discovered
        ),
        tls_services_assessed=(
            tls_services_assessed
        ),
    )

    if (
        http_services_assessed
        > http_services_discovered
    ):
        raise ValueError(
            "HTTP services assessed cannot exceed "
            "HTTP services discovered."
        )

    if (
        urls_authorized
        > urls_discovered
    ):
        raise ValueError(
            "Authorized URLs cannot exceed "
            "discovered URLs."
        )

    if (
        urls_assessed
        > urls_authorized
    ):
        raise ValueError(
            "URLs assessed cannot exceed "
            "authorized URLs."
        )

    if (
        tls_services_assessed
        > tls_services_discovered
    ):
        raise ValueError(
            "TLS services assessed cannot exceed "
            "TLS services discovered."
        )

    engine_states = tuple(
        engines
    )

    status_counter: Counter[str] = (
        Counter()
    )

    derived_limitations: list[str] = list(
        limitations
    )

    for state in engine_states:
        engine = state.engine.strip()
        status = state.status.strip().lower()

        if not engine:
            raise ValueError(
                "Engine coverage state requires "
                "a non-empty engine name."
            )

        if status not in ENGINE_STATUSES:
            raise ValueError(
                "Unsupported engine coverage status: "
                f"{state.status}"
            )

        status_counter[
            status
        ] += 1

        if state.limitation:
            derived_limitations.append(
                state.limitation
            )
        elif status != "completed":
            derived_limitations.append(
                f"{engine}: {status}"
            )

    incomplete_statuses = (
        "failed",
        "timed_out",
        "cancelled",
        "interrupted",
    )

    engines_incomplete = sum(
        status_counter[
            status
        ]
        for status
        in incomplete_statuses
    )

    return CoverageSummaryData(
        http_services_discovered=(
            http_services_discovered
        ),
        http_services_assessed=(
            http_services_assessed
        ),
        http_services_unassessed=(
            http_services_discovered
            - http_services_assessed
        ),
        urls_discovered=(
            urls_discovered
        ),
        urls_authorized=(
            urls_authorized
        ),
        urls_assessed=(
            urls_assessed
        ),
        urls_unassessed=(
            urls_authorized
            - urls_assessed
        ),
        tls_services_discovered=(
            tls_services_discovered
        ),
        tls_services_assessed=(
            tls_services_assessed
        ),
        tls_services_unassessed=(
            tls_services_discovered
            - tls_services_assessed
        ),
        engines_total=len(
            engine_states
        ),
        engines_completed=status_counter[
            "completed"
        ],
        engines_failed=status_counter[
            "failed"
        ],
        engines_timed_out=status_counter[
            "timed_out"
        ],
        engines_skipped=status_counter[
            "skipped"
        ],
        engines_cancelled=status_counter[
            "cancelled"
        ],
        engines_interrupted=status_counter[
            "interrupted"
        ],
        engines_incomplete=(
            engines_incomplete
        ),
        limitations=_clean_limitations(
            derived_limitations
        ),
    )
