from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class EngineContributionInput:
    """Raw contribution measurements for one assessment engine."""

    engine: str
    discovery_items: int = 0
    detections_generated: int = 0
    canonical_finding_ids: tuple[
        str,
        ...
    ] = ()


@dataclass(frozen=True)
class EngineContributionResult:
    """Unique and corroborating value contributed by one engine."""

    engine: str
    discovery_items_contributed: int
    detections_generated: int
    canonical_findings_supported: int
    unique_canonical_findings: int
    corroborating_canonical_findings: int


def _canonical_finding_ids(
    values: Iterable[str],
) -> frozenset[str]:
    return frozenset(
        normalized
        for value in values
        if (
            normalized := str(
                value
            ).strip()
        )
    )


def calculate_engine_contribution(
    contributions: Iterable[
        EngineContributionInput
    ],
) -> tuple[
    EngineContributionResult,
    ...
]:
    """Calculate per-engine unique and corroborating contribution."""

    items = tuple(
        contributions
    )

    prepared: list[
        tuple[
            EngineContributionInput,
            str,
            frozenset[str],
        ]
    ] = []

    engine_keys: set[str] = set()

    for item in items:
        engine = item.engine.strip()
        engine_key = engine.lower()

        if not engine:
            raise ValueError(
                "Engine contribution requires "
                "a non-empty engine name."
            )

        if engine_key in engine_keys:
            raise ValueError(
                "duplicate engine contribution row: "
                f"{engine}"
            )

        if (
            item.discovery_items < 0
            or item.detections_generated < 0
        ):
            raise ValueError(
                "Engine contribution counts "
                "must be non-negative."
            )

        engine_keys.add(
            engine_key
        )

        prepared.append(
            (
                item,
                engine,
                _canonical_finding_ids(
                    item.canonical_finding_ids
                ),
            )
        )

    supporters: dict[
        str,
        set[str],
    ] = defaultdict(
        set
    )

    for (
        _item,
        engine,
        finding_ids,
    ) in prepared:
        engine_key = engine.lower()

        for finding_id in finding_ids:
            supporters[
                finding_id
            ].add(
                engine_key
            )

    results: list[
        EngineContributionResult
    ] = []

    for (
        item,
        engine,
        finding_ids,
    ) in prepared:
        engine_key = engine.lower()

        unique_count = sum(
            1
            for finding_id in finding_ids
            if supporters[
                finding_id
            ] == {
                engine_key,
            }
        )

        corroborating_count = sum(
            1
            for finding_id in finding_ids
            if len(
                supporters[
                    finding_id
                ]
            ) > 1
        )

        results.append(
            EngineContributionResult(
                engine=engine,
                discovery_items_contributed=(
                    item.discovery_items
                ),
                detections_generated=(
                    item.detections_generated
                ),
                canonical_findings_supported=len(
                    finding_ids
                ),
                unique_canonical_findings=(
                    unique_count
                ),
                corroborating_canonical_findings=(
                    corroborating_count
                ),
            )
        )

    return tuple(
        results
    )
