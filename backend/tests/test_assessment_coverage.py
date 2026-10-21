import pytest


def _coverage():
    try:
        from app.assessment import coverage
    except ImportError as exc:
        pytest.fail(
            "Coverage telemetry module does not exist yet: "
            f"{exc}"
        )

    return coverage


def _telemetry():
    try:
        from app.assessment import telemetry
    except ImportError as exc:
        pytest.fail(
            "Engine contribution module does not exist yet: "
            f"{exc}"
        )

    return telemetry


def test_coverage_tracks_surfaces_engine_outcomes_and_gaps():
    coverage = _coverage()

    engines = (
        coverage.EngineCoverageState(
            engine="nmap",
            status="completed",
        ),
        coverage.EngineCoverageState(
            engine="httpx",
            status="failed",
            limitation="httpx parser failed",
        ),
        coverage.EngineCoverageState(
            engine="katana",
            status="timed_out",
        ),
        coverage.EngineCoverageState(
            engine="sslyze",
            status="skipped",
        ),
        coverage.EngineCoverageState(
            engine="zap",
            status="cancelled",
        ),
        coverage.EngineCoverageState(
            engine="nikto",
            status="interrupted",
        ),
    )

    summary = coverage.calculate_coverage(
        http_services_discovered=5,
        http_services_assessed=3,
        urls_discovered=40,
        urls_authorized=30,
        urls_assessed=24,
        tls_services_discovered=4,
        tls_services_assessed=3,
        engines=engines,
        limitations=(
            "Excluded out-of-scope redirects",
        ),
    )

    assert summary.http_services_discovered == 5
    assert summary.http_services_assessed == 3
    assert summary.http_services_unassessed == 2

    assert summary.urls_discovered == 40
    assert summary.urls_authorized == 30
    assert summary.urls_assessed == 24
    assert summary.urls_unassessed == 6

    assert summary.tls_services_discovered == 4
    assert summary.tls_services_assessed == 3
    assert summary.tls_services_unassessed == 1

    assert summary.engines_total == 6
    assert summary.engines_completed == 1
    assert summary.engines_failed == 1
    assert summary.engines_timed_out == 1
    assert summary.engines_skipped == 1
    assert summary.engines_cancelled == 1
    assert summary.engines_interrupted == 1

    assert summary.engines_incomplete == 4

    assert (
        "Excluded out-of-scope redirects"
        in summary.limitations
    )

    assert (
        "httpx parser failed"
        in summary.limitations
    )

    assert any(
        "katana" in limitation.lower()
        and "timed_out" in limitation.lower()
        for limitation in summary.limitations
    )


def test_coverage_rejects_impossible_or_negative_counts():
    coverage = _coverage()

    with pytest.raises(
        ValueError,
        match="non-negative",
    ):
        coverage.calculate_coverage(
            http_services_discovered=-1,
            http_services_assessed=0,
            urls_discovered=0,
            urls_authorized=0,
            urls_assessed=0,
            tls_services_discovered=0,
            tls_services_assessed=0,
        )

    with pytest.raises(
        ValueError,
        match="cannot exceed",
    ):
        coverage.calculate_coverage(
            http_services_discovered=2,
            http_services_assessed=3,
            urls_discovered=0,
            urls_authorized=0,
            urls_assessed=0,
            tls_services_discovered=0,
            tls_services_assessed=0,
        )

    with pytest.raises(
        ValueError,
        match="authorized",
    ):
        coverage.calculate_coverage(
            http_services_discovered=0,
            http_services_assessed=0,
            urls_discovered=10,
            urls_authorized=5,
            urls_assessed=6,
            tls_services_discovered=0,
            tls_services_assessed=0,
        )



def test_engine_contribution_distinguishes_unique_and_corroborating_findings():
    telemetry = _telemetry()

    results = telemetry.calculate_engine_contribution(
        (
            telemetry.EngineContributionInput(
                engine="nuclei",
                discovery_items=4,
                detections_generated=5,
                canonical_finding_ids=(
                    "finding-a",
                    "finding-shared",
                ),
            ),
            telemetry.EngineContributionInput(
                engine="zap",
                discovery_items=2,
                detections_generated=3,
                canonical_finding_ids=(
                    "finding-shared",
                    "finding-b",
                ),
            ),
        )
    )

    by_engine = {
        result.engine:
            result
        for result in results
    }

    nuclei = by_engine[
        "nuclei"
    ]

    assert nuclei.discovery_items_contributed == 4
    assert nuclei.detections_generated == 5
    assert nuclei.canonical_findings_supported == 2
    assert nuclei.unique_canonical_findings == 1
    assert (
        nuclei.corroborating_canonical_findings
        == 1
    )

    zap = by_engine[
        "zap"
    ]

    assert zap.canonical_findings_supported == 2
    assert zap.unique_canonical_findings == 1
    assert (
        zap.corroborating_canonical_findings
        == 1
    )


def test_engine_contribution_deduplicates_repeated_finding_support():
    telemetry = _telemetry()

    result = (
        telemetry.calculate_engine_contribution(
            (
                telemetry.EngineContributionInput(
                    engine="nikto",
                    discovery_items=0,
                    detections_generated=4,
                    canonical_finding_ids=(
                        "finding-a",
                        "finding-a",
                        "",
                        "   ",
                    ),
                ),
            )
        )[0]
    )

    assert result.canonical_findings_supported == 1
    assert result.unique_canonical_findings == 1
    assert (
        result.corroborating_canonical_findings
        == 0
    )


def test_engine_contribution_rejects_negative_counts():
    telemetry = _telemetry()

    with pytest.raises(
        ValueError,
        match="non-negative",
    ):
        telemetry.calculate_engine_contribution(
            (
                telemetry.EngineContributionInput(
                    engine="nuclei",
                    discovery_items=-1,
                    detections_generated=0,
                ),
            )
        )


def test_engine_contribution_rejects_duplicate_engine_rows_case_insensitively():
    telemetry = _telemetry()

    with pytest.raises(
        ValueError,
        match="duplicate",
    ):
        telemetry.calculate_engine_contribution(
            (
                telemetry.EngineContributionInput(
                    engine="ZAP",
                ),
                telemetry.EngineContributionInput(
                    engine="zap",
                ),
            )
        )
