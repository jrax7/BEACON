"""Deterministic local-lab validation for BEACON Engine v2."""

from pathlib import Path


FIXTURE_ROOT = (
    Path(__file__).parent
    / "fixtures"
    / "engine_v2"
)

EXPECTED_ENGINE_FIXTURES = {
    "nmap": "nmap.xml",
    "httpx": "httpx.jsonl",
    "katana": "katana.jsonl",
    "sslyze": "sslyze.json",
    "nuclei": "nuclei.jsonl",
    "zap": "zap.json",
    "nikto": "nikto.json",
}

FORBIDDEN_SECRET_MARKERS = (
    b"authorization:",
    b"proxy-authorization:",
    b"bearer ",
    b"cookie:",
    b"set-cookie:",
    b"password=",
    b"passwd=",
    b"api_key=",
    b"apikey=",
    b"secret=",
)


def test_all_seven_engine_fixtures_exist_and_are_sanitized():
    """Every Engine v2 adapter has deterministic sanitized raw output."""

    assert FIXTURE_ROOT.is_dir()

    observed = {
        path.name
        for path in FIXTURE_ROOT.iterdir()
        if path.is_file()
        and path.name != "manifest.json"
    }

    assert observed == set(
        EXPECTED_ENGINE_FIXTURES.values()
    )

    for engine, filename in (
        EXPECTED_ENGINE_FIXTURES.items()
    ):
        fixture = (
            FIXTURE_ROOT
            / filename
        )

        raw = fixture.read_bytes()

        assert raw, (
            f"{engine} fixture must not be empty"
        )

        lowered = raw.lower()

        for marker in (
            FORBIDDEN_SECRET_MARKERS
        ):
            assert marker not in lowered, (
                f"{engine} fixture contains "
                f"forbidden secret marker "
                f"{marker!r}"
            )


def test_fixture_manifest_names_all_seven_engines():
    import json

    manifest_path = (
        FIXTURE_ROOT
        / "manifest.json"
    )

    manifest = json.loads(
        manifest_path.read_text(
            encoding="utf-8",
        )
    )

    engines = manifest[
        "engines"
    ]

    assert set(
        engines
    ) == set(
        EXPECTED_ENGINE_FIXTURES
    )

    for engine, filename in (
        EXPECTED_ENGINE_FIXTURES.items()
    ):
        assert (
            engines[engine][
                "fixture"
            ]
            == filename
        )

        assert (
            engines[engine][
                "sanitized"
            ]
            is True
        )

        assert (
            engines[engine][
                "deterministic"
            ]
            is True
        )


def test_fixture_nmap_parses_into_service_inventory():
    from app.assessment.handoff import (
        ServiceInventory,
    )
    from app.scanners.nmap import (
        parse_nmap_service_inventory,
    )

    raw = (
        FIXTURE_ROOT
        / "nmap.xml"
    ).read_bytes()

    scanner_version, inventory = (
        parse_nmap_service_inventory(
            raw,
            requested_hostname="lab-target",
        )
    )

    assert scanner_version == "7.95"

    assert isinstance(
        inventory,
        ServiceInventory,
    )

    assert len(
        inventory.services
    ) == 1

    service = inventory.services[0]

    assert service.host == "lab-target"
    assert service.ip == "127.0.0.1"
    assert service.port == 80
    assert service.transport == "tcp"
    assert service.service == "http"
    assert service.state == "open"


def test_fixture_httpx_parses_into_http_inventory():
    from app.assessment.handoff import (
        HTTPServiceInventory,
    )
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        FIXTURE_ROOT
        / "httpx.jsonl"
    ).read_bytes()

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1_000_000,
    )

    assert isinstance(
        inventory,
        HTTPServiceInventory,
    )

    assert len(
        inventory.services
    ) == 1

    service = inventory.services[0]

    assert service.url == (
        "http://lab-target:80"
    )

    assert service.host == "lab-target"
    assert service.port == 80
    assert service.scheme == "http"
    assert service.status_code == 200
    assert service.title == "BEACON Local Lab"


def test_fixture_katana_parses_into_web_endpoint_inventory():
    from app.assessment.handoff import (
        WebEndpointInventory,
    )
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    raw = (
        FIXTURE_ROOT
        / "katana.jsonl"
    ).read_bytes()

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "lab-target",
        ),
        max_output_bytes=1_000_000,
    )

    assert isinstance(
        inventory,
        WebEndpointInventory,
    )

    assert len(
        inventory.endpoints
    ) == 2

    by_url = {
        endpoint.url:
            endpoint
        for endpoint
        in inventory.endpoints
    }

    assert (
        "http://lab-target/"
        in by_url
    )

    assert (
        "http://lab-target/search?q=beacon"
        in by_url
    )

    search = by_url[
        "http://lab-target/search?q=beacon"
    ]

    assert search.method == "GET"

    assert search.parameter_names == (
        "q",
    )


def test_fixture_sslyze_parses_under_exact_tls_scope():
    from app.assessment.handoff import (
        TLSService,
        TLSServiceInventory,
    )
    from app.scanners.sslyze import (
        SslyzeAssessmentResult,
        parse_sslyze_json,
    )

    raw = (
        FIXTURE_ROOT
        / "sslyze.json"
    ).read_bytes()

    authorized = TLSServiceInventory(
        services=(
            TLSService(
                host="lab-target",
                ip="127.0.0.1",
                port=443,
            ),
        )
    )

    result = parse_sslyze_json(
        raw,
        authorized_services=authorized,
        max_output_bytes=2_000_000,
    )

    assert isinstance(
        result,
        SslyzeAssessmentResult,
    )

    assert result.scanner_version == (
        "6.3.1"
    )

    assert result.raw_json == raw

    assert len(
        result.servers
    ) == 1

    server = result.servers[0]

    assert server.host == "lab-target"
    assert server.ip == "127.0.0.1"
    assert server.port == 443

    assert server.connectivity_status == (
        "ERROR"
    )

    assert server.scan_status == (
        "ERROR_NO_CONNECTIVITY"
    )

    assert (
        result.detection_candidates
        == ()
    )


def test_fixture_nuclei_parses_against_immutable_snapshot():
    from types import SimpleNamespace

    from app.scanners.nuclei import (
        NucleiAssessmentResult,
        parse_nuclei_jsonl,
    )

    raw = (
        FIXTURE_ROOT
        / "nuclei.jsonl"
    ).read_bytes()

    snapshot = SimpleNamespace(
        template_manifest=[
            {
                "template_id":
                    "beacon-lab-header",
                "template_revision_or_digest":
                    "b" * 64,
                "template_source":
                    "beacon-local-lab",
                "template_path":
                    (
                        "http/misconfiguration/"
                        "beacon-lab-header.yaml"
                    ),
                "template_severity":
                    "low",
                "template_tags": [
                    "misconfig",
                    "beacon-lab",
                ],
                "protocol":
                    "http",
                "policy_group":
                    "BEACON_SAFE",
                "approved_profiles": [
                    "quick",
                    "standard",
                    "deep",
                ],
            }
        ]
    )

    result = parse_nuclei_jsonl(
        raw_jsonl=raw,
        snapshot=snapshot,
        max_output_bytes=1_000_000,
    )

    assert isinstance(
        result,
        NucleiAssessmentResult,
    )

    assert result.raw_jsonl == raw

    assert len(
        result.detection_candidates
    ) == 1

    candidate = (
        result
        .detection_candidates[0]
    )

    assert candidate.template_id == (
        "beacon-lab-header"
    )

    assert candidate.template_name == (
        "BEACON Local Lab Header Observation"
    )

    # Immutable snapshot provenance must win
    # over scanner-provided metadata.
    assert candidate.template_source == (
        "beacon-local-lab"
    )

    assert candidate.template_severity == (
        "low"
    )

    assert candidate.protocol == "http"

    assert candidate.host == (
        "http://lab-target"
    )

    assert candidate.matched_at == (
        "http://lab-target/"
    )


def test_fixture_zap_parses_into_detection_candidates():
    import json

    from app.scanners.zap import (
        ZapDetectionCandidate,
        parse_zap_alerts,
    )

    raw = (
        FIXTURE_ROOT
        / "zap.json"
    ).read_text(
        encoding="utf-8",
    )

    alerts = json.loads(
        raw
    )

    candidates = parse_zap_alerts(
        alerts=alerts,
        authorized_host="lab-target",
    )

    assert len(
        candidates
    ) == 1

    candidate = candidates[0]

    assert isinstance(
        candidate,
        ZapDetectionCandidate,
    )

    assert candidate.plugin_id == (
        "10021"
    )

    assert candidate.title == (
        "X-Content-Type-Options "
        "Header Missing"
    )

    assert candidate.severity == "low"

    assert candidate.affected_url == (
        "http://lab-target/"
    )


def test_fixture_nikto_parses_into_structured_findings():
    from app.scanners.nikto import (
        NiktoFindingResult,
        parse_nikto_json,
    )

    raw = (
        FIXTURE_ROOT
        / "nikto.json"
    ).read_bytes()

    (
        host,
        ip_address,
        port,
        server_banner,
        start_time,
        end_time,
        findings,
    ) = parse_nikto_json(
        raw
    )

    assert host == "lab-target"
    assert ip_address == "127.0.0.1"
    assert port == 80

    assert len(
        findings
    ) == 1

    finding = findings[0]

    assert isinstance(
        finding,
        NiktoFindingResult,
    )

    assert finding.finding_id == (
        "beacon-lab-header"
    )

    assert finding.method == "GET"
    assert finding.path == "/"

    assert (
        "X-Content-Type-Options"
        in finding.message
    )


def _fixture_zap_and_nikto_outputs():
    import json

    from types import SimpleNamespace

    from app.scanners.nikto import (
        NiktoAssessmentResult,
        NiktoScanResult,
        _nikto_detection_candidates,
        parse_nikto_json,
    )
    from app.scanners.zap import (
        parse_zap_alerts,
    )

    zap_raw = (
        FIXTURE_ROOT
        / "zap.json"
    ).read_text(
        encoding="utf-8",
    )

    zap_candidates = parse_zap_alerts(
        alerts=json.loads(
            zap_raw
        ),
        authorized_host="lab-target",
    )

    nikto_raw = (
        FIXTURE_ROOT
        / "nikto.json"
    ).read_bytes()

    (
        host,
        ip_address,
        port,
        server_banner,
        start_time,
        end_time,
        findings,
    ) = parse_nikto_json(
        nikto_raw
    )

    scan_result = NiktoScanResult(
        scanner_version="2.6.0",
        command_summary=(
            "deterministic local-lab fixture"
        ),
        target_url="http://lab-target/",
        host=host,
        ip_address=ip_address,
        port=port,
        server_banner=server_banner,
        start_time=start_time,
        end_time=end_time,
        raw_json=nikto_raw,
        console_output=(
            "1 requests: 0 errors "
            "and 1 items reported"
        ),
        reached_max_time=False,
        soft_404_detected=False,
        completed_requests=1,
        request_error_count=0,
        findings=findings,
    )

    nikto_candidates = (
        _nikto_detection_candidates(
            scan_result
        )
    )

    zap_output = SimpleNamespace(
        scanner_version="2.16.1",
        detection_candidates=(
            zap_candidates
        ),
    )

    nikto_output = NiktoAssessmentResult(
        scan_results=(
            scan_result,
        ),
        raw_evidence=(
            nikto_raw,
        ),
        detection_candidates=(
            nikto_candidates
        ),
    )

    return (
        zap_output,
        nikto_output,
    )


def test_fixture_zap_and_nikto_normalize_as_http_header_detections():
    from app.assessment.orchestration import (
        normalize_engine_v2_output,
    )

    (
        zap_output,
        nikto_output,
    ) = _fixture_zap_and_nikto_outputs()

    zap_records = (
        normalize_engine_v2_output(
            "zap",
            zap_output,
        )
    )

    nikto_records = (
        normalize_engine_v2_output(
            "nikto",
            nikto_output,
        )
    )

    assert len(
        zap_records
    ) == 1

    assert len(
        nikto_records
    ) == 1

    zap = zap_records[0]
    nikto = nikto_records[0]

    assert zap.engine == "zap"
    assert nikto.engine == "nikto"

    assert zap.rule_id == "10021"

    assert nikto.rule_id == (
        "beacon-lab-header"
    )

    assert zap.affected_location == (
        "http://lab-target/"
    )

    assert nikto.affected_location == (
        "http://lab-target/"
    )

    assert (
        zap.source_metadata[
            "canonical_type"
        ]
        == "http_header"
    )

    assert (
        nikto.source_metadata[
            "canonical_type"
        ]
        == "http_header"
    )

    assert (
        zap.source_metadata[
            "header_name"
        ].lower()
        == "x-content-type-options"
    )

    assert (
        nikto.source_metadata[
            "header_name"
        ].lower()
        == "x-content-type-options"
    )

    assert (
        zap.source_metadata[
            "weakness"
        ].lower()
        == "missing"
    )

    assert (
        nikto.source_metadata[
            "weakness"
        ].lower()
        == "missing"
    )

    assert (
        zap.asset_identity
        == nikto.asset_identity
    )


def test_fixture_zap_and_nikto_duplicate_header_correlates():
    from app.assessment.correlation import (
        CorrelationInput,
        decide_correlation,
    )
    from app.assessment.orchestration import (
        normalize_engine_v2_output,
    )

    (
        zap_output,
        nikto_output,
    ) = _fixture_zap_and_nikto_outputs()

    zap = normalize_engine_v2_output(
        "zap",
        zap_output,
    )[0]

    nikto = normalize_engine_v2_output(
        "nikto",
        nikto_output,
    )[0]

    def correlation_input(
        record,
        detection_id,
    ):
        metadata = (
            record.source_metadata
        )

        return CorrelationInput(
            detection_id=(
                detection_id
            ),
            engine=record.engine,
            rule_id=record.rule_id,
            title=record.title,
            canonical_type=(
                metadata.get(
                    "canonical_type"
                )
            ),
            asset_identity=(
                record.asset_identity
            ),
            affected_service=(
                record.affected_service
            ),
            affected_port=(
                record.affected_port
            ),
            affected_location=(
                record.affected_location
            ),
            affected_parameter=(
                record.affected_parameter
            ),
            cve_ids=record.cve_ids,
            cwe_ids=record.cwe_ids,
            source_metadata=metadata,
        )

    decision = decide_correlation(
        correlation_input(
            zap,
            "fixture-zap",
        ),
        correlation_input(
            nikto,
            "fixture-nikto",
        ),
    )

    assert decision.strategy == (
        "HTTPHeaderCorrelation"
    )

    assert decision.decision == (
        "merge"
    )

    assert decision.confidence == (
        "high"
    )

    assert decision.candidate_identity

    assert (
        "x-content-type-options"
        in decision.candidate_identity.lower()
    )



def _live_local_lab_enabled():
    import os

    return (
        os.getenv(
            "BEACON_RUN_LIVE_LOCAL_LAB"
        )
        == "1"
    )


def _live_local_lab_target():
    import os

    host = os.getenv(
        "BEACON_LIVE_LOCAL_LAB_HOST",
        "lab-target",
    )

    port = int(
        os.getenv(
            "BEACON_LIVE_LOCAL_LAB_PORT",
            "80",
        )
    )

    return host, port


def _live_local_lab_skip_reason():
    return (
        "opt-in live scanner validation; "
        "set BEACON_RUN_LIVE_LOCAL_LAB=1"
    )


def _pytest():
    import pytest

    return pytest


@_pytest().mark.live_local_lab
@_pytest().mark.skipif(
    not _live_local_lab_enabled(),
    reason=_live_local_lab_skip_reason(),
)
def test_live_local_lab_nmap_discovers_bounded_http_service():
    from app.scanners.nmap import (
        run_nmap_discovery,
    )

    host, port = (
        _live_local_lab_target()
    )

    result = run_nmap_discovery(
        target=host,
        ports=(port,),
        full_tcp=False,
        timeout_seconds=60,
    )

    assert result.raw_xml

    assert any(
        service.port == port
        and service.state == "open"
        for service
        in result.service_inventory.services
    )


@_pytest().mark.live_local_lab
@_pytest().mark.skipif(
    not _live_local_lab_enabled(),
    reason=_live_local_lab_skip_reason(),
)
def test_live_local_lab_nmap_handoff_is_classified_by_httpx():
    from app.scanners.httpx import (
        run_httpx_probe,
    )
    from app.scanners.nmap import (
        run_nmap_discovery,
    )

    host, port = (
        _live_local_lab_target()
    )

    nmap_result = run_nmap_discovery(
        target=host,
        ports=(port,),
        full_tcp=False,
        timeout_seconds=60,
    )

    inventory = run_httpx_probe(
        inventory=(
            nmap_result.service_inventory
        ),
        timeout_seconds=60,
        request_rate=5,
        max_output_bytes=1_000_000,
    )

    assert inventory.services

    assert any(
        service.port == port
        and service.scheme in {
            "http",
            "https",
        }
        and service.status_code == 200
        for service
        in inventory.services
    )
