import json
from dataclasses import FrozenInstanceError, asdict
from datetime import datetime, timezone
from uuid import uuid4

import pytest


def test_scanner_health_is_immutable():
    from app.scanners.base import ScannerHealth

    health = ScannerHealth(
        name="nmap",
        version="7.95",
        healthy=True,
        message="ready",
        checked_at=datetime.now(timezone.utc),
    )

    with pytest.raises(FrozenInstanceError):
        health.healthy = False


def test_scanner_artifact_records_bounded_metadata():
    from app.scanners.base import ScannerArtifact

    artifact = ScannerArtifact(
        relative_path="scan-id/nmap/nmap.xml",
        sha256="a" * 64,
        size_bytes=4096,
    )

    assert artifact.relative_path == (
        "scan-id/nmap/nmap.xml"
    )
    assert artifact.sha256 == "a" * 64
    assert artifact.size_bytes == 4096


def test_scanner_execution_context_identifies_one_assessment():
    from app.scanners.base import ScannerExecutionContext

    scan_id = uuid4()

    context = ScannerExecutionContext(
        scan_id=scan_id,
        target_host="portal.example.com",
        workspace="/tmp/beacon/scan-1/nmap",
        timeout_seconds=120,
    )

    assert context.scan_id == scan_id
    assert context.target_host == "portal.example.com"
    assert context.timeout_seconds == 120


def test_scanner_adapter_protocol_exposes_health_contract():
    from app.scanners.base import ScannerAdapter

    assert hasattr(ScannerAdapter, "runtime_version")
    assert hasattr(ScannerAdapter, "health_check")


def test_discovered_service_is_immutable():
    from app.assessment.handoff import DiscoveredService

    service = DiscoveredService(
        host="portal.example.com",
        ip="203.0.113.10",
        port=443,
        transport="tcp",
        service="https",
        product="nginx",
        version="1.26",
        tls_hint=True,
        state="open",
    )

    with pytest.raises(FrozenInstanceError):
        service.port = 8443


def test_service_inventory_uses_tuple_not_mutable_list():
    from app.assessment.handoff import (
        DiscoveredService,
        ServiceInventory,
    )

    service = DiscoveredService(
        host="portal.example.com",
        ip="203.0.113.10",
        port=443,
        transport="tcp",
        service="https",
        tls_hint=True,
        state="open",
    )

    inventory = ServiceInventory(
        services=(service,),
    )

    assert isinstance(inventory.services, tuple)
    assert inventory.services == (service,)


def test_http_service_inventory_preserves_redirect_metadata():
    from app.assessment.handoff import (
        HTTPService,
        HTTPServiceInventory,
    )

    service = HTTPService(
        url="https://portal.example.com/",
        host="portal.example.com",
        port=443,
        scheme="https",
        status_code=200,
        title="Portal",
        effective_url="https://portal.example.com/",
        redirect_chain=(
            "http://portal.example.com/",
            "https://portal.example.com/",
        ),
        server="nginx",
        technology_hints=(
            "nginx",
            "react",
        ),
        content_type="text/html",
    )

    inventory = HTTPServiceInventory(
        services=(service,),
    )

    assert inventory.services[0].status_code == 200
    assert inventory.services[0].technology_hints == (
        "nginx",
        "react",
    )


def test_web_endpoint_inventory_preserves_parameter_identity():
    from app.assessment.handoff import (
        WebEndpoint,
        WebEndpointInventory,
    )

    endpoint = WebEndpoint(
        url="https://portal.example.com/login",
        method="POST",
        parameter_names=(
            "username",
            "password",
        ),
        source_url="https://portal.example.com/",
        discovery_method="form",
    )

    inventory = WebEndpointInventory(
        endpoints=(endpoint,),
    )

    assert inventory.endpoints[0].method == "POST"
    assert inventory.endpoints[0].parameter_names == (
        "username",
        "password",
    )


def test_tls_service_inventory_tracks_authorized_host_port():
    from app.assessment.handoff import (
        TLSService,
        TLSServiceInventory,
    )

    service = TLSService(
        host="portal.example.com",
        ip="203.0.113.10",
        port=443,
    )

    inventory = TLSServiceInventory(
        services=(service,),
    )

    assert inventory.services == (service,)


def test_vulnerability_target_set_combines_typed_inputs():
    from app.assessment.handoff import (
        DiscoveredService,
        HTTPService,
        TLSService,
        VulnerabilityTargetSet,
        WebEndpoint,
    )

    network_service = DiscoveredService(
        host="portal.example.com",
        ip="203.0.113.10",
        port=443,
        transport="tcp",
        service="https",
        tls_hint=True,
        state="open",
    )

    http_service = HTTPService(
        url="https://portal.example.com/",
        host="portal.example.com",
        port=443,
        scheme="https",
    )

    endpoint = WebEndpoint(
        url="https://portal.example.com/login",
        method="GET",
    )

    tls_service = TLSService(
        host="portal.example.com",
        ip="203.0.113.10",
        port=443,
    )

    targets = VulnerabilityTargetSet(
        network_services=(network_service,),
        http_services=(http_service,),
        web_endpoints=(endpoint,),
        tls_services=(tls_service,),
    )

    assert targets.network_services == (
        network_service,
    )
    assert targets.http_services == (
        http_service,
    )
    assert targets.web_endpoints == (
        endpoint,
    )
    assert targets.tls_services == (
        tls_service,
    )


def test_handoff_inventory_can_be_serialized_to_json():
    from app.assessment.handoff import (
        DiscoveredService,
        ServiceInventory,
    )

    inventory = ServiceInventory(
        services=(
            DiscoveredService(
                host="portal.example.com",
                ip="203.0.113.10",
                port=443,
                transport="tcp",
                service="https",
                product="nginx",
                version="1.26",
                tls_hint=True,
                state="open",
            ),
        ),
    )

    payload = asdict(inventory)

    encoded = json.dumps(payload)

    assert '"portal.example.com"' in encoded
    assert '"443"' not in encoded
    assert '"port": 443' in encoded


def test_all_handoff_collections_default_to_empty_tuples():
    from app.assessment.handoff import (
        HTTPServiceInventory,
        ServiceInventory,
        TLSServiceInventory,
        VulnerabilityTargetSet,
        WebEndpointInventory,
    )

    assert ServiceInventory().services == ()
    assert HTTPServiceInventory().services == ()
    assert WebEndpointInventory().endpoints == ()
    assert TLSServiceInventory().services == ()

    targets = VulnerabilityTargetSet()

    assert targets.network_services == ()
    assert targets.http_services == ()
    assert targets.web_endpoints == ()
    assert targets.tls_services == ()
