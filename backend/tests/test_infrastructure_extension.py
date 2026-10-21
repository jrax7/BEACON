"""Task 23 RED contracts for Deep Infrastructure Extension."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest


TARGET_HOST = "portal.example.com"
AUTHORIZED_IP = "93.184.216.34"
SECOND_IP = "93.184.216.35"
SHARED_EDGE_IP = "104.16.0.10"


def _infrastructure_scope(
    *,
    authorized_ips=(AUTHORIZED_IP,),
    authorized_cidrs=(),
    resolved_target_ips=None,
    broad_port_scan_allowed=True,
    network_active_checks_allowed=True,
    third_party_infrastructure_attested_excluded=True,
):
    if resolved_target_ips is None:
        resolved_target_ips = tuple(authorized_ips)

    return {
        "enabled": True,
        "infrastructure_extension_enabled": True,
        "authorized_ips": list(authorized_ips),
        "authorized_cidrs": list(authorized_cidrs),
        "resolved_target_ips": list(resolved_target_ips),
        "broad_port_scan_allowed": broad_port_scan_allowed,
        "network_active_checks_allowed": network_active_checks_allowed,
        "third_party_infrastructure_attested_excluded": (
            third_party_infrastructure_attested_excluded
        ),
    }


def _authorization_for(scope):
    from app.assessment.authorization import (
        InfrastructureScopeAuthorization,
    )

    return InfrastructureScopeAuthorization(
        authorized_ips=tuple(scope["authorized_ips"]),
        authorized_cidrs=tuple(scope["authorized_cidrs"]),
        broad_port_scan_allowed=scope["broad_port_scan_allowed"],
        network_active_checks_allowed=scope[
            "network_active_checks_allowed"
        ],
        third_party_infrastructure_attested_excluded=scope[
            "third_party_infrastructure_attested_excluded"
        ],
    )


def _deep_claim(
    *,
    infrastructure=None,
    resolved_addresses=None,
    profile_name="deep",
    snapshot_id=None,
):
    from app.assessment.orchestration import AssessmentClaim

    now = datetime.now(timezone.utc)
    if resolved_addresses is None:
        resolved_addresses = [AUTHORIZED_IP]
    if snapshot_id is None:
        snapshot_id = uuid4()

    profile_versions = {
        "quick": "quick-v1",
        "standard": "standard-v1",
        "deep": "deep-v1",
    }
    zap_versions = {
        "quick": "beacon-quick-v1",
        "standard": "beacon-standard-v1",
        "deep": "beacon-deep-v1",
    }
    profile_version = profile_versions[profile_name]

    authorized_scope = {"fqdn": TARGET_HOST}
    plan = SimpleNamespace(
        profile=profile_name,
        profile_version=profile_version,
        assessment_mode="web",
        authorized_scope=authorized_scope,
        resolved_addresses=list(resolved_addresses),
        engine_policy_versions={
            "authorization": "active-v1",
            "nmap": f"{profile_name}-v1",
            "httpx": f"{profile_name}-v1",
            "katana": f"{profile_name}-v1",
            "sslyze": f"{profile_name}-v1",
            "nuclei": f"{profile_name}-v1",
            "zap": zap_versions[profile_name],
            "nikto": f"{profile_name}-v1",
        },
        crawl_policy={
            "depth": 5,
            "crawl_duration_seconds": 120,
            "max_response_bytes": 1_000_000,
            "max_output_bytes": 10_000_000,
        },
        rate_budget={"requests_per_second": 10},
        timeout_budget={"assessment_seconds": 3600},
        nuclei_template_snapshot_id=snapshot_id,
        zap_policy_version=zap_versions[profile_name],
    )

    if infrastructure is None:
        plan.infrastructure = None
        plan.infrastructure_authorization = None
    else:
        scope = dict(infrastructure)
        authorized_scope["infrastructure"] = scope
        plan.infrastructure = scope
        plan.infrastructure_authorization = _authorization_for(scope)

    return AssessmentClaim(
        scan_id=uuid4(),
        profile_name=profile_name,
        profile_version=profile_version,
        assessment_mode="web",
        target_hostname=TARGET_HOST,
        plan=plan,
        user_id=uuid4(),
        target_id=uuid4(),
        target_normalized_url=f"https://{TARGET_HOST}",
        target_verification_status="verified",
        target_verification_expires_at=now + timedelta(hours=1),
        active_testing_authorized_at=now,
        scan_profile=profile_name,
        scan_profile_version=profile_version,
        scan_assessment_mode="web",
    )


def _resolver_for(*addresses):
    def resolve(hostname):
        assert hostname == TARGET_HOST
        return tuple(addresses)

    return resolve


def _evaluate_shared_infrastructure(
    *,
    authorization,
    requested_addresses,
    shared_infrastructure_detected,
    provider,
):
    from app.assessment import authorization as authorization_module

    evaluator = getattr(
        authorization_module,
        "evaluate_infrastructure_risk",
        None,
    )
    assert callable(
        evaluator
    ), "Task 23 requires evaluate_infrastructure_risk()"

    return evaluator(
        authorization=authorization,
        requested_addresses=tuple(requested_addresses),
        shared_infrastructure_detected=(
            shared_infrastructure_detected
        ),
        provider=provider,
    )


def _empty_web_context():
    from app.assessment.handoff import (
        HTTPServiceInventory,
        WebEndpointInventory,
    )

    return {
        "httpx": HTTPServiceInventory(services=()),
        "katana": WebEndpointInventory(endpoints=()),
    }


def _network_service_inventory():
    from app.assessment.handoff import (
        DiscoveredService,
        ServiceInventory,
    )

    return ServiceInventory(
        services=(
            DiscoveredService(
                host=TARGET_HOST,
                ip=AUTHORIZED_IP,
                port=22,
                transport="tcp",
                service="ssh",
                tls_hint=False,
            ),
        )
    )


def _nuclei_snapshot(approved_groups):
    return SimpleNamespace(
        id=uuid4(),
        policy_version="deep-v1",
        nuclei_version="3.11.1",
        template_source="projectdiscovery/nuclei-templates",
        template_source_revision="task23-test",
        snapshot_digest="a" * 64,
        approved_groups=list(approved_groups),
        approved_template_groups=list(approved_groups),
        template_manifest=[],
        template_count=0,
    )


def test_shared_provider_without_exact_scope_is_blocked():
    authorization = _authorization_for(
        _infrastructure_scope(
            authorized_ips=(),
            authorized_cidrs=(),
            resolved_target_ips=(),
        )
    )

    decision = _evaluate_shared_infrastructure(
        authorization=authorization,
        requested_addresses=(SHARED_EDGE_IP,),
        shared_infrastructure_detected=True,
        provider="cloudflare",
    )

    assert decision.allowed is False
    assert "shared" in decision.reason.lower()


def test_shared_provider_with_exact_ip_scope_is_allowed():
    authorization = _authorization_for(
        _infrastructure_scope(
            authorized_ips=(SHARED_EDGE_IP,),
            resolved_target_ips=(SHARED_EDGE_IP,),
        )
    )

    decision = _evaluate_shared_infrastructure(
        authorization=authorization,
        requested_addresses=(SHARED_EDGE_IP,),
        shared_infrastructure_detected=True,
        provider="cloudflare",
    )

    assert decision.allowed is True


def test_deep_infrastructure_nmap_uses_literal_authorized_ip_and_full_tcp():
    from app.assessment.handoff import ServiceInventory
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope()
    claim = _deep_claim(infrastructure=scope)
    calls = []
    inventory = ServiceInventory(services=())

    def fake_nmap(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(service_inventory=inventory)

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_resolver_for(AUTHORIZED_IP),
    )

    result = runner.run(
        stage="nmap",
        claim=claim,
        context={
            "infrastructure": scope,
            "infrastructure_authorization": _authorization_for(scope),
        },
    )

    assert result.service_inventory is inventory
    assert calls == [
        {
            "target": AUTHORIZED_IP,
            "ports": (),
            "full_tcp": True,
            "timeout_seconds": 1800,
        }
    ]


def test_deep_infrastructure_revalidation_rejects_ip_outside_scope():
    from app.assessment.handoff import ServiceInventory
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope(
        authorized_ips=(AUTHORIZED_IP,),
        resolved_target_ips=(AUTHORIZED_IP, SECOND_IP),
    )
    claim = _deep_claim(
        infrastructure=scope,
        resolved_addresses=[AUTHORIZED_IP, SECOND_IP],
    )
    calls = []

    def fake_nmap(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(service_inventory=ServiceInventory(services=()))

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_resolver_for(SECOND_IP),
    )

    with pytest.raises(
        (RuntimeError, ValueError),
        match=r"(?i)scope|authorized|infrastructure",
    ):
        runner.run(
            stage="nmap",
            claim=claim,
            context={
                "infrastructure": scope,
                "infrastructure_authorization": _authorization_for(
                    scope
                ),
            },
        )

    assert calls == []


def test_domain_verification_without_infrastructure_keeps_bounded_nmap():
    from app.assessment.handoff import ServiceInventory
    from app.assessment.orchestration import ProductionStageRunner

    claim = _deep_claim(infrastructure=None)
    calls = []
    inventory = ServiceInventory(services=())

    def fake_nmap(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(service_inventory=inventory)

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_resolver_for(AUTHORIZED_IP),
    )

    runner.run(stage="nmap", claim=claim, context={})

    assert calls == [
        {
            "target": TARGET_HOST,
            "ports": (80, 443),
            "full_tcp": False,
            "timeout_seconds": 1800,
        }
    ]


def test_deep_infrastructure_nmap_requires_all_explicit_consents():
    from app.assessment.handoff import ServiceInventory
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope(
        broad_port_scan_allowed=False,
    )
    claim = _deep_claim(infrastructure=scope)
    calls = []

    def fake_nmap(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(service_inventory=ServiceInventory(services=()))

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_resolver_for(AUTHORIZED_IP),
    )

    with pytest.raises(
        (RuntimeError, ValueError),
        match=r"(?i)broad|consent|authorization|infrastructure",
    ):
        runner.run(
            stage="nmap",
            claim=claim,
            context={
                "infrastructure": scope,
                "infrastructure_authorization": _authorization_for(
                    scope
                ),
            },
        )

    assert calls == []


def test_infrastructure_nuclei_requires_approved_infrastructure_group():
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope()
    snapshot = _nuclei_snapshot(["BEACON_SAFE"])
    claim = _deep_claim(
        infrastructure=scope,
        snapshot_id=snapshot.id,
    )
    calls = []

    def fake_nuclei(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            raw_jsonl=b"",
            detection_candidates=(),
        )

    runner = ProductionStageRunner(
        nuclei_runner=fake_nuclei,
        nuclei_snapshot_loader=lambda _snapshot_id: snapshot,
        resolver=_resolver_for(AUTHORIZED_IP),
    )
    context = _empty_web_context()
    context.update(
        {
            "nmap": _network_service_inventory(),
            "infrastructure": scope,
            "infrastructure_authorization": _authorization_for(
                scope
            ),
        }
    )

    with pytest.raises(
        (RuntimeError, ValueError),
        match=r"(?i)infrastructure|template|policy",
    ):
        runner.run(
            stage="nuclei",
            claim=claim,
            context=context,
        )

    assert calls == []


def test_infrastructure_nuclei_targets_only_discovered_network_services():
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope()
    snapshot = _nuclei_snapshot(
        ["BEACON_SAFE", "BEACON_INFRASTRUCTURE"]
    )
    claim = _deep_claim(
        infrastructure=scope,
        snapshot_id=snapshot.id,
    )
    calls = []

    def fake_nuclei(**kwargs):
        target_path = Path(kwargs["target_list_path"])
        record = dict(kwargs)
        record["target_list"] = target_path.read_text(
            encoding="utf-8"
        ).splitlines()
        calls.append(record)
        return SimpleNamespace(
            raw_jsonl=b"",
            detection_candidates=(),
        )

    runner = ProductionStageRunner(
        nuclei_runner=fake_nuclei,
        nuclei_snapshot_loader=lambda _snapshot_id: snapshot,
        resolver=_resolver_for(AUTHORIZED_IP),
    )
    context = _empty_web_context()
    context.update(
        {
            "nmap": _network_service_inventory(),
            "infrastructure": scope,
            "infrastructure_authorization": _authorization_for(
                scope
            ),
        }
    )

    result = runner.run(
        stage="nuclei",
        claim=claim,
        context=context,
    )

    assert result.detection_candidates == ()
    assert len(calls) == 1
    assert calls[0]["snapshot"] is snapshot
    assert calls[0]["target_list"] == [f"{AUTHORIZED_IP}:22"]
    assert calls[0]["allow_local_network_access"] is False

def test_persisted_infrastructure_claim_drives_full_tcp_without_manual_context():
    from app.assessment.handoff import ServiceInventory
    from app.assessment.orchestration import ProductionStageRunner

    scope = _infrastructure_scope()

    claim = _deep_claim(
        infrastructure=None,
    )

    # Simulate the persisted authorization state that the production
    # DatabaseOrchestrationStore must place on an execution claim.
    object.__setattr__(
        claim,
        "infrastructure",
        scope,
    )

    object.__setattr__(
        claim,
        "infrastructure_authorization",
        _authorization_for(
            scope
        ),
    )

    calls = []

    inventory = ServiceInventory(
        services=()
    )

    def fake_nmap(**kwargs):
        calls.append(
            kwargs
        )

        return SimpleNamespace(
            service_inventory=inventory
        )

    runner = ProductionStageRunner(
        nmap_runner=fake_nmap,
        resolver=_resolver_for(
            AUTHORIZED_IP
        ),
    )

    result = runner.run(
        stage="nmap",
        claim=claim,
        context={},
    )

    assert (
        result.service_inventory
        is inventory
    )

    assert calls == [
        {
            "target":
                AUTHORIZED_IP,
            "ports":
                (),
            "full_tcp":
                True,
            "timeout_seconds":
                1800,
        }
    ]


def test_database_claim_hydrates_persisted_infrastructure_authorization(
    monkeypatch,
):
    from app.assessment.orchestration import (
        DatabaseOrchestrationStore,
    )

    now = datetime.now(
        timezone.utc
    )

    scan_id = uuid4()
    user_id = uuid4()
    target_id = uuid4()
    organization_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        organization_id=organization_id,
        status="queued",
        profile="deep",
        profile_version="deep-v1",
        assessment_mode="web",
        started_at=None,
        completed_at=None,
        failure_reason=None,
        completed_with_warnings=False,
        engine_version=None,
        progress=0,
        celery_task_id=None,
        user_id=user_id,
        target_id=target_id,
        active_testing_authorized_at=now,
    )

    plan = SimpleNamespace(
        profile="deep",
        profile_version="deep-v1",
        assessment_mode="web",
    )

    target = SimpleNamespace(
        organization_id=organization_id,
        hostname=TARGET_HOST,
        normalized_url=(
            f"https://{TARGET_HOST}"
        ),
        verification_status="verified",
        verification_expires_at=(
            now
            + timedelta(
                hours=1
            )
        ),
    )

    persisted = SimpleNamespace(
        scan_id=scan_id,
        confirmed_by_user_id=user_id,
        authorization_version=(
            "infrastructure-v1"
        ),
        authorization_text_hash=(
            "a" * 64
        ),
        confirmed_at=now,
        source_ip=None,
        authorized_ips=[
            AUTHORIZED_IP,
        ],
        authorized_cidrs=[],
        resolved_target_ips=[
            AUTHORIZED_IP,
        ],
        broad_port_scan_allowed=True,
        network_active_checks_allowed=True,
        third_party_infrastructure_attested_excluded=True,
    )

    class RecordingDatabase:
        def __init__(self):
            self.commit_count = 0

        def commit(self):
            self.commit_count += 1

    class SessionContext:
        def __init__(
            self,
            database,
        ):
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

    database = RecordingDatabase()

    store = DatabaseOrchestrationStore(
        session_factory=(
            lambda:
                SessionContext(
                    database
                )
        ),
        clock=lambda: now,
    )

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
        "_load_infrastructure_authorization",
        lambda database, scan_id:
            persisted,
        raising=False,
    )

    claim = store.claim(
        scan_id=scan_id,
        celery_task_id=(
            "task23-runtime"
        ),
    )

    assert claim is not None

    expected_scope = (
        _infrastructure_scope()
    )

    assert getattr(
        claim,
        "infrastructure",
        None,
    ) == expected_scope

    assert getattr(
        claim,
        "infrastructure_authorization",
        None,
    ) == _authorization_for(
        expected_scope
    )

    assert (
        database.commit_count
        == 1
    )


# TASK27_INFRA_WEB_SCOPE_RED_BEGIN
def test_infrastructure_httpx_preserves_verified_fqdn_candidate():
    """Infrastructure discovery must not erase verified web scope."""

    from app.assessment.handoff import (
        DiscoveredService,
        HTTPServiceInventory,
        ServiceInventory,
    )
    from app.assessment.orchestration import (
        ProductionStageRunner,
    )

    scope = _infrastructure_scope()

    claim = _deep_claim(
        infrastructure=scope,
    )

    # Infrastructure Nmap intentionally executes against the literal
    # separately-authorized IP. Its resulting service inventory therefore
    # carries the IP as the discovered host.
    infrastructure_inventory = (
        ServiceInventory(
            services=(
                DiscoveredService(
                    host=AUTHORIZED_IP,
                    ip=AUTHORIZED_IP,
                    port=80,
                    transport="tcp",
                    service="http",
                    tls_hint=False,
                ),
            )
        )
    )

    calls = []

    def fake_httpx(**kwargs):
        calls.append(
            kwargs
        )

        return HTTPServiceInventory(
            services=()
        )

    runner = ProductionStageRunner(
        httpx_runner=fake_httpx,
        resolver=_resolver_for(
            AUTHORIZED_IP
        ),
    )

    result = runner.run(
        stage="httpx",
        claim=claim,
        context={
            "nmap": SimpleNamespace(
                service_inventory=(
                    infrastructure_inventory
                ),
            ),
            "infrastructure":
                scope,
            "infrastructure_authorization":
                _authorization_for(
                    scope
                ),
        },
    )

    assert isinstance(
        result,
        HTTPServiceInventory,
    )

    assert len(
        calls
    ) == 1

    handed_off = calls[
        0
    ][
        "inventory"
    ]

    assert isinstance(
        handed_off,
        ServiceInventory,
    )

    # TASK27_HTTPX_HANDOFF_NO_AMPLIFICATION
    # Restoring the verified web authority must not append a second
    # candidate for every network service. HTTPX receives one logical
    # service for each Nmap-discovered service.
    assert len(
        handed_off.services
    ) == len(
        infrastructure_inventory.services
    )

    # The separately-authorized infrastructure IP may drive broad
    # discovery, but the normal web pipeline must retain the verified
    # FQDN as its active HTTP authority. Otherwise httpx/Katana produce
    # IP URLs and ZAP's exact-FQDN guard correctly rejects all of them.
    assert any(
        service.host
        == TARGET_HOST
        and service.ip
        == AUTHORIZED_IP
        and service.port
        == 80
        for service
        in handed_off.services
    )
# TASK27_INFRA_WEB_SCOPE_RED_END
