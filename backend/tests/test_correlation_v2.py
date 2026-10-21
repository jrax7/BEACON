from dataclasses import replace
from types import SimpleNamespace

import pytest


def _correlation():
    try:
        from app.assessment import correlation
    except ImportError as exc:
        pytest.fail(
            "Correlation v2 module does not exist yet: "
            f"{exc}"
        )

    return correlation


def test_cve_correlation_merges_same_asset_service_and_single_cve():
    correlation = _correlation()

    first = correlation.CorrelationInput(
        detection_id="detection-a",
        engine="nuclei",
        rule_id="cve-check-a",
        title="Scanner A CVE",
        asset_identity="app.example.com",
        affected_service="https",
        affected_port=443,
        cve_ids=("CVE-2026-1234",),
    )

    second = correlation.CorrelationInput(
        detection_id="detection-b",
        engine="future-scanner",
        rule_id="different-rule",
        title="Scanner B CVE",
        asset_identity="APP.EXAMPLE.COM",
        affected_service="HTTPS",
        affected_port=443,
        cve_ids=("cve-2026-1234",),
    )

    decision = correlation.decide_correlation(
        first,
        second,
    )

    assert decision.strategy == "CVECorrelation"
    assert decision.decision == "merge"
    assert decision.confidence == "high"

    assert decision.candidate_identity == (
        "cve|app.example.com|443|https|CVE-2026-1234"
    )


def test_cve_correlation_separates_when_service_context_differs():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="detection-a",
        engine="nuclei",
        rule_id="cve-a",
        title="CVE",
        asset_identity="app.example.com",
        affected_service="https",
        affected_port=443,
        cve_ids=("CVE-2026-1234",),
    )

    other = replace(
        base,
        detection_id="detection-b",
        affected_port=8443,
    )

    decision = correlation.decide_correlation(
        base,
        other,
    )

    assert decision.strategy == "CVECorrelation"
    assert decision.decision == "separate"
    assert "service context" in decision.reason.lower()


def test_generic_correlation_requires_same_engine_rule_asset_and_context():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="generic-a",
        engine="nikto",
        rule_id="999001",
        title="Generic observation",
        asset_identity="app.example.com",
        affected_service="https",
        affected_port=443,
        affected_location="/admin",
    )

    duplicate = replace(
        base,
        detection_id="generic-b",
    )

    decision = correlation.decide_correlation(
        base,
        duplicate,
    )

    assert decision.strategy == "GenericCorrelation"
    assert decision.decision == "merge"

    different_rule = replace(
        duplicate,
        rule_id="999002",
    )

    separated = correlation.decide_correlation(
        base,
        different_rule,
    )

    assert separated.decision == "separate"


def test_correlation_decision_contains_explainable_provenance():
    correlation = _correlation()

    first = correlation.CorrelationInput(
        detection_id="a",
        engine="nuclei",
        rule_id="cve-a",
        title="CVE A",
        asset_identity="host.example.com",
        affected_service="https",
        affected_port=443,
        cve_ids=("CVE-2026-1111",),
    )

    second = replace(
        first,
        detection_id="b",
        engine="other",
        rule_id="cve-b",
    )

    decision = correlation.decide_correlation(
        first,
        second,
    )

    assert decision.strategy_version == (
        correlation.CORRELATION_VERSION
    )

    assert decision.detection_a_id == "a"
    assert decision.detection_b_id == "b"
    assert decision.reason
    assert decision.details["strategy"] == (
        "CVECorrelation"
    )



def test_web_parameter_correlation_requires_exact_method_endpoint_parameter_and_weakness():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="web-a",
        engine="zap",
        rule_id="40018",
        title="SQL Injection",
        canonical_type="web_parameter",
        asset_identity="app.example.com",
        affected_location=(
            "https://app.example.com/search?q=one#fragment"
        ),
        affected_parameter="q",
        cwe_ids=("CWE-89",),
        source_metadata={
            "http_method": "GET",
        },
    )

    same = replace(
        base,
        detection_id="web-b",
        engine="nuclei",
        rule_id="sql-injection",
        affected_location=(
            "https://APP.EXAMPLE.COM/search?q=two"
        ),
    )

    merged = correlation.decide_correlation(
        base,
        same,
    )

    assert merged.strategy == (
        "WebParameterCorrelation"
    )
    assert merged.decision == "merge"

    different_parameter = replace(
        same,
        affected_parameter="page",
    )

    separated = correlation.decide_correlation(
        base,
        different_parameter,
    )

    assert separated.decision == "separate"
    assert "parameter" in separated.reason.lower()


def test_http_header_correlation_requires_same_application_header_and_weakness():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="header-a",
        engine="zap",
        rule_id="10038",
        title="CSP missing",
        canonical_type="http_header",
        asset_identity="https://app.example.com",
        source_metadata={
            "header_name":
                "Content-Security-Policy",
            "weakness":
                "missing",
        },
    )

    same = replace(
        base,
        detection_id="header-b",
        engine="nikto",
        rule_id="header-check",
    )

    merged = correlation.decide_correlation(
        base,
        same,
    )

    assert merged.strategy == (
        "HTTPHeaderCorrelation"
    )
    assert merged.decision == "merge"

    different_header = replace(
        same,
        source_metadata={
            "header_name":
                "Strict-Transport-Security",
            "weakness":
                "missing",
        },
    )

    separated = correlation.decide_correlation(
        base,
        different_header,
    )

    assert separated.decision == "separate"


def test_tls_correlation_requires_same_host_port_and_weakness():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="tls-a",
        engine="sslyze",
        rule_id="tls-1.0",
        title="TLS 1.0 enabled",
        canonical_type="tls",
        asset_identity="tls.example.com",
        affected_port=443,
        source_metadata={
            "weakness":
                "protocol:tls_1_0",
        },
    )

    same = replace(
        base,
        detection_id="tls-b",
        engine="nuclei",
        rule_id="deprecated-tls",
    )

    merged = correlation.decide_correlation(
        base,
        same,
    )

    assert merged.strategy == "TLSCorrelation"
    assert merged.decision == "merge"

    different_weakness = replace(
        same,
        source_metadata={
            "weakness":
                "protocol:tls_1_1",
        },
    )

    separated = correlation.decide_correlation(
        base,
        different_weakness,
    )

    assert separated.decision == "separate"


def test_service_configuration_correlation_requires_exact_service_context():
    correlation = _correlation()

    base = correlation.CorrelationInput(
        detection_id="service-a",
        engine="nmap",
        rule_id="service-config",
        title="Service configuration",
        canonical_type=(
            "service_configuration"
        ),
        asset_identity="host.example.com",
        affected_service="http",
        affected_port=8080,
        source_metadata={
            "weakness":
                "directory-listing",
        },
    )

    same = replace(
        base,
        detection_id="service-b",
        engine="nikto",
        rule_id="directory-indexing",
    )

    merged = correlation.decide_correlation(
        base,
        same,
    )

    assert merged.strategy == (
        "ServiceConfigurationCorrelation"
    )
    assert merged.decision == "merge"

    different_service = replace(
        same,
        affected_service="https",
    )

    separated = correlation.decide_correlation(
        base,
        different_service,
    )

    assert separated.decision == "separate"
    assert "service" in separated.reason.lower()



def _legacy_finding(
    *,
    tool: str,
    external_id: str,
    title: str,
    evidence=None,
):
    return SimpleNamespace(
        tool_name=tool,
        external_finding_id=external_id,
        title=title,
        severity="low",
        confidence="medium",
        cwe_id=None,
        affected_url=(
            "https://example.test/"
        ),
        affected_port=443,
        description=None,
        remediation=None,
        evidence=evidence,
    )


def test_legacy_header_mapping_is_owned_by_correlation_v2():
    correlation = _correlation()

    zap = _legacy_finding(
        tool="zap",
        external_id="10038",
        title="CSP Header Not Set",
    )

    nikto = _legacy_finding(
        tool="nikto",
        external_id="999001",
        title=(
            "Nikto: Suggested security header "
            "missing: content-security-policy."
        ),
    )

    zap_mapping = (
        correlation.legacy_canonical_issue_for_finding(
            zap
        )
    )

    nikto_mapping = (
        correlation.legacy_canonical_issue_for_finding(
            nikto
        )
    )

    assert zap_mapping == nikto_mapping

    assert zap_mapping["issue_key"] == (
        "missing-security-header:csp"
    )


def test_legacy_wildcard_cors_requires_explicit_evidence():
    correlation = _correlation()

    generic = _legacy_finding(
        tool="zap",
        external_id="10098",
        title="Cross-Domain Misconfiguration",
        evidence={
            "evidence":
                "Origin reflected dynamically",
        },
    )

    wildcard = _legacy_finding(
        tool="zap",
        external_id="10098",
        title="Cross-Domain Misconfiguration",
        evidence={
            "evidence":
                "Access-Control-Allow-Origin: *",
        },
    )

    assert (
        correlation.legacy_canonical_issue_for_finding(
            generic
        )
        is None
    )

    result = (
        correlation.legacy_canonical_issue_for_finding(
            wildcard
        )
    )

    assert result["issue_key"] == (
        "cors:wildcard-origin"
    )


def test_legacy_aggregation_routes_canonical_identity_through_v2(
    monkeypatch,
):
    from app.assessment import correlation
    from app.services import finding_aggregation

    row = _legacy_finding(
        tool="future-scanner",
        external_id="future-rule",
        title="Future finding",
    )

    monkeypatch.setattr(
        correlation,
        "legacy_canonical_issue_for_finding",
        lambda finding: {
            "issue_key":
                "compatibility:v2",
            "title":
                "Compatibility Bridge",
            "cwe_id":
                "CWE-999",
        },
    )

    issues = (
        finding_aggregation.aggregate_findings(
            [row]
        )
    )

    assert len(
        issues
    ) == 1

    assert issues[
        0
    ][
        "issue_key"
    ] == "compatibility:v2"

    assert issues[
        0
    ][
        "title"
    ] == "Compatibility Bridge"
