import json
import subprocess

import pytest

from app.assessment.handoff import (
    TLSService,
    TLSServiceInventory,
)


def _tls_service(
    *,
    host="portal.example.com",
    ip="203.0.113.10",
    port=443,
):
    return TLSService(
        host=host,
        ip=ip,
        port=port,
    )


def _completed_process(
    stdout=b"",
    *,
    stderr=b"",
    returncode=0,
):
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _attempt(result, status="COMPLETED"):
    return {
        "status": status,
        "error_reason": None,
        "error_trace": None,
        "result": result,
    }


SAMPLE_SSLYZE_PAYLOAD = {
    "invalid_server_strings": [],
    "date_scans_started": "2026-08-28T18:00:00Z",
    "date_scans_completed": "2026-08-28T18:00:05Z",
    "sslyze_version": "6.3.1",
    "sslyze_url": (
        "https://github.com/nabla-c0d3/sslyze"
    ),
    "server_scan_results": [
        {
            "uuid": (
                "00000000-0000-0000-0000-000000000801"
            ),
            "server_location": {
                "hostname": "portal.example.com",
                "port": 443,
                "connection_type": "DIRECT",
                "ip_address": "203.0.113.10",
                "http_proxy_settings": None,
            },
            "network_configuration": {
                "tls_server_name_indication": (
                    "portal.example.com"
                ),
            },
            "connectivity_status": "COMPLETED",
            "connectivity_error_trace": None,
            "connectivity_result": {
                "highest_tls_version_supported": (
                    "TLS_1_3"
                ),
                "cipher_suite_supported": (
                    "TLS_AES_256_GCM_SHA384"
                ),
                "client_auth_requirement": "DISABLED",
                "supports_ecdh_key_exchange": True,
            },
            "scan_status": "COMPLETED",
            "scan_result": {
                "tls_1_0_cipher_suites": _attempt(
                    {
                        "tls_version_used": "TLS_1_0",
                        "is_tls_version_supported": True,
                        "accepted_cipher_suites": [],
                        "rejected_cipher_suites": [],
                    }
                ),
                "tls_1_1_cipher_suites": _attempt(
                    {
                        "tls_version_used": "TLS_1_1",
                        "is_tls_version_supported": False,
                        "accepted_cipher_suites": [],
                        "rejected_cipher_suites": [],
                    }
                ),
                "tls_1_2_cipher_suites": _attempt(
                    {
                        "tls_version_used": "TLS_1_2",
                        "is_tls_version_supported": True,
                        "accepted_cipher_suites": [],
                        "rejected_cipher_suites": [],
                    }
                ),
                "tls_1_3_cipher_suites": _attempt(
                    {
                        "tls_version_used": "TLS_1_3",
                        "is_tls_version_supported": True,
                        "accepted_cipher_suites": [],
                        "rejected_cipher_suites": [],
                    }
                ),
                "heartbleed": _attempt(
                    {
                        "is_vulnerable_to_heartbleed": True,
                    }
                ),
                "openssl_ccs_injection": _attempt(
                    {
                        "is_vulnerable_to_ccs_injection": (
                            False
                        ),
                    }
                ),
                "robot": _attempt(
                    {
                        "robot_result": (
                            "VULNERABLE_WEAK_ORACLE"
                        ),
                    }
                ),
                "tls_compression": _attempt(
                    {
                        "supports_compression": True,
                    }
                ),
                "session_renegotiation": _attempt(
                    {
                        "supports_secure_renegotiation": (
                            False
                        ),
                        (
                            "is_vulnerable_to_"
                            "client_renegotiation_dos"
                        ): True,
                        (
                            "client_renegotiations_"
                            "success_count"
                        ): 1,
                    }
                ),
                "certificate_info": _attempt(
                    {
                        (
                            "hostname_used_for_"
                            "server_name_indication"
                        ): "portal.example.com",
                        "certificate_deployments": [
                            {
                                "path_validation_results": [
                                    {
                                        "trust_store": {
                                            "path": (
                                                "/mozilla.pem"
                                            ),
                                            "name": "Mozilla",
                                            "version": "2026",
                                            "ev_oids": None,
                                        },
                                        (
                                            "verified_"
                                            "certificate_chain"
                                        ): None,
                                        "validation_error": (
                                            "certificate expired"
                                        ),
                                        (
                                            "was_validation_"
                                            "successful"
                                        ): False,
                                    }
                                ],
                            }
                        ],
                    }
                ),
            },
        }
    ],
}


SAMPLE_SSLYZE_JSON = (
    json.dumps(
        SAMPLE_SSLYZE_PAYLOAD
    ).encode("utf-8")
)


def test_sslyze_targets_pin_authorized_ip():
    from app.scanners.sslyze import (
        build_sslyze_targets,
    )

    inventory = TLSServiceInventory(
        services=(
            _tls_service(),
        ),
    )

    assert build_sslyze_targets(
        inventory
    ) == (
        (
            "portal.example.com:"
            "443{203.0.113.10}"
        ),
    )


def test_sslyze_targets_are_deduplicated():
    from app.scanners.sslyze import (
        build_sslyze_targets,
    )

    service = _tls_service()

    inventory = TLSServiceInventory(
        services=(
            service,
            service,
        ),
    )

    assert build_sslyze_targets(
        inventory
    ) == (
        (
            "portal.example.com:"
            "443{203.0.113.10}"
        ),
    )


def test_sslyze_targets_reject_invalid_port():
    from app.scanners.sslyze import (
        SslyzeScannerError,
        build_sslyze_targets,
    )

    inventory = TLSServiceInventory(
        services=(
            _tls_service(
                port=65536,
            ),
        ),
    )

    with pytest.raises(
        SslyzeScannerError,
        match="valid range",
    ):
        build_sslyze_targets(
            inventory
        )


def test_sslyze_targets_reject_empty_host():
    from app.scanners.sslyze import (
        SslyzeScannerError,
        build_sslyze_targets,
    )

    inventory = TLSServiceInventory(
        services=(
            _tls_service(
                host="",
            ),
        ),
    )

    with pytest.raises(
        SslyzeScannerError,
        match="host",
    ):
        build_sslyze_targets(
            inventory
        )


def test_sslyze_parser_returns_typed_result():
    from app.scanners.sslyze import (
        SslyzeAssessmentResult,
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    assert isinstance(
        result,
        SslyzeAssessmentResult,
    )

    assert result.scanner_version == "6.3.1"
    assert result.raw_json == SAMPLE_SSLYZE_JSON

    assert len(result.servers) == 1


def test_sslyze_parser_preserves_authorized_identity():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    server = result.servers[0]

    assert server.host == "portal.example.com"
    assert server.ip == "203.0.113.10"
    assert server.port == 443

    assert server.connectivity_status == "COMPLETED"
    assert server.scan_status == "COMPLETED"

    assert server.highest_tls_version_supported == (
        "TLS_1_3"
    )

    assert server.client_auth_requirement == (
        "DISABLED"
    )


def test_sslyze_parser_extracts_supported_protocols():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    assert result.servers[0].supported_protocols == (
        "TLS_1_0",
        "TLS_1_2",
        "TLS_1_3",
    )


def test_sslyze_parser_emits_legacy_protocol_candidate():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    candidates = {
        candidate.kind: candidate
        for candidate in result.detection_candidates
    }

    assert "legacy_tls_protocol" in candidates

    candidate = candidates[
        "legacy_tls_protocol"
    ]

    assert candidate.host == "portal.example.com"
    assert candidate.port == 443
    assert candidate.evidence_key == "protocol"
    assert candidate.evidence_value == "TLS_1_0"


def test_sslyze_parser_emits_known_tls_vulnerability_candidates():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    kinds = {
        candidate.kind
        for candidate in result.detection_candidates
    }

    assert "heartbleed" in kinds
    assert "robot" in kinds
    assert "tls_compression" in kinds
    assert "insecure_renegotiation" in kinds
    assert "client_renegotiation_dos" in kinds

    # False flags must not become detections.
    assert "openssl_ccs_injection" not in kinds


def test_sslyze_parser_emits_certificate_validation_candidate():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    result = parse_sslyze_json(
        SAMPLE_SSLYZE_JSON,
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    candidates = [
        candidate
        for candidate in result.detection_candidates
        if candidate.kind
        == "certificate_path_validation"
    ]

    assert len(candidates) == 1

    assert candidates[0].evidence_value == (
        "certificate expired"
    )


def test_sslyze_parser_does_not_accept_out_of_scope_result():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    payload = json.loads(
        SAMPLE_SSLYZE_JSON
    )

    payload[
        "server_scan_results"
    ][0]["server_location"] = {
        "hostname": "other.example.net",
        "port": 443,
        "connection_type": "DIRECT",
        "ip_address": "198.51.100.50",
        "http_proxy_settings": None,
    }

    result = parse_sslyze_json(
        json.dumps(payload).encode(),
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    assert result.servers == ()
    assert result.detection_candidates == ()


def test_sslyze_parser_preserves_connectivity_failure_without_detection():
    from app.scanners.sslyze import (
        parse_sslyze_json,
    )

    payload = json.loads(
        SAMPLE_SSLYZE_JSON
    )

    server = payload[
        "server_scan_results"
    ][0]

    server["connectivity_status"] = "ERROR"
    server["connectivity_error_trace"] = (
        "connection timed out"
    )
    server["connectivity_result"] = None
    server["scan_status"] = (
        "ERROR_NO_CONNECTIVITY"
    )
    server["scan_result"] = None

    result = parse_sslyze_json(
        json.dumps(payload).encode(),
        authorized_services=(
            TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            )
        ),
        max_output_bytes=2_000_000,
    )

    assert len(result.servers) == 1

    parsed = result.servers[0]

    assert parsed.connectivity_status == "ERROR"
    assert parsed.scan_status == (
        "ERROR_NO_CONNECTIVITY"
    )
    assert parsed.connectivity_error == (
        "connection timed out"
    )

    assert result.detection_candidates == ()


def test_sslyze_parser_rejects_malformed_json():
    from app.scanners.sslyze import (
        SslyzeScannerError,
        parse_sslyze_json,
    )

    with pytest.raises(
        SslyzeScannerError,
        match="invalid JSON",
    ):
        parse_sslyze_json(
            b'{"server_scan_results":',
            authorized_services=(
                TLSServiceInventory()
            ),
            max_output_bytes=1024,
        )


def test_sslyze_parser_rejects_oversized_output():
    from app.scanners.sslyze import (
        SslyzeScannerError,
        parse_sslyze_json,
    )

    with pytest.raises(
        SslyzeScannerError,
        match="output limit",
    ):
        parse_sslyze_json(
            b"x" * 1025,
            authorized_services=(
                TLSServiceInventory()
            ),
            max_output_bytes=1024,
        )


def test_sslyze_parser_requires_server_results_array():
    from app.scanners.sslyze import (
        SslyzeScannerError,
        parse_sslyze_json,
    )

    with pytest.raises(
        SslyzeScannerError,
        match="server_scan_results",
    ):
        parse_sslyze_json(
            b'{"server_scan_results": {}}',
            authorized_services=(
                TLSServiceInventory()
            ),
            max_output_bytes=1024,
        )


def test_get_sslyze_version_uses_installed_distribution(
    monkeypatch,
):
    import importlib.metadata as package_metadata

    from app.scanners.sslyze import (
        get_sslyze_version,
    )

    requested = []

    def fake_version(distribution):
        requested.append(distribution)
        return "6.3.1"

    monkeypatch.setattr(
        package_metadata,
        "version",
        fake_version,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError(
            "SSLyze CLI must not be invoked for "
            "package version discovery"
        )

    monkeypatch.setattr(
        "app.scanners.sslyze.subprocess.run",
        fail_if_called,
    )

    assert get_sslyze_version() == "6.3.1"
    assert requested == ["sslyze"]


def test_sslyze_runner_skips_empty_inventory(
    monkeypatch,
):
    from app.scanners.sslyze import (
        run_sslyze_assessment,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError(
            "SSLyze subprocess should not run"
        )

    monkeypatch.setattr(
        "app.scanners.sslyze.subprocess.run",
        fail_if_called,
    )

    result = run_sslyze_assessment(
        inventory=TLSServiceInventory(),
        timeout_seconds=300,
        max_output_bytes=2_000_000,
    )

    assert result.servers == ()
    assert result.detection_candidates == ()
    assert result.raw_json == b""


def test_sslyze_runner_uses_pinned_ip_target(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.sslyze import (
        run_sslyze_assessment,
    )

    captured = {}

    monkeypatch.setattr(
        settings,
        "sslyze_binary",
        "sslyze",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return _completed_process(
            stdout=SAMPLE_SSLYZE_JSON,
        )

    monkeypatch.setattr(
        "app.scanners.sslyze.subprocess.run",
        fake_run,
    )

    result = run_sslyze_assessment(
        inventory=TLSServiceInventory(
            services=(
                _tls_service(),
            ),
        ),
        timeout_seconds=300,
        max_output_bytes=2_000_000,
    )

    command = captured["command"]

    assert command[0] == "sslyze"

    assert "--json_out" in command

    json_index = command.index(
        "--json_out"
    )

    assert command[json_index + 1] == "-"

    assert "--slow_connection" in command

    assert (
        "portal.example.com:"
        "443{203.0.113.10}"
    ) in command

    assert captured["kwargs"]["timeout"] == 300

    assert result.scanner_version == "6.3.1"


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        (
            "timeout_seconds",
            0,
            "timeout",
        ),
        (
            "max_output_bytes",
            0,
            "output limit",
        ),
    ],
)
def test_sslyze_runner_rejects_non_positive_budgets(
    field,
    value,
    match,
):
    from app.scanners.sslyze import (
        SslyzeScannerError,
        run_sslyze_assessment,
    )

    kwargs = {
        "inventory": TLSServiceInventory(
            services=(
                _tls_service(),
            ),
        ),
        "timeout_seconds": 300,
        "max_output_bytes": 2_000_000,
    }

    kwargs[field] = value

    with pytest.raises(
        SslyzeScannerError,
        match=match,
    ):
        run_sslyze_assessment(
            **kwargs,
        )


def test_sslyze_runner_rejects_process_failure(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.sslyze import (
        SslyzeScannerError,
        run_sslyze_assessment,
    )

    monkeypatch.setattr(
        settings,
        "sslyze_binary",
        "sslyze",
        raising=False,
    )

    monkeypatch.setattr(
        "app.scanners.sslyze.subprocess.run",
        lambda *args, **kwargs: _completed_process(
            returncode=2,
            stderr=b"SSLyze execution failed",
        ),
    )

    with pytest.raises(
        SslyzeScannerError,
        match="exited unsuccessfully",
    ):
        run_sslyze_assessment(
            inventory=TLSServiceInventory(
                services=(
                    _tls_service(),
                ),
            ),
            timeout_seconds=300,
            max_output_bytes=2_000_000,
        )


def test_sslyze_runner_uses_explicit_checks_without_mozilla_policy(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.sslyze import (
        run_sslyze_assessment,
    )

    captured = {}

    monkeypatch.setattr(
        settings,
        "sslyze_binary",
        "sslyze",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command

        return _completed_process(
            stdout=SAMPLE_SSLYZE_JSON,
        )

    monkeypatch.setattr(
        "app.scanners.sslyze.subprocess.run",
        fake_run,
    )

    run_sslyze_assessment(
        inventory=TLSServiceInventory(
            services=(
                _tls_service(),
            ),
        ),
        timeout_seconds=300,
        max_output_bytes=2_000_000,
    )

    command = captured["command"]

    mozilla_index = command.index(
        "--mozilla_config"
    )

    assert command[
        mozilla_index + 1
    ] == "disable"

    required_checks = {
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--certinfo",
        "--heartbleed",
        "--openssl_ccs",
        "--robot",
        "--compression",
        "--reneg",
    }

    assert required_checks.issubset(
        set(command)
    )
