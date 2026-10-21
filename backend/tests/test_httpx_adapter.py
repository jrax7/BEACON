import json
import subprocess

import pytest

from app.assessment.handoff import (
    DiscoveredService,
    ServiceInventory,
)


def _service(
    *,
    host="portal.example.com",
    ip="203.0.113.10",
    port=443,
    transport="tcp",
    service="https",
    tls_hint=True,
    state="open",
):
    return DiscoveredService(
        host=host,
        ip=ip,
        port=port,
        transport=transport,
        service=service,
        tls_hint=tls_hint,
        state=state,
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


def test_candidate_generation_uses_only_service_inventory():
    from app.scanners.httpx import (
        build_httpx_candidates,
    )

    inventory = ServiceInventory(
        services=(
            _service(
                host="portal.example.com",
                port=443,
            ),
            _service(
                host="portal.example.com",
                port=8080,
                service="http",
                tls_hint=False,
            ),
        ),
    )

    assert build_httpx_candidates(
        inventory
    ) == (
        "portal.example.com:443",
        "portal.example.com:8080",
    )


def test_candidate_generation_deduplicates_services():
    from app.scanners.httpx import (
        build_httpx_candidates,
    )

    duplicate = _service(
        host="portal.example.com",
        port=443,
    )

    inventory = ServiceInventory(
        services=(
            duplicate,
            duplicate,
        ),
    )

    assert build_httpx_candidates(
        inventory
    ) == (
        "portal.example.com:443",
    )


def test_candidate_generation_ignores_non_tcp_services():
    from app.scanners.httpx import (
        build_httpx_candidates,
    )

    inventory = ServiceInventory(
        services=(
            _service(
                transport="udp",
                port=443,
            ),
        ),
    )

    assert build_httpx_candidates(
        inventory
    ) == ()


def test_candidate_generation_ignores_non_open_services():
    from app.scanners.httpx import (
        build_httpx_candidates,
    )

    inventory = ServiceInventory(
        services=(
            _service(
                state="closed",
            ),
        ),
    )

    assert build_httpx_candidates(
        inventory
    ) == ()


def test_candidate_generation_formats_ipv6_literals():
    from app.scanners.httpx import (
        build_httpx_candidates,
    )

    inventory = ServiceInventory(
        services=(
            _service(
                host="2001:db8::10",
                ip="2001:db8::10",
                port=8443,
            ),
        ),
    )

    assert build_httpx_candidates(
        inventory
    ) == (
        "[2001:db8::10]:8443",
    )


def test_jsonl_parser_produces_http_service_inventory():
    from app.assessment.handoff import (
        HTTPServiceInventory,
    )
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        json.dumps(
            {
                "url": "https://portal.example.com:443",
                "input": "portal.example.com:443",
                "host": "portal.example.com",
                "host_ip": "203.0.113.10",
                "port": "443",
                "scheme": "https",
                "status_code": 200,
                "title": "Customer Portal",
                "webserver": "nginx",
                "tech": [
                    "nginx",
                    "React",
                ],
                "content_type": "text/html",
                "failed": False,
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1024 * 1024,
    )

    assert isinstance(
        inventory,
        HTTPServiceInventory,
    )

    assert len(inventory.services) == 1

    service = inventory.services[0]

    assert service.url == (
        "https://portal.example.com:443"
    )
    assert service.host == "portal.example.com"
    assert service.port == 443
    assert service.scheme == "https"
    assert service.status_code == 200
    assert service.title == "Customer Portal"
    assert service.server == "nginx"
    assert service.technology_hints == (
        "nginx",
        "React",
    )
    assert service.content_type == "text/html"


def test_jsonl_parser_skips_failed_probes():
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        json.dumps(
            {
                "url": "https://portal.example.com:443",
                "input": "portal.example.com:443",
                "host": "portal.example.com",
                "port": "443",
                "scheme": "https",
                "failed": True,
                "error": "connection refused",
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1024 * 1024,
    )

    assert inventory.services == ()


def test_jsonl_parser_rejects_malformed_json():
    from app.scanners.httpx import (
        HttpxScannerError,
        parse_httpx_jsonl,
    )

    with pytest.raises(
        HttpxScannerError,
        match="invalid JSONL",
    ):
        parse_httpx_jsonl(
            b'{"url": "https://example.com"\n',
            max_output_bytes=1024,
        )


def test_jsonl_parser_rejects_oversized_output():
    from app.scanners.httpx import (
        HttpxScannerError,
        parse_httpx_jsonl,
    )

    with pytest.raises(
        HttpxScannerError,
        match="output limit",
    ):
        parse_httpx_jsonl(
            b"x" * 1025,
            max_output_bytes=1024,
        )


def test_jsonl_parser_rejects_non_object_record():
    from app.scanners.httpx import (
        HttpxScannerError,
        parse_httpx_jsonl,
    )

    with pytest.raises(
        HttpxScannerError,
        match="JSON object",
    ):
        parse_httpx_jsonl(
            b'["not", "an", "object"]\n',
            max_output_bytes=1024,
        )


def test_redirect_location_is_observation_not_new_service():
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        json.dumps(
            {
                "url": "https://portal.example.com/",
                "input": "portal.example.com:443",
                "host": "portal.example.com",
                "port": "443",
                "scheme": "https",
                "status_code": 302,
                "location": "https://external.example.net/login",
                "failed": False,
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1024 * 1024,
    )

    assert len(inventory.services) == 1

    service = inventory.services[0]

    # The classified service remains the original authorized host.
    assert service.host == "portal.example.com"
    assert service.url == (
        "https://portal.example.com/"
    )

    # The redirect can be preserved as evidence, but it does not
    # become another HTTPService.
    assert service.redirect_chain == (
        "https://portal.example.com/",
        "https://external.example.net/login",
    )


def test_same_host_final_url_is_preserved():
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        json.dumps(
            {
                "url": "https://portal.example.com/",
                "input": "portal.example.com:443",
                "host": "portal.example.com",
                "port": "443",
                "scheme": "https",
                "status_code": 200,
                "final_url": (
                    "https://portal.example.com/login"
                ),
                "chain_status_codes": [
                    302,
                    200,
                ],
                "failed": False,
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1024 * 1024,
    )

    service = inventory.services[0]

    assert service.effective_url == (
        "https://portal.example.com/login"
    )
    assert service.redirect_chain == (
        "https://portal.example.com/",
        "https://portal.example.com/login",
    )


def test_parser_derives_host_from_url_not_reported_ip():
    from app.scanners.httpx import (
        parse_httpx_jsonl,
    )

    raw = (
        json.dumps(
            {
                "url": "https://portal.example.com/",
                "input": "portal.example.com:443",
                "host": "203.0.113.10",
                "host_ip": "203.0.113.10",
                "port": "443",
                "scheme": "https",
                "status_code": 200,
                "failed": False,
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_httpx_jsonl(
        raw,
        max_output_bytes=1024 * 1024,
    )

    # Canonical scope identity comes from the URL, not an IP field
    # that varies between httpx versions.
    assert inventory.services[0].host == (
        "portal.example.com"
    )


def test_get_httpx_version_uses_dedicated_pd_binary(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.httpx import (
        get_httpx_version,
    )

    captured = {}

    monkeypatch.setattr(
        settings,
        "httpx_binary",
        "/usr/local/bin/pd-httpx",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return _completed_process(
            stdout=b"httpx version v1.8.1\n",
        )

    monkeypatch.setattr(
        "app.scanners.httpx.subprocess.run",
        fake_run,
    )

    version = get_httpx_version()

    assert version == "v1.8.1"

    assert captured["command"] == [
        "/usr/local/bin/pd-httpx",
        "-version",
    ]


def test_version_probe_rejects_python_httpx_cli(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.httpx import (
        HttpxScannerError,
        get_httpx_version,
    )

    monkeypatch.setattr(
        settings,
        "httpx_binary",
        "httpx",
        raising=False,
    )

    def fake_run(command, **kwargs):
        return _completed_process(
            stderr=(
                b"The httpx command line client could not run "
                b"because the required dependencies were not "
                b"installed."
            ),
            returncode=1,
        )

    monkeypatch.setattr(
        "app.scanners.httpx.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        HttpxScannerError,
        match="ProjectDiscovery",
    ):
        get_httpx_version()


def test_run_httpx_probe_feeds_only_generated_candidates(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.httpx import (
        run_httpx_probe,
    )

    inventory = ServiceInventory(
        services=(
            _service(
                host="portal.example.com",
                port=443,
            ),
            _service(
                host="portal.example.com",
                port=8080,
                service="http",
                tls_hint=False,
            ),
        ),
    )

    captured = {}

    monkeypatch.setattr(
        settings,
        "httpx_binary",
        "/usr/local/bin/pd-httpx",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        raw = (
            json.dumps(
                {
                    "url": (
                        "https://portal.example.com:443"
                    ),
                    "input": "portal.example.com:443",
                    "port": "443",
                    "scheme": "https",
                    "status_code": 200,
                    "failed": False,
                }
            ).encode()
            + b"\n"
        )

        return _completed_process(
            stdout=raw,
        )

    monkeypatch.setattr(
        "app.scanners.httpx.subprocess.run",
        fake_run,
    )

    result = run_httpx_probe(
        inventory=inventory,
        timeout_seconds=120,
        request_rate=5,
        max_output_bytes=1024 * 1024,
    )

    assert len(result.services) == 1

    assert captured["kwargs"]["input"] == (
        b"portal.example.com:443\n"
        b"portal.example.com:8080\n"
    )

    command = captured["command"]

    assert command[0] == (
        "/usr/local/bin/pd-httpx"
    )

    assert "-json" in command
    assert "-silent" in command
    assert "-duc" in command
    assert "-fhr" in command
    assert "-include-chain" in command

    rate_index = command.index("-rl")

    assert command[rate_index + 1] == "5"


def test_run_httpx_probe_does_not_execute_for_empty_inventory(
    monkeypatch,
):
    from app.scanners.httpx import (
        run_httpx_probe,
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError(
            "httpx subprocess should not run"
        )

    monkeypatch.setattr(
        "app.scanners.httpx.subprocess.run",
        fail_if_called,
    )

    result = run_httpx_probe(
        inventory=ServiceInventory(),
        timeout_seconds=120,
        request_rate=5,
        max_output_bytes=1024,
    )

    assert result.services == ()


def test_run_httpx_probe_rejects_non_positive_rate():
    from app.scanners.httpx import (
        HttpxScannerError,
        run_httpx_probe,
    )

    with pytest.raises(
        HttpxScannerError,
        match="request rate",
    ):
        run_httpx_probe(
            inventory=ServiceInventory(
                services=(
                    _service(),
                ),
            ),
            timeout_seconds=120,
            request_rate=0,
            max_output_bytes=1024,
        )


def test_run_httpx_probe_rejects_non_positive_timeout():
    from app.scanners.httpx import (
        HttpxScannerError,
        run_httpx_probe,
    )

    with pytest.raises(
        HttpxScannerError,
        match="timeout",
    ):
        run_httpx_probe(
            inventory=ServiceInventory(
                services=(
                    _service(),
                ),
            ),
            timeout_seconds=0,
            request_rate=5,
            max_output_bytes=1024,
        )


def test_run_httpx_probe_rejects_scanner_failure(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.httpx import (
        HttpxScannerError,
        run_httpx_probe,
    )

    monkeypatch.setattr(
        settings,
        "httpx_binary",
        "/usr/local/bin/pd-httpx",
        raising=False,
    )

    monkeypatch.setattr(
        "app.scanners.httpx.subprocess.run",
        lambda *args, **kwargs: _completed_process(
            returncode=1,
            stderr=b"httpx execution failed",
        ),
    )

    with pytest.raises(
        HttpxScannerError,
        match="exited unsuccessfully",
    ):
        run_httpx_probe(
            inventory=ServiceInventory(
                services=(
                    _service(),
                ),
            ),
            timeout_seconds=120,
            request_rate=5,
            max_output_bytes=1024,
        )
