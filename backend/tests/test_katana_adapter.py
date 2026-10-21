import json
import subprocess

import pytest

from app.assessment.handoff import (
    HTTPService,
    HTTPServiceInventory,
)


def _http_service(
    *,
    url="https://portal.example.com/",
    host="portal.example.com",
    port=443,
    scheme="https",
):
    return HTTPService(
        url=url,
        host=host,
        port=port,
        scheme=scheme,
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


def test_katana_inputs_use_only_http_inventory():
    from app.scanners.katana import (
        build_katana_inputs,
    )

    inventory = HTTPServiceInventory(
        services=(
            _http_service(
                url="https://portal.example.com/",
            ),
            _http_service(
                url="http://portal.example.com:8080/",
                port=8080,
                scheme="http",
            ),
        ),
    )

    assert build_katana_inputs(
        inventory
    ) == (
        "https://portal.example.com/",
        "http://portal.example.com:8080/",
    )


def test_katana_inputs_are_deduplicated():
    from app.scanners.katana import (
        build_katana_inputs,
    )

    service = _http_service()

    inventory = HTTPServiceInventory(
        services=(
            service,
            service,
        ),
    )

    assert build_katana_inputs(
        inventory
    ) == (
        "https://portal.example.com/",
    )


def test_katana_inputs_reject_non_http_scheme():
    from app.scanners.katana import (
        KatanaScannerError,
        build_katana_inputs,
    )

    inventory = HTTPServiceInventory(
        services=(
            _http_service(
                url="ftp://portal.example.com/",
                scheme="ftp",
            ),
        ),
    )

    with pytest.raises(
        KatanaScannerError,
        match="HTTP or HTTPS",
    ):
        build_katana_inputs(
            inventory
        )


def test_jsonl_parser_produces_web_endpoint_inventory():
    from app.assessment.handoff import (
        WebEndpointInventory,
    )
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    raw = (
        json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": (
                        "https://portal.example.com/login"
                    ),
                },
                "source": (
                    "https://portal.example.com/"
                ),
                "tag": "a",
                "attribute": "href",
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "portal.example.com",
        ),
        max_output_bytes=1024 * 1024,
    )

    assert isinstance(
        inventory,
        WebEndpointInventory,
    )

    assert len(inventory.endpoints) == 1

    endpoint = inventory.endpoints[0]

    assert endpoint.url == (
        "https://portal.example.com/login"
    )
    assert endpoint.method == "GET"
    assert endpoint.source_url == (
        "https://portal.example.com/"
    )
    assert endpoint.discovery_method == (
        "a:href"
    )


def test_jsonl_parser_extracts_parameter_names():
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    raw = (
        json.dumps(
            {
                "request": {
                    "method": "POST",
                    "endpoint": (
                        "https://portal.example.com/search"
                        "?q=test&page=1"
                    ),
                },
                "source": (
                    "https://portal.example.com/"
                ),
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "portal.example.com",
        ),
        max_output_bytes=1024 * 1024,
    )

    assert inventory.endpoints[0].parameter_names == (
        "page",
        "q",
    )


def test_jsonl_parser_deduplicates_method_and_url():
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    record = {
        "request": {
            "method": "GET",
            "endpoint": (
                "https://portal.example.com/login"
            ),
        },
        "source": (
            "https://portal.example.com/"
        ),
    }

    raw = (
        json.dumps(record).encode()
        + b"\n"
        + json.dumps(record).encode()
        + b"\n"
    )

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "portal.example.com",
        ),
        max_output_bytes=1024 * 1024,
    )

    assert len(inventory.endpoints) == 1


def test_jsonl_parser_rejects_out_of_scope_endpoint():
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    raw = (
        json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": (
                        "https://evil.example.net/admin"
                    ),
                },
                "source": (
                    "https://portal.example.com/"
                ),
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "portal.example.com",
        ),
        max_output_bytes=1024 * 1024,
    )

    assert inventory.endpoints == ()


def test_jsonl_parser_rejects_child_subdomain():
    from app.scanners.katana import (
        parse_katana_jsonl,
    )

    raw = (
        json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": (
                        "https://child.portal.example.com/"
                    ),
                },
                "source": (
                    "https://portal.example.com/"
                ),
            }
        ).encode()
        + b"\n"
    )

    inventory = parse_katana_jsonl(
        raw,
        authorized_hosts=(
            "portal.example.com",
        ),
        max_output_bytes=1024 * 1024,
    )

    assert inventory.endpoints == ()


def test_jsonl_parser_rejects_malformed_json():
    from app.scanners.katana import (
        KatanaScannerError,
        parse_katana_jsonl,
    )

    with pytest.raises(
        KatanaScannerError,
        match="invalid JSONL",
    ):
        parse_katana_jsonl(
            b'{"request":\n',
            authorized_hosts=(
                "portal.example.com",
            ),
            max_output_bytes=1024,
        )


def test_jsonl_parser_rejects_oversized_output():
    from app.scanners.katana import (
        KatanaScannerError,
        parse_katana_jsonl,
    )

    with pytest.raises(
        KatanaScannerError,
        match="output limit",
    ):
        parse_katana_jsonl(
            b"x" * 1025,
            authorized_hosts=(
                "portal.example.com",
            ),
            max_output_bytes=1024,
        )


def test_run_katana_uses_exact_fqdn_scope(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.katana import run_katana_crawl

    captured = {}

    monkeypatch.setattr(
        settings,
        "katana_binary",
        "/usr/local/bin/pd-katana",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        raw = (
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": (
                            "https://portal.example.com/login"
                        ),
                    },
                    "source": (
                        "https://portal.example.com/"
                    ),
                }
            ).encode()
            + b"\n"
        )

        return _completed_process(
            stdout=raw,
        )

    monkeypatch.setattr(
        "app.scanners.katana.subprocess.run",
        fake_run,
    )

    result = run_katana_crawl(
        inventory=HTTPServiceInventory(
            services=(
                _http_service(),
            ),
        ),
        depth=3,
        crawl_duration_seconds=300,
        request_rate=5,
        max_response_bytes=1_000_000,
        max_output_bytes=1_000_000,
        timeout_seconds=330,
    )

    assert len(result.endpoints) == 1

    command = captured["command"]

    assert command[0] == (
        "/usr/local/bin/pd-katana"
    )

    assert "-jsonl" in command
    assert "-silent" in command
    assert "-duc" in command

    scope_index = command.index("-fs")
    assert command[scope_index + 1] == "fqdn"

    depth_index = command.index("-d")
    assert command[depth_index + 1] == "3"

    rate_index = command.index("-rl")
    assert command[rate_index + 1] == "5"

    assert "-headless" not in command
    assert "-hl" not in command


def test_run_katana_feeds_only_inventory_urls(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.katana import run_katana_crawl

    captured = {}

    monkeypatch.setattr(
        settings,
        "katana_binary",
        "/usr/local/bin/pd-katana",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["input"] = kwargs["input"]
        return _completed_process()

    monkeypatch.setattr(
        "app.scanners.katana.subprocess.run",
        fake_run,
    )

    run_katana_crawl(
        inventory=HTTPServiceInventory(
            services=(
                _http_service(
                    url="https://portal.example.com/",
                ),
                _http_service(
                    url=(
                        "http://portal.example.com:8080/"
                    ),
                    port=8080,
                    scheme="http",
                ),
            ),
        ),
        depth=3,
        crawl_duration_seconds=300,
        request_rate=5,
        max_response_bytes=1_000_000,
        max_output_bytes=1_000_000,
        timeout_seconds=330,
    )

    assert captured["input"] == (
        b"https://portal.example.com/\n"
        b"http://portal.example.com:8080/\n"
    )


def test_run_katana_skips_empty_inventory(
    monkeypatch,
):
    from app.scanners.katana import run_katana_crawl

    def fail_if_called(*args, **kwargs):
        raise AssertionError(
            "Katana subprocess should not run"
        )

    monkeypatch.setattr(
        "app.scanners.katana.subprocess.run",
        fail_if_called,
    )

    result = run_katana_crawl(
        inventory=HTTPServiceInventory(),
        depth=3,
        crawl_duration_seconds=300,
        request_rate=5,
        max_response_bytes=1_000_000,
        max_output_bytes=1_000_000,
        timeout_seconds=330,
    )

    assert result.endpoints == ()


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("depth", 0, "depth"),
        (
            "crawl_duration_seconds",
            0,
            "crawl duration",
        ),
        (
            "request_rate",
            0,
            "request rate",
        ),
        (
            "max_response_bytes",
            0,
            "response size",
        ),
        (
            "max_output_bytes",
            0,
            "output limit",
        ),
        (
            "timeout_seconds",
            0,
            "timeout",
        ),
    ],
)
def test_run_katana_rejects_non_positive_budgets(
    field,
    value,
    match,
):
    from app.scanners.katana import (
        KatanaScannerError,
        run_katana_crawl,
    )

    kwargs = {
        "inventory": HTTPServiceInventory(
            services=(
                _http_service(),
            ),
        ),
        "depth": 3,
        "crawl_duration_seconds": 300,
        "request_rate": 5,
        "max_response_bytes": 1_000_000,
        "max_output_bytes": 1_000_000,
        "timeout_seconds": 330,
    }

    kwargs[field] = value

    with pytest.raises(
        KatanaScannerError,
        match=match,
    ):
        run_katana_crawl(
            **kwargs,
        )


def test_get_katana_version_uses_dedicated_binary(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.katana import (
        get_katana_version,
    )

    captured = {}

    monkeypatch.setattr(
        settings,
        "katana_binary",
        "/usr/local/bin/pd-katana",
        raising=False,
    )

    def fake_run(command, **kwargs):
        captured["command"] = command

        return _completed_process(
            stdout=b"Current Version: v1.7.0\n",
        )

    monkeypatch.setattr(
        "app.scanners.katana.subprocess.run",
        fake_run,
    )

    assert get_katana_version() == "v1.7.0"

    assert captured["command"] == [
        "/usr/local/bin/pd-katana",
        "-version",
    ]


def test_run_katana_rejects_scanner_failure(
    monkeypatch,
):
    from app.config import settings
    from app.scanners.katana import (
        KatanaScannerError,
        run_katana_crawl,
    )

    monkeypatch.setattr(
        settings,
        "katana_binary",
        "/usr/local/bin/pd-katana",
        raising=False,
    )

    monkeypatch.setattr(
        "app.scanners.katana.subprocess.run",
        lambda *args, **kwargs: _completed_process(
            returncode=1,
            stderr=b"katana failed",
        ),
    )

    with pytest.raises(
        KatanaScannerError,
        match="exited unsuccessfully",
    ):
        run_katana_crawl(
            inventory=HTTPServiceInventory(
                services=(
                    _http_service(),
                ),
            ),
            depth=3,
            crawl_duration_seconds=300,
            request_rate=5,
            max_response_bytes=1_000_000,
            max_output_bytes=1_000_000,
            timeout_seconds=330,
        )
