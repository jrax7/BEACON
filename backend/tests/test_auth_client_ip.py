from __future__ import annotations

from types import SimpleNamespace

from app.auth.client_ip import trusted_client_ip


def _request(
    peer: str,
    headers: dict[str, str],
):
    return SimpleNamespace(
        client=SimpleNamespace(
            host=peer,
        ),
        headers=headers,
    )


def _settings(
    trusted_proxy_cidrs: str,
):
    return SimpleNamespace(
        trusted_proxy_cidrs=trusted_proxy_cidrs,
        client_ip_header="x-forwarded-for",
    )


def test_forwarded_header_is_ignored_from_untrusted_peer() -> None:
    request = _request(
        "198.51.100.10",
        {
            "x-forwarded-for": "203.0.113.99",
        },
    )

    assert trusted_client_ip(
        request,
        _settings(
            "10.0.0.0/8",
        ),
    ) == "198.51.100.10"


def test_forwarded_header_is_used_from_explicit_trusted_proxy() -> None:
    request = _request(
        "10.20.30.40",
        {
            "x-forwarded-for": (
                "203.0.113.99, 10.20.30.40"
            ),
        },
    )

    assert trusted_client_ip(
        request,
        _settings(
            "10.0.0.0/8",
        ),
    ) == "203.0.113.99"


def test_invalid_forwarded_ip_fails_closed_to_peer() -> None:
    request = _request(
        "10.20.30.40",
        {
            "x-forwarded-for": "not-an-ip",
        },
    )

    assert trusted_client_ip(
        request,
        _settings(
            "10.0.0.0/8",
        ),
    ) == "10.20.30.40"


def test_no_trusted_proxy_configuration_ignores_forwarding() -> None:
    request = _request(
        "127.0.0.1",
        {
            "x-forwarded-for": "203.0.113.99",
        },
    )

    assert trusted_client_ip(
        request,
        _settings(""),
    ) == "127.0.0.1"
