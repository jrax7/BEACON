import pytest


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("192.168.1.10", "private"),
        ("10.0.0.1", "private"),
        ("fc00::1", "private"),
        ("169.254.169.254", "link_local"),
        ("fe80::1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("8.8.8.8", "public"),
        ("2606:4700:4700::1111", "public"),
    ],
)
def test_address_classification(address, expected):
    from app.assessment.scope import classify_ip_address

    assert classify_ip_address(address).value == expected


def test_private_resolution_is_rejected_for_public_web_scan():
    from app.assessment.scope import validate_resolved_addresses

    with pytest.raises(
        ValueError,
        match="blocked address class",
    ):
        validate_resolved_addresses(
            ["192.168.1.10"],
        )


def test_loopback_resolution_is_rejected_for_public_web_scan():
    from app.assessment.scope import validate_resolved_addresses

    with pytest.raises(
        ValueError,
        match="blocked address class",
    ):
        validate_resolved_addresses(
            ["127.0.0.1"],
        )


def test_public_resolution_is_allowed():
    from app.assessment.scope import validate_resolved_addresses

    validate_resolved_addresses(
        ["8.8.8.8"],
    )


def test_explicit_lab_mode_can_allow_private_address():
    from app.assessment.scope import validate_resolved_addresses

    validate_resolved_addresses(
        ["192.168.1.50"],
        allow_private=True,
    )


def test_exact_fqdn_matches_case_insensitively():
    from app.assessment.scope import host_is_within_exact_fqdn

    assert host_is_within_exact_fqdn(
        "PORTAL.EXAMPLE.COM",
        "portal.example.com",
    )


def test_exact_fqdn_accepts_trailing_dns_dot():
    from app.assessment.scope import host_is_within_exact_fqdn

    assert host_is_within_exact_fqdn(
        "portal.example.com.",
        "portal.example.com",
    )


def test_exact_fqdn_does_not_authorize_sibling_subdomain():
    from app.assessment.scope import host_is_within_exact_fqdn

    assert (
        host_is_within_exact_fqdn(
            "api.example.com",
            "portal.example.com",
        )
        is False
    )


def test_exact_fqdn_does_not_authorize_child_subdomain():
    from app.assessment.scope import host_is_within_exact_fqdn

    assert (
        host_is_within_exact_fqdn(
            "child.portal.example.com",
            "portal.example.com",
        )
        is False
    )
