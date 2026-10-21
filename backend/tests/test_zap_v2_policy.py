from datetime import datetime, timezone

import pytest

from app.assessment.authorization import (
    ActiveAuthorizationConfirmation,
)


def _valid_active_confirmation():
    return ActiveAuthorizationConfirmation(
        confirmed=True,
        confirmed_by_user_id=42,
        confirmed_at=datetime.now(timezone.utc),
        authorization_version="active-v1",
    )


def test_quick_zap_policy_never_enables_active_scanning():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=None,
    )

    assert policy.profile_name == "quick"
    assert policy.policy_version == "beacon-quick-v1"
    assert policy.active_scan_enabled is False


def test_standard_zap_policy_requires_active_authorization():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    with pytest.raises(
        ValueError,
        match="active testing authorization",
    ):
        resolve_zap_policy(
            profile_name="standard",
            active_confirmation=None,
        )


def test_deep_zap_policy_requires_active_authorization():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    with pytest.raises(
        ValueError,
        match="active testing authorization",
    ):
        resolve_zap_policy(
            profile_name="deep",
            active_confirmation=None,
        )


def test_standard_zap_policy_enables_locked_active_policy():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=(
            _valid_active_confirmation()
        ),
    )

    assert policy.profile_name == "standard"
    assert (
        policy.policy_version
        == "beacon-standard-v1"
    )
    assert policy.active_scan_enabled is True


def test_deep_zap_policy_enables_locked_active_policy():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="deep",
        active_confirmation=(
            _valid_active_confirmation()
        ),
    )

    assert policy.profile_name == "deep"
    assert (
        policy.policy_version
        == "beacon-deep-v1"
    )
    assert policy.active_scan_enabled is True


def test_quick_remains_passive_even_with_active_confirmation():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=(
            _valid_active_confirmation()
        ),
    )

    assert policy.profile_name == "quick"
    assert policy.active_scan_enabled is False


def test_zap_scope_selects_only_exact_authorized_fqdn():
    from app.assessment.handoff import (
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.assessment.zap_policy import (
        build_zap_scope_selection,
    )

    portal_root = WebEndpoint(
        url="https://portal.example.com/",
        method="GET",
        discovery_method="katana",
    )

    portal_login = WebEndpoint(
        url="https://PORTAL.EXAMPLE.COM/login",
        method="POST",
        parameter_names=(
            "username",
            "password",
        ),
        discovery_method="form",
    )

    portal_trailing_dot = WebEndpoint(
        url="https://portal.example.com./account",
        method="GET",
        discovery_method="katana",
    )

    sibling = WebEndpoint(
        url="https://api.example.com/v1/",
        method="GET",
        discovery_method="katana",
    )

    child = WebEndpoint(
        url="https://child.portal.example.com/",
        method="GET",
        discovery_method="katana",
    )

    external_redirect = WebEndpoint(
        url="https://login.microsoftonline.com/",
        method="GET",
        source_url="https://portal.example.com/login",
        discovery_method="redirect",
    )

    inventory = WebEndpointInventory(
        endpoints=(
            portal_root,
            portal_login,
            portal_trailing_dot,
            sibling,
            child,
            external_redirect,
        )
    )

    selection = build_zap_scope_selection(
        authorized_host="portal.example.com",
        inventory=inventory,
    )

    assert selection.authorized_host == (
        "portal.example.com"
    )

    assert selection.included_endpoints == (
        portal_root,
        portal_login,
        portal_trailing_dot,
    )

    assert selection.excluded_endpoints == (
        sibling,
        child,
        external_redirect,
    )


def test_zap_scope_excludes_urls_containing_userinfo():
    from app.assessment.handoff import (
        WebEndpoint,
        WebEndpointInventory,
    )
    from app.assessment.zap_policy import (
        build_zap_scope_selection,
    )

    username_only = WebEndpoint(
        url=(
            "https://evil.example@"
            "portal.example.com/account"
        ),
        method="GET",
        discovery_method="katana",
    )

    username_and_password = WebEndpoint(
        url=(
            "https://user:secret@"
            "portal.example.com/private"
        ),
        method="GET",
        discovery_method="katana",
    )

    normal_endpoint = WebEndpoint(
        url="https://portal.example.com/dashboard",
        method="GET",
        discovery_method="katana",
    )

    inventory = WebEndpointInventory(
        endpoints=(
            username_only,
            username_and_password,
            normal_endpoint,
        )
    )

    selection = build_zap_scope_selection(
        authorized_host="portal.example.com",
        inventory=inventory,
    )

    assert selection.included_endpoints == (
        normal_endpoint,
    )

    assert selection.excluded_endpoints == (
        username_only,
        username_and_password,
    )


def test_quick_zap_policy_has_no_active_rules():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="quick",
        active_confirmation=None,
    )

    assert policy.active_scan_enabled is False
    assert policy.default_alert_threshold == "OFF"
    assert policy.active_rules == ()
    assert policy.max_rule_duration_minutes == 0
    assert policy.max_scan_duration_minutes == 0


def test_standard_uses_explicit_locked_active_rule_allowlist():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=(
            _valid_active_confirmation()
        ),
    )

    assert policy.active_scan_enabled is True

    assert policy.default_alert_threshold == "OFF"

    assert policy.default_attack_strength == "LOW"

    assert tuple(
        rule.rule_id
        for rule in policy.active_rules
    ) == (
        6,       # Path Traversal
        20019,   # External Redirect
        40003,   # CRLF Injection
        40008,   # Parameter Tampering
        40012,   # Reflected XSS
        40018,   # SQL Injection
        40032,   # .htaccess Information Leak
        40034,   # .env Information Leak
        40035,   # Hidden File Finder
        90021,   # XPath Injection
    )

    assert policy.max_rule_duration_minutes == 2
    assert policy.max_scan_duration_minutes == 20
    assert policy.max_alerts_per_rule == 20


def test_deep_is_explicit_superset_of_standard_policy():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    confirmation = (
        _valid_active_confirmation()
    )

    standard = resolve_zap_policy(
        profile_name="standard",
        active_confirmation=confirmation,
    )

    deep = resolve_zap_policy(
        profile_name="deep",
        active_confirmation=confirmation,
    )

    standard_ids = {
        rule.rule_id
        for rule in standard.active_rules
    }

    deep_ids = {
        rule.rule_id
        for rule in deep.active_rules
    }

    assert standard_ids < deep_ids

    assert deep_ids == {
        6,       # Path Traversal
        7,       # Remote File Inclusion
        20019,   # External Redirect
        40003,   # CRLF Injection
        40008,   # Parameter Tampering
        40009,   # Server Side Include
        40012,   # Reflected XSS
        40018,   # SQL Injection
        40032,   # .htaccess Information Leak
        40034,   # .env Information Leak
        40035,   # Hidden File Finder
        40042,   # Spring Actuator Information Leak
        90017,   # XSLT Injection
        90019,   # Server Side Code Injection
        90020,   # Remote OS Command Injection
        90021,   # XPath Injection
        90023,   # XML External Entity
        90035,   # Server Side Template Injection
    }

    assert deep.default_alert_threshold == "OFF"
    assert deep.default_attack_strength == "MEDIUM"

    assert deep.max_rule_duration_minutes == 5
    assert deep.max_scan_duration_minutes == 45
    assert deep.max_alerts_per_rule == 50


def test_locked_zap_policies_never_use_insane_strength():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    confirmation = (
        _valid_active_confirmation()
    )

    for profile_name in (
        "standard",
        "deep",
    ):
        policy = resolve_zap_policy(
            profile_name=profile_name,
            active_confirmation=confirmation,
        )

        assert (
            policy.default_attack_strength
            != "INSANE"
        )

        assert all(
            rule.attack_strength
            != "INSANE"
            for rule in policy.active_rules
        )


def test_locked_zap_policies_exclude_unapproved_risky_rules():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    blocked_rule_ids = {
        20015,   # Heartbleed
        20018,   # RCE CVE-2012-1823
        30001,   # Buffer Overflow
        30002,   # Format String Error
        40014,   # Persistent XSS
        40016,   # Persistent XSS Prime
        40017,   # Persistent XSS Spider
        40043,   # Log4Shell
        40044,   # Billion Laughs / DoS
        40045,   # Spring4Shell
        40048,   # React2Shell
        50000,   # Script Active Scan Rules
        90026,   # Beta
        90029,   # Beta
        90034,   # Cloud Metadata
        90036,   # Blind SSTI
        90037,   # Time-based OS command injection
        100043,  # Alpha
    }

    confirmation = (
        _valid_active_confirmation()
    )

    for profile_name in (
        "standard",
        "deep",
    ):
        policy = resolve_zap_policy(
            profile_name=profile_name,
            active_confirmation=confirmation,
        )

        enabled_ids = {
            rule.rule_id
            for rule in policy.active_rules
        }

        assert enabled_ids.isdisjoint(
            blocked_rule_ids
        )


def test_unknown_future_zap_rule_is_not_implicitly_enabled():
    from app.assessment.zap_policy import (
        resolve_zap_policy,
    )

    policy = resolve_zap_policy(
        profile_name="deep",
        active_confirmation=(
            _valid_active_confirmation()
        ),
    )

    assert (
        999999
        not in {
            rule.rule_id
            for rule in policy.active_rules
        }
    )
