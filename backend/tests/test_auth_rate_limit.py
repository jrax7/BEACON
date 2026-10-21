from __future__ import annotations


def test_rate_limit_module_exists() -> None:
    from app.auth.rate_limit import RedisRateLimiter

    assert RedisRateLimiter is not None


def test_rate_limit_dimension_is_normalized_and_hashed() -> None:
    from app.auth.rate_limit import rate_limit_key

    first = rate_limit_key(
        "login-identity",
        " User@Example.COM ",
    )

    second = rate_limit_key(
        "login-identity",
        "user@example.com",
    )

    assert first == second

    assert (
        "user@example.com"
        not in first.lower()
    )


def test_ip_dimension_is_not_stored_in_plaintext() -> None:
    from app.auth.rate_limit import rate_limit_key

    result = rate_limit_key(
        "login-ip",
        "203.0.113.55",
    )

    assert "203.0.113.55" not in result


def test_progressive_login_cooldown_contract() -> None:
    from app.auth.rate_limit import (
        login_cooldown_seconds,
    )

    assert login_cooldown_seconds(0) == 0
    assert login_cooldown_seconds(4) == 0

    assert login_cooldown_seconds(5) == 60
    assert login_cooldown_seconds(7) == 60

    assert login_cooldown_seconds(8) == 300
    assert login_cooldown_seconds(9) == 300

    assert login_cooldown_seconds(10) == 900
    assert login_cooldown_seconds(50) == 900


def test_declared_rate_policies_match_phase16b_defaults() -> None:
    from app.auth.rate_limit import POLICIES

    assert POLICIES["login_ip"] == (
        10,
        60,
    )

    assert POLICIES["login_identity_failure"] == (
        5,
        15 * 60,
    )

    assert POLICIES["registration_ip"] == (
        5,
        60 * 60,
    )

    assert POLICIES["forgot_ip"] == (
        5,
        15 * 60,
    )

    assert POLICIES["forgot_identity"] == (
        3,
        60 * 60,
    )

    assert POLICIES["resend_ip"] == (
        5,
        60 * 60,
    )

    assert POLICIES["resend_identity"] == (
        3,
        60 * 60,
    )


def test_rate_limit_lua_is_true_sliding_window() -> None:
    from app.auth.rate_limit import (
        SLIDING_WINDOW_LUA,
    )

    source = SLIDING_WINDOW_LUA.upper()

    assert "ZREMRANGEBYSCORE" in source
    assert "ZCARD" in source
    assert "ZADD" in source
    assert "PEXPIRE" in source
