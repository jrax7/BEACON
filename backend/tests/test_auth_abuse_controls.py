from __future__ import annotations

from types import SimpleNamespace


class FakeRedis:
    def __init__(self):
        self.eval_calls = []
        self.deleted = []
        self.setex_calls = []
        self.ttl_value = 0
        self.sliding_response = [
            1,
            1,
            0,
        ]
        self.failure_count = 0

    def eval(
        self,
        script,
        numkeys,
        *args,
    ):
        self.eval_calls.append(
            (
                script,
                numkeys,
                args,
            )
        )

        if "failure-history" in script:
            return self.failure_count

        return self.sliding_response

    def delete(self, *keys):
        self.deleted.extend(keys)

    def ttl(self, key):
        return self.ttl_value

    def setex(
        self,
        key,
        seconds,
        value,
    ):
        self.setex_calls.append(
            (
                key,
                seconds,
                value,
            )
        )


def _settings():
    return SimpleNamespace(
        redis_url="redis://unused/0",
    )


def test_denied_sliding_window_exposes_bounded_retry() -> None:
    from app.auth.rate_limit import RedisRateLimiter

    fake = FakeRedis()

    fake.sliding_response = [
        0,
        10,
        30_000,
    ]

    limiter = RedisRateLimiter(
        client=fake,
        runtime_settings=_settings(),
    )

    decision = limiter.check(
        "login_ip",
        "203.0.113.20",
    )

    assert not decision.allowed
    assert decision.retry_after == 30
    assert decision.count == 10


def test_success_clear_removes_only_identity_failure_state() -> None:
    from app.auth.rate_limit import (
        RedisRateLimiter,
        rate_limit_key,
    )

    fake = FakeRedis()

    limiter = RedisRateLimiter(
        client=fake,
        runtime_settings=_settings(),
    )

    identity = "User@Example.COM"

    limiter.clear_login_failures(
        identity
    )

    failure_key = rate_limit_key(
        "login-identity-failures",
        identity,
    )

    cooldown_key = rate_limit_key(
        "login-identity-cooldown",
        identity,
    )

    ip_key = rate_limit_key(
        "login-ip",
        "203.0.113.20",
    )

    assert failure_key in fake.deleted
    assert cooldown_key in fake.deleted
    assert ip_key not in fake.deleted


def test_fifth_failure_creates_one_minute_cooldown() -> None:
    from app.auth.rate_limit import RedisRateLimiter

    fake = FakeRedis()
    fake.failure_count = 5

    limiter = RedisRateLimiter(
        client=fake,
        runtime_settings=_settings(),
    )

    retry_after = limiter.record_login_failure(
        "user@example.com"
    )

    assert retry_after == 60

    assert fake.setex_calls
    assert fake.setex_calls[-1][1] == 60


def test_active_identity_cooldown_is_observed() -> None:
    from app.auth.rate_limit import RedisRateLimiter

    fake = FakeRedis()
    fake.ttl_value = 217

    limiter = RedisRateLimiter(
        client=fake,
        runtime_settings=_settings(),
    )

    assert (
        limiter.login_cooldown_retry_after(
            "user@example.com"
        )
        == 217
    )


def test_router_applies_same_abuse_helper_to_session_and_token() -> None:
    from pathlib import Path

    source = Path(
        "/app/app/routers/auth.py"
    ).read_text(
        encoding="utf-8",
    )

    assert (
        source.count(
            "_authenticate_with_abuse_controls("
        )
        >= 2
    )


def test_normal_login_does_not_require_turnstile() -> None:
    from pathlib import Path

    source = Path(
        "/app/app/routers/auth.py"
    ).read_text(
        encoding="utf-8",
    )

    login_start = source.index(
        '@router.post(\n    "/login",'
    )

    token_start = source.index(
        '@router.post(\n    "/token",'
    )

    login_block = source[
        login_start:token_start
    ]

    assert "verify_turnstile" not in login_block
