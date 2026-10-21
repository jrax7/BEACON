from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from time import time
from uuid import uuid4

from redis import Redis
from redis.exceptions import RedisError

from app.config import settings


POLICIES = {
    "login_ip": (
        10,
        60,
    ),
    "login_identity_failure": (
        5,
        15 * 60,
    ),
    "registration_ip": (
        5,
        60 * 60,
    ),
    "forgot_ip": (
        5,
        15 * 60,
    ),
    "forgot_identity": (
        3,
        60 * 60,
    ),
    "resend_ip": (
        5,
        60 * 60,
    ),
    "resend_identity": (
        3,
        60 * 60,
    ),
}


SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now_ms - window_ms

redis.call(
    'ZREMRANGEBYSCORE',
    key,
    '-inf',
    cutoff
)

local count = redis.call(
    'ZCARD',
    key
)

if count >= limit then
    local oldest = redis.call(
        'ZRANGE',
        key,
        0,
        0,
        'WITHSCORES'
    )

    local retry_ms = window_ms

    if oldest[2] then
        retry_ms = math.max(
            1,
            window_ms
            - (
                now_ms
                - tonumber(oldest[2])
            )
        )
    end

    redis.call(
        'PEXPIRE',
        key,
        window_ms + 1000
    )

    return {
        0,
        count,
        retry_ms
    }
end

redis.call(
    'ZADD',
    key,
    now_ms,
    member
)

redis.call(
    'PEXPIRE',
    key,
    window_ms + 1000
)

return {
    1,
    count + 1,
    0
}
"""


LOGIN_FAILURE_LUA = """
-- failure-history
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]
local cutoff = now_ms - window_ms

redis.call(
    'ZREMRANGEBYSCORE',
    key,
    '-inf',
    cutoff
)

redis.call(
    'ZADD',
    key,
    now_ms,
    member
)

redis.call(
    'PEXPIRE',
    key,
    window_ms + 1000
)

return redis.call(
    'ZCARD',
    key
)
"""


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    count: int
    retry_after: int


def _normalize_dimension(
    value: object,
) -> str:
    return str(
        value
    ).strip().lower()


def rate_limit_key(
    namespace: str,
    value: object,
) -> str:
    normalized = _normalize_dimension(
        value
    )

    digest = sha256(
        normalized.encode(
            "utf-8"
        )
    ).hexdigest()

    return (
        "beacon:auth:"
        f"{namespace}:"
        f"{digest}"
    )


def login_cooldown_seconds(
    failure_count: int,
) -> int:
    if failure_count >= 10:
        return 15 * 60

    if failure_count >= 8:
        return 5 * 60

    if failure_count >= 5:
        return 60

    return 0


class RedisRateLimiter:
    """Transient Redis-backed authentication abuse controls."""

    def __init__(
        self,
        *,
        client=None,
        runtime_settings=settings,
        clock=time,
    ) -> None:
        self.runtime_settings = (
            runtime_settings
        )

        self.client = (
            client
            if client is not None
            else Redis.from_url(
                runtime_settings.redis_url,
                decode_responses=True,
            )
        )

        self.clock = clock

    def _now_ms(self) -> int:
        return int(
            self.clock()
            * 1000
        )

    def check(
        self,
        policy_name: str,
        value: object,
    ) -> RateLimitDecision:
        if policy_name not in POLICIES:
            raise ValueError(
                "Unknown authentication rate-limit policy."
            )

        limit, window_seconds = (
            POLICIES[
                policy_name
            ]
        )

        key = rate_limit_key(
            policy_name.replace(
                "_",
                "-",
            ),
            value,
        )

        now_ms = self._now_ms()

        member = (
            f"{now_ms}:"
            f"{uuid4().hex}"
        )

        try:
            result = self.client.eval(
                SLIDING_WINDOW_LUA,
                1,
                key,
                now_ms,
                window_seconds * 1000,
                limit,
                member,
            )
        except RedisError:
            # Redis contains only transient abuse state.
            # Loss of Redis resets counters but must not
            # destroy account/session availability.
            return RateLimitDecision(
                allowed=True,
                count=0,
                retry_after=0,
            )

        allowed = bool(
            int(result[0])
        )

        count = int(
            result[1]
        )

        retry_ms = int(
            result[2]
        )

        return RateLimitDecision(
            allowed=allowed,
            count=count,
            retry_after=(
                max(
                    1,
                    ceil(
                        retry_ms
                        / 1000
                    ),
                )
                if retry_ms > 0
                else 0
            ),
        )

    def login_cooldown_retry_after(
        self,
        identity: object,
    ) -> int:
        key = rate_limit_key(
            "login-identity-cooldown",
            identity,
        )

        try:
            ttl = int(
                self.client.ttl(
                    key
                )
            )
        except RedisError:
            return 0

        return max(
            0,
            ttl,
        )

    def record_login_failure(
        self,
        identity: object,
    ) -> int:
        history_key = rate_limit_key(
            "login-identity-failures",
            identity,
        )

        now_ms = self._now_ms()

        member = (
            f"{now_ms}:"
            f"{uuid4().hex}"
        )

        try:
            failure_count = int(
                self.client.eval(
                    LOGIN_FAILURE_LUA,
                    1,
                    history_key,
                    now_ms,
                    15 * 60 * 1000,
                    member,
                )
            )
        except RedisError:
            return 0

        cooldown = login_cooldown_seconds(
            failure_count
        )

        if cooldown <= 0:
            return 0

        cooldown_key = rate_limit_key(
            "login-identity-cooldown",
            identity,
        )

        try:
            self.client.setex(
                cooldown_key,
                cooldown,
                "1",
            )
        except RedisError:
            return 0

        return cooldown

    def clear_login_failures(
        self,
        identity: object,
    ) -> None:
        history_key = rate_limit_key(
            "login-identity-failures",
            identity,
        )

        cooldown_key = rate_limit_key(
            "login-identity-cooldown",
            identity,
        )

        try:
            self.client.delete(
                history_key,
                cooldown_key,
            )
        except RedisError:
            return
