from __future__ import annotations

from types import SimpleNamespace


class FakeResponse:
    def __init__(
        self,
        payload,
    ):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeClient:
    def __init__(
        self,
        payload,
    ):
        self.payload = payload
        self.calls = []

    def post(
        self,
        url,
        *,
        data,
        timeout,
    ):
        self.calls.append(
            {
                "url": url,
                "data": data,
                "timeout": timeout,
            }
        )

        return FakeResponse(
            self.payload
        )


def _settings(
    *,
    environment="production",
    secret="turnstile-secret",
):
    return SimpleNamespace(
        environment=environment,
        turnstile_secret_key=secret,
    )


def test_turnstile_success_is_accepted() -> None:
    from app.auth.turnstile import verify_turnstile

    client = FakeClient(
        {
            "success": True,
        }
    )

    assert verify_turnstile(
        "browser-token",
        remote_ip="203.0.113.9",
        runtime_settings=_settings(),
        client=client,
    )

    assert len(client.calls) == 1

    call = client.calls[0]

    assert (
        call["url"]
        == "https://challenges.cloudflare.com/"
        "turnstile/v0/siteverify"
    )

    assert (
        call["data"]["secret"]
        == "turnstile-secret"
    )

    assert (
        call["data"]["response"]
        == "browser-token"
    )

    assert (
        call["data"]["remoteip"]
        == "203.0.113.9"
    )

    assert call["timeout"] <= 5.0


def test_turnstile_false_response_is_rejected() -> None:
    from app.auth.turnstile import verify_turnstile

    client = FakeClient(
        {
            "success": False,
        }
    )

    assert not verify_turnstile(
        "browser-token",
        runtime_settings=_settings(),
        client=client,
    )


def test_turnstile_production_failure_fails_closed() -> None:
    from app.auth.turnstile import verify_turnstile

    class BrokenClient:
        def post(self, *args, **kwargs):
            raise RuntimeError(
                "network failure"
            )

    assert not verify_turnstile(
        "browser-token",
        runtime_settings=_settings(),
        client=BrokenClient(),
    )


def test_development_can_omit_turnstile_secret() -> None:
    from app.auth.turnstile import verify_turnstile

    assert verify_turnstile(
        "",
        runtime_settings=_settings(
            environment="development",
            secret="",
        ),
        client=FakeClient(
            {
                "success": False,
            }
        ),
    )


def test_production_rejects_missing_turnstile_token() -> None:
    from app.auth.turnstile import verify_turnstile

    assert not verify_turnstile(
        "",
        runtime_settings=_settings(),
        client=FakeClient(
            {
                "success": True,
            }
        ),
    )
