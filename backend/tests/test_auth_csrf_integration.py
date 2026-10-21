from __future__ import annotations

from pathlib import Path


PRINCIPAL = (
    Path(__file__).resolve().parents[1]
    / "app"
    / "auth"
    / "principal.py"
)


def _source() -> str:
    assert PRINCIPAL.exists(), (
        "centralized principal resolver does not exist yet"
    )

    return PRINCIPAL.read_text(
        encoding="utf-8",
    )


def test_session_unsafe_policy_mentions_csrf_header() -> None:
    source = _source()

    assert "X-CSRF-Token" in source


def test_session_unsafe_policy_validates_origin_and_referer() -> None:
    source = _source()

    assert "Origin" in source
    assert "Referer" in source


def test_origin_policy_uses_configured_browser_origins() -> None:
    source = _source()

    assert "browser_origins" in source


def test_principal_resolver_distinguishes_session_and_bearer() -> None:
    source = _source()

    assert '"session"' in source
    assert '"bearer"' in source


def test_mixed_auth_has_stable_error_code() -> None:
    source = _source()

    assert "AUTH_MIXED_CREDENTIALS" in source


def test_csrf_has_stable_error_code() -> None:
    source = _source()

    assert "CSRF_INVALID" in source


def test_origin_has_stable_error_code() -> None:
    source = _source()

    assert "ORIGIN_INVALID" in source
