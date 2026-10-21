from __future__ import annotations

from uuid import uuid4

import app.auth.csrf as csrf


SECRET = "c" * 64


def test_csrf_is_stable_for_session_and_secret() -> None:
    session_id = uuid4()

    first = csrf.derive_csrf_token(
        session_id,
        SECRET,
    )
    second = csrf.derive_csrf_token(
        session_id,
        SECRET,
    )

    assert first == second
    assert first


def test_csrf_changes_for_different_session() -> None:
    first = csrf.derive_csrf_token(
        uuid4(),
        SECRET,
    )
    second = csrf.derive_csrf_token(
        uuid4(),
        SECRET,
    )

    assert first != second


def test_csrf_validation_rejects_wrong_value() -> None:
    session_id = uuid4()

    assert csrf.validate_csrf_token(
        session_id,
        csrf.derive_csrf_token(
            session_id,
            SECRET,
        ),
        SECRET,
    )

    assert not csrf.validate_csrf_token(
        session_id,
        "incorrect",
        SECRET,
    )


def test_csrf_compare_uses_constant_time_helper(
    monkeypatch,
) -> None:
    session_id = uuid4()
    candidate = csrf.derive_csrf_token(
        session_id,
        SECRET,
    )

    real_compare = csrf.hmac.compare_digest
    calls = []

    def tracked_compare(left, right):
        calls.append(
            (
                left,
                right,
            )
        )

        return real_compare(
            left,
            right,
        )

    monkeypatch.setattr(
        csrf.hmac,
        "compare_digest",
        tracked_compare,
    )

    assert csrf.validate_csrf_token(
        session_id,
        candidate,
        SECRET,
    )

    assert len(calls) == 1
