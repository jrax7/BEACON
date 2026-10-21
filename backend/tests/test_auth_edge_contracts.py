from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.routers.auth as auth_router

from app.models.user import User
from app.security.auth import hash_password


PASSWORD = "CorrectPassword-2026"
WRONG_PASSWORD = "WrongPassword-2026"


def test_unknown_and_known_invalid_credentials_both_execute_password_verifier(
    monkeypatch,
) -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
    )

    User.__table__.create(
        engine
    )

    try:
        with Session(
            engine
        ) as database:
            database.add(
                User(
                    id=uuid4(),
                    email="known@example.com",
                    full_name="Known User",
                    password_hash=hash_password(
                        PASSWORD
                    ),
                    role="user",
                    is_active=True,
                    is_email_verified=True,
                )
            )

            database.commit()

            verified_hashes = []

            def fake_verify_password(
                password,
                encoded_hash,
            ):
                assert (
                    password
                    == WRONG_PASSWORD
                )

                verified_hashes.append(
                    encoded_hash
                )

                return False

            monkeypatch.setattr(
                auth_router,
                "verify_password",
                fake_verify_password,
            )

            for email in (
                "missing@example.com",
                "known@example.com",
            ):
                with pytest.raises(
                    HTTPException
                ) as exc_info:
                    auth_router._authenticate_credentials(
                        email,
                        WRONG_PASSWORD,
                        database,
                    )

                assert (
                    exc_info.value.status_code
                    == 401
                )

                detail = (
                    exc_info.value.detail
                )

                assert (
                    detail["code"]
                    == "AUTH_INVALID_CREDENTIALS"
                )

            # Unknown and known-invalid identities must both
            # execute one password-verification path.
            assert (
                len(
                    verified_hashes
                )
                == 2
            )

            assert all(
                isinstance(
                    value,
                    str,
                )
                and value
                for value
                in verified_hashes
            )

    finally:
        engine.dispose()
