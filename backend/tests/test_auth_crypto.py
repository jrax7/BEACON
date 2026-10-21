from __future__ import annotations

import base64
import re

from app.auth.crypto import (
    generate_opaque_token,
    hash_opaque_token,
)


def _decode_urlsafe(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)

    return base64.urlsafe_b64decode(
        value + padding
    )


def test_opaque_token_has_at_least_256_bits_of_randomness_shape() -> None:
    first = generate_opaque_token()
    second = generate_opaque_token()

    assert first != second
    assert len(_decode_urlsafe(first)) >= 32
    assert len(_decode_urlsafe(second)) >= 32


def test_hash_is_sha256_hex_and_not_equal_to_raw() -> None:
    raw = generate_opaque_token()
    hashed = hash_opaque_token(raw)

    assert hashed != raw
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        hashed,
    )
