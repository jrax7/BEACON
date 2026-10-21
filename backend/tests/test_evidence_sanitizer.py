import importlib.util


def _evidence_module():
    try:
        spec = importlib.util.find_spec(
            "app.assessment.evidence"
        )
    except ModuleNotFoundError:
        spec = None

    assert spec is not None, (
        "Evidence sanitizer module does not exist yet."
    )

    from app.assessment import evidence

    return evidence


def test_sanitize_headers_redacts_secret_headers_case_insensitively():
    evidence = _evidence_module()

    headers = {
        "Authorization": "Bearer auth-secret",
        "authorization": "Basic lower-secret",
        "COOKIE": "session=cookie-secret",
        "Set-Cookie": "session=response-secret",
        "X-API-Key": "api-secret",
        "X-Auth-Token": "auth-token-secret",
        "Content-Type": "application/json",
        "Server": "nginx",
    }

    sanitized = evidence.sanitize_headers(
        headers
    )

    for key in (
        "Authorization",
        "authorization",
        "COOKIE",
        "Set-Cookie",
        "X-API-Key",
        "X-Auth-Token",
    ):
        assert sanitized[key] == (
            evidence.REDACTED
        )

    assert sanitized[
        "Content-Type"
    ] == "application/json"

    assert sanitized[
        "Server"
    ] == "nginx"

    assert headers[
        "Authorization"
    ] == "Bearer auth-secret"


def test_sanitize_text_redacts_common_secret_assignments_case_insensitively():
    evidence = _evidence_module()

    value = (
        "Password=OpenSesame\n"
        "TOKEN: abc123\n"
        '"api_key": "api-value"\n'
        "Authorization: Bearer bearer-value\n"
        "note=keep-this"
    )

    sanitized = evidence.sanitize_text(
        value
    )

    for secret in (
        "OpenSesame",
        "abc123",
        "api-value",
        "bearer-value",
    ):
        assert secret not in sanitized

    assert "Password=[REDACTED]" in sanitized
    assert "TOKEN: [REDACTED]" in sanitized

    assert (
        '"api_key": "[REDACTED]"'
        in sanitized
    )

    assert (
        "Authorization: [REDACTED]"
        in sanitized
    )

    assert "note=keep-this" in sanitized



def test_sanitize_text_bounds_utf8_output_by_bytes():
    evidence = _evidence_module()

    value = (
        b"token=body-secret\n"
        + (
            "\U0001f642" * 100
        ).encode(
            "utf-8"
        )
    )

    sanitized = evidence.sanitize_text(
        value,
        max_bytes=48,
    )

    assert sanitized is not None

    assert "body-secret" not in sanitized

    assert len(
        sanitized.encode(
            "utf-8"
        )
    ) <= 48

    assert sanitized.endswith(
        evidence.TRUNCATION_MARKER
    )


def test_sanitize_http_evidence_sanitizes_bodies_and_headers_without_mutation():
    evidence = _evidence_module()

    request_headers = {
        "Authorization":
            "Bearer request-secret",
        "Content-Type":
            "application/json",
    }

    response_headers = {
        "Set-Cookie":
            "session=response-cookie",
        "Server":
            "nginx",
    }

    request_body = (
        '{"password":"request-body-secret",'
        '"name":"alice"}'
    )

    response_body = (
        "token=response-body-secret\n"
        + ("x" * 200)
    )

    sanitized = (
        evidence.sanitize_http_evidence(
            request_headers=request_headers,
            response_headers=response_headers,
            request_body=request_body,
            response_body=response_body,
            max_body_bytes=72,
        )
    )

    assert sanitized[
        "request"
    ][
        "headers"
    ][
        "Authorization"
    ] == evidence.REDACTED

    assert sanitized[
        "response"
    ][
        "headers"
    ][
        "Set-Cookie"
    ] == evidence.REDACTED

    assert sanitized[
        "request"
    ][
        "headers"
    ][
        "Content-Type"
    ] == "application/json"

    assert sanitized[
        "response"
    ][
        "headers"
    ][
        "Server"
    ] == "nginx"

    assert (
        "request-body-secret"
        not in sanitized[
            "request"
        ][
            "body"
        ]
    )

    assert (
        "response-body-secret"
        not in sanitized[
            "response"
        ][
            "body"
        ]
    )

    assert len(
        sanitized[
            "response"
        ][
            "body"
        ].encode(
            "utf-8"
        )
    ) <= 72

    assert request_headers[
        "Authorization"
    ] == "Bearer request-secret"

    assert response_headers[
        "Set-Cookie"
    ] == "session=response-cookie"

    assert request_body == (
        '{"password":"request-body-secret",'
        '"name":"alice"}'
    )


def test_sanitizer_rejects_nonpositive_body_limit():
    evidence = _evidence_module()

    try:
        evidence.sanitize_text(
            "hello",
            max_bytes=0,
        )
    except ValueError as exc:
        assert (
            "positive"
            in str(
                exc
            ).lower()
        )
    else:
        raise AssertionError(
            "zero evidence body limit was accepted"
        )
