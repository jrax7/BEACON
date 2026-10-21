import inspect


def test_retest_link_request_schema_exists() -> None:
    from app.schemas.findings import (
        FindingRetestLinkRequest,
    )

    fields = (
        FindingRetestLinkRequest
        .model_fields
    )

    assert "scan_id" in fields
    assert fields["scan_id"].is_required()


def test_retest_link_route_precedes_dynamic_finding_routes() -> None:
    import app.routers.findings as module

    source = inspect.getsource(
        module
    )

    static_path = (
        '"/retests/{retest_id}/scan"'
    )

    dynamic_path = (
        '"/{finding_id:path}'
    )

    assert static_path in source
    assert dynamic_path in source

    assert (
        source.index(static_path)
        < source.index(dynamic_path)
    )


def test_retest_link_route_uses_manage_permission_and_service() -> None:
    import app.routers.findings as module

    source = inspect.getsource(
        module.link_finding_retest_scan
    )

    assert (
        "Permission.FINDING_MANAGE"
        in source
    )

    assert (
        "link_retest_scan("
        in source
    )

    assert (
        "database.commit()"
        in source
    )


def test_retest_link_route_is_exposed_in_openapi() -> None:
    from app.main import app

    schema = app.openapi()

    path = (
        "/api/v1/findings/"
        "retests/{retest_id}/scan"
    )

    assert path in schema["paths"]
    assert (
        "patch"
        in schema["paths"][path]
    )


def test_link_service_finalizes_already_terminal_scan() -> None:
    import inspect

    from app.services.finding_retests import (
        link_retest_scan,
    )

    source = inspect.getsource(
        link_retest_scan
    )

    assert "database.flush()" in source

    assert (
        "complete_retests_for_terminal_scan("
        in source
    )
