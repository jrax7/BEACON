from __future__ import annotations

import inspect


def test_findings_router_exposes_workflow_routes() -> None:
    import app.main as main_module

    schema = main_module.app.openapi()
    paths = schema["paths"]

    expected = {
        "/api/v1/findings/{finding_id}/lifecycle":
            "patch",
        "/api/v1/findings/{finding_id}/disposition":
            "patch",
        "/api/v1/findings/{finding_id}/assignee":
            "patch",
        "/api/v1/findings/{finding_id}/remediation-owner":
            "patch",
        "/api/v1/findings/{finding_id}/history":
            "get",
    }

    missing = []

    for path, method in expected.items():
        if (
            path not in paths
            or method not in paths[path]
        ):
            missing.append(
                f"{method.upper()} {path}"
            )

    assert not missing, (
        "Phase 16E workflow API routes are missing: "
        + ", ".join(missing)
    )

    assert (
        "delete"
        in paths[
            "/api/v1/findings/{finding_id}/disposition"
        ]
    )


def test_workflow_routes_use_server_actor_and_manage_permission() -> None:
    import app.routers.findings as module

    source = inspect.getsource(module)

    assert "Permission.FINDING_MANAGE" in source
    assert "actor_user_id=current_user.id" in (
        source.replace(" ", "").replace("\n", "")
    )
    assert "resolve_workspace_members" in source
