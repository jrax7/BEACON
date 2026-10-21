from pathlib import Path


BACKEND = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def source(path: str) -> str:
    return (
        BACKEND
        / path
    ).read_text(
        encoding="utf-8",
    )


def test_user_response_exposes_safe_org_metadata() -> None:
    schema = source(
        "app/schemas/auth.py"
    )

    assert (
        "organization_id: UUID | None = None"
        in schema
    )

    assert (
        "organization_name: str | None = None"
        in schema
    )

    assert (
        "organization_role: str | None = None"
        in schema
    )


def test_registration_creates_admin_workspace_in_same_transaction() -> None:
    router = source(
        "app/routers/auth.py"
    )

    register = router.split(
        "def register_user(",
        1,
    )[1].split(
        '@router.post(\n    "/login"',
        1,
    )[0]

    assert (
        "create_personal_organization("
        in register
    )

    assert (
        "OrganizationRole.ADMIN"
        in register
    )

    assert (
        register.index(
            "database.flush()"
        )
        < register.index(
            "create_personal_organization("
        )
        < register.index(
            "database.commit()"
        )
    )


def test_login_and_me_attach_server_resolved_org_metadata() -> None:
    router = source(
        "app/routers/auth.py"
    )

    assert (
        "def _attach_organization_metadata("
        in router
    )

    assert (
        "resolve_organization_context("
        in router
    )

    login = router.split(
        "def browser_login(",
        1,
    )[1].split(
        '@router.post(\n    "/token"',
        1,
    )[0]

    assert (
        "_attach_organization_metadata("
        in login
    )

    me = router.split(
        "def read_current_user(",
        1,
    )[1].split(
        '@router.post(\n    "/logout"',
        1,
    )[0]

    assert (
        "_attach_organization_metadata("
        in me
    )


def test_programmatic_jwt_does_not_embed_org_authority() -> None:
    router = source(
        "app/routers/auth.py"
    )

    token = router.split(
        "def issue_programmatic_token(",
        1,
    )[1].split(
        '@router.get(\n    "/me"',
        1,
    )[0]

    assert "create_access_token(" in token
    assert "user.id" in token

    assert "organization_id" not in token
    assert "organization_role" not in token


def test_auth_audit_supports_nullable_org_context() -> None:
    audit = source(
        "app/auth/audit.py"
    )

    assert (
        "organization_id: UUID | None = None"
        in audit
    )

    assert (
        "organization_id=organization_id"
        in audit
    )


def test_demo_provisioning_uses_isolated_analyst_org() -> None:
    demo = source(
        "app/scripts/provision_demo.py"
    )

    assert (
        "OrganizationRole.ANALYST"
        in demo
    )

    assert (
        "create_personal_organization("
        in demo
    )

    assert (
        "organization_id=organization.id"
        in demo
    )

    assert 'role="demo"' in demo
    assert 'user.role = "demo"' in demo
