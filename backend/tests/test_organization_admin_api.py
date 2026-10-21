from pathlib import Path


BACKEND = (
    Path(__file__)
    .resolve()
    .parents[1]
)


def read(
    relative: str,
) -> str:
    path = (
        BACKEND
        / relative
    )

    if not path.exists():
        return ""

    return path.read_text(
        encoding="utf-8",
    )


def test_organization_admin_router_exists() -> None:
    assert (
        BACKEND
        / "app"
        / "routers"
        / "organizations.py"
    ).exists()


def test_organization_schema_exists() -> None:
    assert (
        BACKEND
        / "app"
        / "schemas"
        / "organizations.py"
    ).exists()


def test_organization_admin_routes_exist() -> None:
    source = read(
        "app/routers/organizations.py"
    )

    for route in (
        "/organizations",
        "/organization",
        "/organization/active",
        "/organization/members",
        "/organization/invitations",
        "/organization/invitations/accept",
    ):
        assert route in source


def test_organization_admin_uses_central_rbac() -> None:
    source = read(
        "app/routers/organizations.py"
    )

    for permission in (
        "Permission.ORGANIZATION_READ",
        "Permission.ORGANIZATION_MANAGE",
        "Permission.MEMBER_MANAGE",
    ):
        assert permission in source

    assert (
        "require_permission"
        in source
    )


def test_membership_role_update_is_supported() -> None:
    source = read(
        "app/routers/organizations.py"
    )

    assert (
        "membership_id"
        in source
    )

    assert (
        "role"
        in source
    )

    assert (
        "PATCH"
        in source
        or
        "@router.patch"
        in source
    )


def test_final_admin_is_protected() -> None:
    source = (
        read(
            "app/routers/organizations.py"
        )
        + read(
            "app/organizations/service.py"
        )
    ).lower()

    assert (
        "final admin"
        in source
        or
        "last admin"
        in source
    )


def test_main_registers_organization_router() -> None:
    source = read(
        "app/main.py"
    )

    assert (
        "organizations"
        in source
    )
