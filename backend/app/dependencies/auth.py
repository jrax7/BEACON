from typing import (
    Annotated,
)

from fastapi import Depends

from app.auth.principal import (
    AuthenticatedPrincipal,
    get_current_principal,
    get_logout_principal,
    oauth2_scheme,
)
from app.models.user import User


CurrentPrincipal = Annotated[
    AuthenticatedPrincipal,
    Depends(
        get_current_principal
    ),
]


CurrentLogoutPrincipal = Annotated[
    AuthenticatedPrincipal,
    Depends(
        get_logout_principal
    ),
]


def get_current_user(
    principal: CurrentPrincipal,
) -> User:
    """Preserve CurrentUser while carrying request organization context."""

    setattr(
        principal.user,
        "_beacon_organization_id",
        principal.organization_id,
    )

    return principal.user


CurrentUser = Annotated[
    User,
    Depends(
        get_current_user
    ),
]


__all__ = [
    "CurrentLogoutPrincipal",
    "CurrentPrincipal",
    "CurrentUser",
    "get_current_principal",
    "get_logout_principal",
    "get_current_user",
    "oauth2_scheme",
]
