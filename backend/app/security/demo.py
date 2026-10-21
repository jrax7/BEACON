from fastapi import HTTPException, status

from app.config import settings
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.security.targets import normalize_target_url


DEMO_ROLE = "demo"


def is_demo_user(
    user: User,
) -> bool:
    """Return whether the account uses the shared demo role."""

    return user.role == DEMO_ROLE


def ensure_demo_mutation_allowed(
    user: User,
) -> None:
    """Prevent demo accounts from protected mutations."""

    if not is_demo_user(user):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "This action is not available for demo accounts."
        ),
    )


def configured_demo_hostname() -> str:
    """Return the configured demo target hostname."""

    normalized_target = normalize_target_url(
        settings.demo_target_url,
    )

    return normalized_target.hostname


def ensure_demo_target_allowed(
    user: User,
    target: Target,
) -> None:
    """Restrict demo accounts to the configured lab target."""

    if not is_demo_user(user):
        return

    if target.hostname != configured_demo_hostname():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )


def ensure_demo_scan_level_allowed(
    user: User,
    scan_level: str,
) -> None:
    """Restrict demo accounts to the Basic scan profile."""

    if not is_demo_user(user):
        return

    if scan_level != "basic":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This scan profile is not available "
                "for demo accounts."
            ),
        )


def ensure_demo_active_scan_allowed(
    user: User,
    active_scan: Scan | None,
) -> None:
    """Allow only one active assessment for the demo account."""

    if not is_demo_user(user):
        return

    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "A demo assessment is already running. "
                "Wait for it to finish before starting another."
            ),
        )
