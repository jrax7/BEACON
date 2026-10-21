from datetime import datetime, timedelta, timezone
import getpass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.organization import Organization
from app.models.target import Target
from app.models.user import User
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
    get_user_membership,
)
from app.security.auth import hash_password
from app.security.targets import (
    is_allowed_lab_target,
    normalize_target_url,
)


DEMO_FULL_NAME = "BEACON Demo"


def validate_demo_password(
    password: str,
) -> str:
    """Validate the shared demo account password."""

    if len(password) < 12:
        raise ValueError(
            "Demo password must contain at least 12 characters."
        )

    if len(password) > 128:
        raise ValueError(
            "Demo password must not exceed 128 characters."
        )

    return password


def provision_demo(
    database: Session,
    password: str,
) -> tuple[User, Target, bool]:
    """Create or refresh the restricted BEACON demo account."""

    validated_password = validate_demo_password(
        password,
    )

    normalized_email = (
        settings.demo_user_email
        .strip()
        .lower()
    )

    normalized_target = normalize_target_url(
        settings.demo_target_url,
    )

    # Validate the configured destination before changing any DB state.
    if not is_allowed_lab_target(
        normalized_target.hostname,
    ):
        raise RuntimeError(
            "Configured demo target is not an allowed lab target."
        )

    user = database.scalar(
        select(User).where(
            User.email == normalized_email,
        )
    )

    created_user = user is None

    if user is not None and user.role != "demo":
        raise RuntimeError(
            "Refusing to convert an existing non-demo account."
        )

    # For an existing demo account, validate ownership before rotating
    # credentials or mutating any other state.
    if user is not None:
        owned_targets = list(
            database.scalars(
                select(Target).where(
                    Target.user_id == user.id,
                )
            ).all()
        )

        unexpected_targets = [
            owned_target
            for owned_target in owned_targets
            if (
                owned_target.hostname
                != normalized_target.hostname
            )
        ]

        if unexpected_targets:
            raise RuntimeError(
                "Demo account owns unexpected targets; "
                "refusing to continue."
            )

    if user is None:
        user = User(
            email=normalized_email,
            full_name=DEMO_FULL_NAME,
            password_hash=hash_password(
                validated_password,
            ),
            role="demo",
            is_active=True,
            is_email_verified=False,
        )

        database.add(user)
        database.flush()

        owned_targets = []

    else:
        user.full_name = DEMO_FULL_NAME
        user.password_hash = hash_password(
            validated_password,
        )
        user.role = "demo"
        user.is_active = True

    # Phase 16B demo accounts remain authenticated-compatible.
    user.is_email_verified = True

    membership = get_user_membership(
        database,
        user.id,
    )

    if membership is None:
        organization, membership = (
            create_personal_organization(
                database,
                user,
                role=OrganizationRole.ANALYST,
                name="BEACON Demo Workspace",
            )
        )
    else:
        organization = database.get(
            Organization,
            membership.organization_id,
        )

        if organization is None:
            raise RuntimeError(
                "Demo organization membership "
                "is invalid."
            )

        membership.role = (
            OrganizationRole.ANALYST.value
        )

        database.add(
            membership
        )

    for owned_target in owned_targets:
        if (
            owned_target.organization_id
            != organization.id
        ):
            raise RuntimeError(
                "Demo target belongs to an "
                "unexpected organization."
            )

    target = next(
        (
            owned_target
            for owned_target in owned_targets
            if (
                owned_target.hostname
                == normalized_target.hostname
            )
        ),
        None,
    )

    now = datetime.now(timezone.utc)

    if target is None:
        target = Target(
            organization_id=organization.id,
            user_id=user.id,
            original_url=normalized_target.original_url,
            normalized_url=normalized_target.normalized_url,
            hostname=normalized_target.hostname,
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=now,
            verification_expires_at=(
                now
                + timedelta(
                    days=settings.demo_verification_ttl_days,
                )
            ),
        )

        database.add(target)

    else:
        target.original_url = normalized_target.original_url
        target.normalized_url = normalized_target.normalized_url
        target.hostname = normalized_target.hostname
        target.verification_method = "file"
        target.verification_token_hash = None
        target.verification_status = "verified"
        target.verified_at = now
        target.verification_expires_at = (
            now
            + timedelta(
                days=settings.demo_verification_ttl_days,
            )
        )

    database.commit()

    database.refresh(user)
    database.refresh(target)

    return (
        user,
        target,
        created_user,
    )


def main() -> None:
    """Provision or refresh the shared BEACON demo account."""

    password = getpass.getpass(
        "Demo password: ",
    )
    confirmation = getpass.getpass(
        "Confirm demo password: ",
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    with SessionLocal() as database:
        user, target, created_user = provision_demo(
            database,
            password,
        )

    action = (
        "created"
        if created_user
        else "updated"
    )

    print(
        f"Demo account {action}: {user.email}"
    )
    print(
        f"Demo target ready: {target.hostname}"
    )


if __name__ == "__main__":
    main()
