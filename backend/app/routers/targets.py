from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_database_session
from app.dependencies.auth import CurrentUser
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.organizations.context import resolve_organization_context
from app.organizations.rbac import Permission, require_permission
from app.schemas.targets import (
    TargetCreate,
    TargetCreateResponse,
    TargetResponse,
    TargetVerificationResponse,
    VerificationTokenResponse,
)
from app.security.demo import (
    configured_demo_hostname,
    ensure_demo_mutation_allowed,
    ensure_demo_target_allowed,
    is_demo_user,
)
from app.security.targets import (
    OwnershipVerificationError,
    TargetValidationError,
    build_dns_verification_record,
    build_file_verification_url,
    generate_verification_value,
    normalize_target_url,
    validate_target_destination,
    verify_dns_ownership,
    verify_file_ownership,
)


router = APIRouter(
    prefix="/api/v1/targets",
    tags=["Targets"],
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


def get_owned_target(
    target_id: UUID,
    current_user: User,
    database: Session,
) -> Target:
    """Return a target only when it belongs to the current user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_READ,
    )

    target = database.scalar(
        select(Target).where(
            Target.id == target_id,
            Target.organization_id == context.organization.id,
        )
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    ensure_demo_target_allowed(
        current_user,
        target,
    )

    return target


def verification_location(
    normalized_url: str,
    hostname: str,
    method: str,
) -> str:
    """Return the required verification destination."""

    normalized_target = normalize_target_url(
        normalized_url,
    )

    if method == "file":
        return build_file_verification_url(
            normalized_target,
        )

    return build_dns_verification_record(
        hostname,
    )


def verification_instructions(
    method: str,
    location: str,
) -> str:
    """Return user-facing ownership instructions."""

    if method == "file":
        return (
            "Create a UTF-8 text file at the displayed URL. "
            "The file must contain only the provided "
            "verification value."
        )

    return (
        "Create a DNS TXT record using the displayed record "
        "name and the provided verification value."
    )


def record_audit_event(
    database: Session,
    current_user: User,
    action: str,
    target_id: UUID | None = None,
    details: dict | None = None,
) -> None:
    """Add a security-relevant action to the audit log."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    database.add(
        AuditLog(
            organization_id=context.organization.id,
            user_id=current_user.id,
            target_id=target_id,
            action=action,
            details=details,
        )
    )


@router.post(
    "",
    response_model=TargetCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    request: TargetCreate,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> TargetCreateResponse:
    """Register a target and create an ownership token."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_CREATE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    try:
        normalized_target = normalize_target_url(
            request.url,
        )

        resolved_addresses = validate_target_destination(
            normalized_target,
        )
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    existing_target = database.scalar(
        select(Target).where(
            Target.organization_id == context.organization.id,
            Target.hostname == normalized_target.hostname,
        )
    )

    if existing_target is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This hostname is already registered to "
                "your BEACON account."
            ),
        )

    value, value_hash = generate_verification_value()

    target = Target(
        organization_id=context.organization.id,
        user_id=current_user.id,
        original_url=normalized_target.original_url,
        normalized_url=normalized_target.normalized_url,
        hostname=normalized_target.hostname,
        verification_method=request.verification_method,
        verification_token_hash=value_hash,
        verification_status="pending",
    )

    database.add(target)
    database.flush()

    record_audit_event(
        database=database,
        current_user=current_user,
        target_id=target.id,
        action="target.created",
        details={
            "hostname": target.hostname,
            "verification_method":
                request.verification_method,
            "resolved_addresses":
                resolved_addresses,
        },
    )

    try:
        database.commit()
    except IntegrityError as exc:
        database.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This hostname is already registered.",
        ) from exc

    database.refresh(target)

    location = verification_location(
        target.normalized_url,
        target.hostname,
        request.verification_method,
    )

    safe_target = TargetResponse.model_validate(
        target
    ).model_dump()

    return TargetCreateResponse(
        **safe_target,
        verification_value=value,
        verification_location=location,
        instructions=verification_instructions(
            request.verification_method,
            location,
        ),
    )


@router.get(
    "",
    response_model=list[TargetResponse],
)
def list_targets(
    current_user: CurrentUser,
    database: DatabaseSession,
) -> list[Target]:
    """List targets belonging to the current user."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_READ,
    )

    targets = list(
        database.scalars(
            select(Target)
            .where(
                Target.organization_id == context.organization.id,
            )
            .order_by(
                Target.created_at.desc(),
            )
        ).all()
    )

    if is_demo_user(current_user):
        targets = [
            target
            for target in targets
            if target.hostname == configured_demo_hostname()
        ]

    return targets


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
)
def read_target(
    target_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Target:
    """Return one target belonging to the current user."""

    return get_owned_target(
        target_id,
        current_user,
        database,
    )


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_target(
    target_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> Response:
    """Delete an unused target while preserving scan history."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_DELETE,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    target = get_owned_target(
        target_id,
        current_user,
        database,
    )

    existing_scan_id = database.scalar(
        select(Scan.id)
        .where(
            Scan.target_id == target.id,
        )
        .limit(1)
    )

    if existing_scan_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This target has scan history and cannot be "
                "deleted. BEACON preserves completed and "
                "historical assessment data."
            ),
        )

    deleted_target_id = str(target.id)
    deleted_hostname = target.hostname

    record_audit_event(
        database=database,
        current_user=current_user,
        action="target.deleted",
        details={
            "target_id": deleted_target_id,
            "hostname": deleted_hostname,
            "verification_status":
                target.verification_status,
        },
    )

    database.delete(target)
    database.commit()

    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
    )


@router.post(
    "/{target_id}/verification-token",
    response_model=VerificationTokenResponse,
)
def regenerate_verification_token(
    target_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> VerificationTokenResponse:
    """Replace the target's current verification token."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_VERIFY,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    target = get_owned_target(
        target_id,
        current_user,
        database,
    )

    method = target.verification_method or "file"
    value, value_hash = generate_verification_value()

    target.verification_token_hash = value_hash
    target.verification_status = "pending"
    target.verified_at = None
    target.verification_expires_at = None

    record_audit_event(
        database=database,
        current_user=current_user,
        target_id=target.id,
        action="target.verification_token_regenerated",
        details={
            "verification_method": method,
        },
    )

    database.commit()

    location = verification_location(
        target.normalized_url,
        target.hostname,
        method,
    )

    return VerificationTokenResponse(
        target_id=target.id,
        verification_method=method,
        verification_value=value,
        verification_location=location,
        instructions=verification_instructions(
            method,
            location,
        ),
    )


@router.post(
    "/{target_id}/verify/file",
    response_model=TargetVerificationResponse,
)
def verify_target_file(
    target_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> TargetVerificationResponse:
    """Verify target ownership through a hosted text file."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_VERIFY,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    target = get_owned_target(
        target_id,
        current_user,
        database,
    )

    if target.verification_token_hash is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Generate a verification token first.",
        )

    try:
        checked_location = verify_file_ownership(
            target.normalized_url,
            target.verification_token_hash,
        )
    except (
        OwnershipVerificationError,
        TargetValidationError,
    ) as exc:
        record_audit_event(
            database=database,
            current_user=current_user,
            target_id=target.id,
            action="target.verification_failed",
            details={
                "method": "file",
                "reason": str(exc),
            },
        )

        database.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    verified_at = datetime.now(timezone.utc)
    expires_at = verified_at + timedelta(
        days=settings.target_verification_ttl_days,
    )

    target.verification_method = "file"
    target.verification_status = "verified"
    target.verified_at = verified_at
    target.verification_expires_at = expires_at

    record_audit_event(
        database=database,
        current_user=current_user,
        target_id=target.id,
        action="target.verification_success",
        details={
            "method": "file",
            "checked_location": checked_location,
        },
    )

    database.commit()

    return TargetVerificationResponse(
        target_id=target.id,
        hostname=target.hostname,
        verification_method="file",
        verification_status="verified",
        checked_location=checked_location,
        verified_at=verified_at,
        verification_expires_at=expires_at,
        message="Target ownership was verified successfully.",
    )


@router.post(
    "/{target_id}/verify/dns",
    response_model=TargetVerificationResponse,
)
def verify_target_dns(
    target_id: UUID,
    current_user: CurrentUser,
    database: DatabaseSession,
) -> TargetVerificationResponse:
    """Verify target ownership through a DNS TXT record."""

    context = resolve_organization_context(
        database,
        current_user,
    )

    require_permission(
        context,
        Permission.TARGET_VERIFY,
    )

    ensure_demo_mutation_allowed(
        current_user,
    )

    target = get_owned_target(
        target_id,
        current_user,
        database,
    )

    if target.verification_token_hash is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Generate a verification token first.",
        )

    try:
        checked_location = verify_dns_ownership(
            target.hostname,
            target.verification_token_hash,
        )
    except (
        OwnershipVerificationError,
        TargetValidationError,
    ) as exc:
        record_audit_event(
            database=database,
            current_user=current_user,
            target_id=target.id,
            action="target.verification_failed",
            details={
                "method": "dns",
                "reason": str(exc),
            },
        )

        database.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    verified_at = datetime.now(timezone.utc)
    expires_at = verified_at + timedelta(
        days=settings.target_verification_ttl_days,
    )

    target.verification_method = "dns"
    target.verification_status = "verified"
    target.verified_at = verified_at
    target.verification_expires_at = expires_at

    record_audit_event(
        database=database,
        current_user=current_user,
        target_id=target.id,
        action="target.verification_success",
        details={
            "method": "dns",
            "checked_location": checked_location,
        },
    )

    database.commit()

    return TargetVerificationResponse(
        target_id=target.id,
        hostname=target.hostname,
        verification_method="dns",
        verification_status="verified",
        checked_location=checked_location,
        verified_at=verified_at,
        verification_expires_at=expires_at,
        message="Target ownership was verified successfully.",
    )
