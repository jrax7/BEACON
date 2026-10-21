from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
from ipaddress import ip_address, ip_network

from app.assessment.profiles import (
    get_assessment_profile,
)


@dataclass(frozen=True)
class ActiveAuthorizationConfirmation:
    confirmed: bool
    confirmed_by_user_id: int | UUID
    confirmed_at: datetime
    authorization_version: str


@dataclass(frozen=True)
class InfrastructureScopeAuthorization:
    authorized_ips: tuple[str, ...]
    authorized_cidrs: tuple[str, ...]

    broad_port_scan_allowed: bool
    network_active_checks_allowed: bool

    third_party_infrastructure_attested_excluded: bool


def validate_active_authorization(
    *,
    profile_name: str,
    confirmation: ActiveAuthorizationConfirmation | None,
) -> None:
    profile = get_assessment_profile(profile_name)

    if not profile.active_web_testing:
        return

    if confirmation is None or not confirmation.confirmed:
        raise ValueError(
            "This profile requires active testing authorization."
        )

    user_id = confirmation.confirmed_by_user_id

    if isinstance(user_id, bool):
        valid_user_id = False
    elif isinstance(user_id, int):
        valid_user_id = user_id > 0
    elif isinstance(user_id, UUID):
        valid_user_id = user_id.int != 0
    else:
        valid_user_id = False

    if not valid_user_id:
        raise ValueError(
            "Active testing authorization requires a valid user."
        )

    if not confirmation.authorization_version.strip():
        raise ValueError(
            "Active testing authorization version is required."
        )


def _address_is_authorized(
    address: str,
    authorization: InfrastructureScopeAuthorization,
) -> bool:
    candidate = ip_address(address)

    authorized_ips = {
        ip_address(value)
        for value in authorization.authorized_ips
    }

    if candidate in authorized_ips:
        return True

    for value in authorization.authorized_cidrs:
        network = ip_network(
            value,
            strict=False,
        )

        if candidate.version != network.version:
            continue

        if candidate in network:
            return True

    return False


def validate_infrastructure_authorization(
    *,
    profile_name: str,
    authorization: InfrastructureScopeAuthorization | None,
    requested_addresses: tuple[str, ...],
) -> None:
    profile = get_assessment_profile(profile_name)

    if not profile.infrastructure_extension_allowed:
        raise ValueError(
            "Infrastructure Extension is available only with "
            "the Deep assessment profile."
        )

    if authorization is None:
        raise ValueError(
            "Deep Infrastructure Extension requires separate "
            "infrastructure authorization."
        )

    if (
        not authorization.authorized_ips
        and not authorization.authorized_cidrs
    ):
        raise ValueError(
            "Infrastructure authorization requires an explicit "
            "IP address or CIDR."
        )

    if not authorization.broad_port_scan_allowed:
        raise ValueError(
            "Infrastructure authorization must explicitly allow "
            "a broad port scan."
        )

    if not authorization.network_active_checks_allowed:
        raise ValueError(
            "Infrastructure authorization must explicitly allow "
            "network active checks."
        )

    if not authorization.third_party_infrastructure_attested_excluded:
        raise ValueError(
            "Infrastructure authorization requires confirmation "
            "that unauthorized third-party infrastructure is excluded."
        )

    for requested_address in requested_addresses:
        if not _address_is_authorized(
            requested_address,
            authorization,
        ):
            raise ValueError(
                f"Requested address {requested_address} is outside "
                "authorized infrastructure scope."
            )


@dataclass(frozen=True)
class InfrastructureRiskDecision:
    """Fail-closed decision for a separately authorized infrastructure target."""

    allowed: bool
    reason: str
    provider: str | None = None
    shared_infrastructure_detected: bool = False


def evaluate_infrastructure_risk(
    *,
    authorization: InfrastructureScopeAuthorization | None,
    requested_addresses: tuple[str, ...],
    shared_infrastructure_detected: bool,
    provider: str | None = None,
) -> InfrastructureRiskDecision:
    """Evaluate exact scope, consent, and shared-provider risk signals."""

    normalized_provider = (
        provider.strip()
        if isinstance(provider, str) and provider.strip()
        else None
    )
    provider_suffix = (
        f" ({normalized_provider})"
        if normalized_provider
        else ""
    )
    addresses = tuple(
        value.strip()
        for value in requested_addresses
        if isinstance(value, str) and value.strip()
    )

    if not addresses:
        return InfrastructureRiskDecision(
            allowed=False,
            reason="Infrastructure risk evaluation requires target addresses.",
            provider=normalized_provider,
            shared_infrastructure_detected=bool(
                shared_infrastructure_detected
            ),
        )

    if authorization is None:
        return InfrastructureRiskDecision(
            allowed=False,
            reason=(
                "Infrastructure testing is blocked: separate exact "
                "IP/CIDR authorization is missing."
            ),
            provider=normalized_provider,
            shared_infrastructure_detected=bool(
                shared_infrastructure_detected
            ),
        )

    if shared_infrastructure_detected and not (
        authorization.authorized_ips or authorization.authorized_cidrs
    ):
        return InfrastructureRiskDecision(
            allowed=False,
            reason=(
                "Shared/CDN infrastructure"
                f"{provider_suffix} is blocked without exact "
                "IP/CIDR authorization."
            ),
            provider=normalized_provider,
            shared_infrastructure_detected=True,
        )

    try:
        validate_infrastructure_authorization(
            profile_name="deep",
            authorization=authorization,
            requested_addresses=addresses,
        )
    except (TypeError, ValueError) as exc:
        reason = str(exc) or "Infrastructure authorization was rejected."
        if shared_infrastructure_detected and "shared" not in reason.lower():
            reason = (
                "Shared/CDN infrastructure"
                f"{provider_suffix} is blocked: {reason}"
            )

        return InfrastructureRiskDecision(
            allowed=False,
            reason=reason,
            provider=normalized_provider,
            shared_infrastructure_detected=bool(
                shared_infrastructure_detected
            ),
        )

    if shared_infrastructure_detected:
        reason = (
            "Shared/CDN infrastructure"
            f"{provider_suffix} is explicitly authorized by exact scope."
        )
    else:
        reason = "Infrastructure target is explicitly authorized by exact scope."

    return InfrastructureRiskDecision(
        allowed=True,
        reason=reason,
        provider=normalized_provider,
        shared_infrastructure_detected=False,
    )
