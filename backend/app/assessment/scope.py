from enum import Enum
from ipaddress import ip_address, ip_network


class AddressClassification(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"


def classify_ip_address(
    address: str,
) -> AddressClassification:
    parsed = ip_address(address)

    if parsed.is_loopback:
        return AddressClassification.LOOPBACK

    if parsed.is_link_local:
        return AddressClassification.LINK_LOCAL

    if parsed.is_multicast:
        return AddressClassification.MULTICAST

    if parsed.is_unspecified:
        return AddressClassification.UNSPECIFIED

    if parsed.is_private:
        return AddressClassification.PRIVATE

    if parsed.is_reserved:
        return AddressClassification.RESERVED

    return AddressClassification.PUBLIC


def validate_resolved_addresses(
    addresses: list[str],
    *,
    allow_private: bool = False,
) -> None:
    for address in addresses:
        classification = classify_ip_address(address)

        if classification == AddressClassification.PUBLIC:
            continue

        if (
            allow_private
            and classification == AddressClassification.PRIVATE
        ):
            continue

        raise ValueError(
            f"Resolved address {address} belongs to blocked "
            f"address class {classification.value}."
        )


def _normalize_hostname(
    hostname: str,
) -> str:
    return hostname.strip().rstrip(".").lower()


def host_is_within_exact_fqdn(
    host: str,
    authorized_host: str,
) -> bool:
    return (
        _normalize_hostname(host)
        == _normalize_hostname(authorized_host)
    )


def address_is_within_infrastructure_scope(
    address: str,
    *,
    authorized_ips: tuple[str, ...] | list[str] = (),
    authorized_cidrs: tuple[str, ...] | list[str] = (),
) -> bool:
    """Return whether a literal address is inside an exact IP/CIDR scope."""

    try:
        candidate = ip_address(address.strip())
    except (AttributeError, ValueError):
        return False

    for value in authorized_ips:
        try:
            if candidate == ip_address(value.strip()):
                return True
        except (AttributeError, ValueError):
            continue

    for value in authorized_cidrs:
        try:
            network = ip_network(value.strip(), strict=False)
        except (AttributeError, ValueError):
            continue

        if candidate.version == network.version and candidate in network:
            return True

    return False


# Descriptive alias for callers that prefer predicate naming.
is_address_in_authorized_scope = address_is_within_infrastructure_scope


def validate_infrastructure_address_scope(
    addresses: tuple[str, ...] | list[str],
    *,
    authorized_ips: tuple[str, ...] | list[str] = (),
    authorized_cidrs: tuple[str, ...] | list[str] = (),
    allow_private: bool = False,
) -> None:
    """Validate destination classes and exact IP/CIDR membership."""

    if not authorized_ips and not authorized_cidrs:
        raise ValueError(
            "Infrastructure scope requires an explicit IP address or CIDR."
        )

    normalized = [value.strip() for value in addresses]
    validate_resolved_addresses(
        normalized,
        allow_private=allow_private,
    )

    for address in normalized:
        if not address_is_within_infrastructure_scope(
            address,
            authorized_ips=authorized_ips,
            authorized_cidrs=authorized_cidrs,
        ):
            raise ValueError(
                f"Address {address} is outside the authorized infrastructure scope."
            )
