from ipaddress import (
    ip_address,
    ip_network,
)


def _trusted_networks(
    value: str,
):
    networks = []

    for item in value.split(","):
        candidate = item.strip()

        if not candidate:
            continue

        networks.append(
            ip_network(
                candidate,
                strict=False,
            )
        )

    return tuple(networks)


def trusted_client_ip(
    request,
    settings,
) -> str:
    """Resolve forwarded client IP only through configured proxies."""

    client = getattr(
        request,
        "client",
        None,
    )

    peer_text = str(
        getattr(
            client,
            "host",
            "",
        )
        or "unknown"
    )

    try:
        peer = ip_address(
            peer_text
        )
    except ValueError:
        return peer_text

    networks = _trusted_networks(
        settings.trusted_proxy_cidrs
    )

    if not any(
        peer in network
        for network in networks
    ):
        return str(
            peer
        )

    header_name = (
        settings.client_ip_header
        .strip()
        .lower()
    )

    if not header_name:
        return str(
            peer
        )

    forwarded = request.headers.get(
        header_name
    )

    if not forwarded:
        return str(
            peer
        )

    candidate = (
        forwarded
        .split(",", 1)[0]
        .strip()
    )

    try:
        return str(
            ip_address(
                candidate
            )
        )
    except ValueError:
        return str(
            peer
        )
