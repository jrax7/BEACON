from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveredService:
    """One network service discovered within authorized scope."""

    host: str
    ip: str
    port: int
    transport: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    tls_hint: bool = False
    state: str = "open"


@dataclass(frozen=True)
class ServiceInventory:
    """Typed network-service handoff produced by discovery."""

    services: tuple[DiscoveredService, ...] = ()


@dataclass(frozen=True)
class HTTPService:
    """One reachable HTTP service derived from service discovery."""

    url: str
    host: str
    port: int
    scheme: str
    status_code: int | None = None
    title: str | None = None
    effective_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    server: str | None = None
    technology_hints: tuple[str, ...] = ()
    content_type: str | None = None


@dataclass(frozen=True)
class HTTPServiceInventory:
    """Typed HTTP-service handoff."""

    services: tuple[HTTPService, ...] = ()


@dataclass(frozen=True)
class WebEndpoint:
    """One discovered web endpoint within assessment scope."""

    url: str
    method: str
    parameter_names: tuple[str, ...] = ()
    source_url: str | None = None
    discovery_method: str | None = None


@dataclass(frozen=True)
class WebEndpointInventory:
    """Typed web-endpoint discovery handoff."""

    endpoints: tuple[WebEndpoint, ...] = ()


@dataclass(frozen=True)
class TLSService:
    """One TLS-capable service selected for TLS assessment."""

    host: str
    ip: str
    port: int


@dataclass(frozen=True)
class TLSServiceInventory:
    """Typed TLS-service handoff."""

    services: tuple[TLSService, ...] = ()


@dataclass(frozen=True)
class VulnerabilityTargetSet:
    """Normalized targets supplied to vulnerability scanners."""

    network_services: tuple[DiscoveredService, ...] = ()
    http_services: tuple[HTTPService, ...] = ()
    web_endpoints: tuple[WebEndpoint, ...] = ()
    tls_services: tuple[TLSService, ...] = ()
