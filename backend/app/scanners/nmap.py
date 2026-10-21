from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
import os
import subprocess

from defusedxml import ElementTree
from xml.etree.ElementTree import Element

from app.assessment.handoff import (
    DiscoveredService,
    ServiceInventory,
)
from app.config import settings


class NmapScannerError(RuntimeError):
    """Raised when the constrained Nmap scan fails."""


@dataclass(frozen=True)
class NmapPortResult:
    """One open TCP service reported by Nmap."""

    address: str | None
    hostname: str
    protocol: str
    port: int
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    tunnel: str | None
    detection_method: str | None
    detection_confidence: int | None


@dataclass(frozen=True)
class NmapScanResult:
    """Parsed result of BEACON's constrained Nmap profile."""

    scanner_version: str
    command_summary: str
    raw_xml: bytes
    open_ports: list[NmapPortResult]


@dataclass(frozen=True)
class NmapDiscoveryResult:
    """Engine v2 Nmap discovery result."""

    scanner_version: str
    command_summary: str
    raw_xml: bytes
    service_inventory: ServiceInventory


def configured_nmap_ports() -> list[int]:
    """Return validated Nmap ports from BEACON configuration."""

    ports: set[int] = set()

    for value in settings.nmap_allowed_ports.split(","):
        value = value.strip()

        if not value:
            continue

        try:
            port = int(value)
        except ValueError as exc:
            raise NmapScannerError(
                "NMAP_ALLOWED_PORTS contains a non-numeric value."
            ) from exc

        if port < 1 or port > 65535:
            raise NmapScannerError(
                f"Nmap port {port} is outside the valid range."
            )

        ports.add(port)

    if not ports:
        raise NmapScannerError(
            "No Nmap ports have been configured."
        )

    return sorted(ports)


def optional_attribute(
    element: Element | None,
    attribute: str,
) -> str | None:
    """Return a non-empty XML attribute or None."""

    if element is None:
        return None

    value = element.attrib.get(attribute)

    if value is None:
        return None

    value = value.strip()

    return value or None


def integer_attribute(
    element: Element | None,
    attribute: str,
) -> int | None:
    """Return an integer XML attribute when available."""

    value = optional_attribute(
        element,
        attribute,
    )

    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def parse_nmap_xml(
    raw_xml: bytes,
    requested_hostname: str,
) -> tuple[str, list[NmapPortResult]]:
    """Parse locally generated Nmap XML output."""

    try:
        root = ElementTree.fromstring(raw_xml)
    except ElementTree.ParseError as exc:
        raise NmapScannerError(
            "Nmap returned invalid XML output."
        ) from exc

    scanner_version = (
        root.attrib.get("version", "").strip()
        or "unknown"
    )

    open_ports: list[NmapPortResult] = []

    for host_element in root.findall("host"):
        address_element = host_element.find("address")
        address = optional_attribute(
            address_element,
            "addr",
        )

        hostname_element = host_element.find(
            "hostnames/hostname"
        )

        reported_hostname = optional_attribute(
            hostname_element,
            "name",
        ) or requested_hostname

        for port_element in host_element.findall(
            "ports/port"
        ):
            state_element = port_element.find("state")

            state = optional_attribute(
                state_element,
                "state",
            ) or "unknown"

            if state != "open":
                continue

            protocol = (
                port_element.attrib.get(
                    "protocol",
                    "tcp",
                )
                .strip()
                .lower()
            )

            try:
                port_number = int(
                    port_element.attrib["portid"]
                )
            except (KeyError, ValueError) as exc:
                raise NmapScannerError(
                    "Nmap returned an invalid port identifier."
                ) from exc

            service_element = port_element.find(
                "service"
            )

            open_ports.append(
                NmapPortResult(
                    address=address,
                    hostname=reported_hostname,
                    protocol=protocol,
                    port=port_number,
                    state=state,
                    service_name=optional_attribute(
                        service_element,
                        "name",
                    ),
                    product=optional_attribute(
                        service_element,
                        "product",
                    ),
                    version=optional_attribute(
                        service_element,
                        "version",
                    ),
                    extra_info=optional_attribute(
                        service_element,
                        "extrainfo",
                    ),
                    tunnel=optional_attribute(
                        service_element,
                        "tunnel",
                    ),
                    detection_method=optional_attribute(
                        service_element,
                        "method",
                    ),
                    detection_confidence=integer_attribute(
                        service_element,
                        "conf",
                    ),
                )
            )

    return scanner_version, open_ports


def parse_nmap_service_inventory(
    raw_xml: bytes,
    requested_hostname: str,
) -> tuple[str, ServiceInventory]:
    """Convert Nmap XML into the Engine v2 service handoff."""

    scanner_version, open_ports = parse_nmap_xml(
        raw_xml,
        requested_hostname=requested_hostname,
    )

    services: list[DiscoveredService] = []

    for port in open_ports:
        if port.address is None:
            raise NmapScannerError(
                "Nmap returned an open service without "
                "a resolved address."
            )

        service_name = (
            port.service_name.lower()
            if port.service_name
            else None
        )

        tunnel = (
            port.tunnel.lower()
            if port.tunnel
            else None
        )

        tls_hint = (
            tunnel in {
                "ssl",
                "tls",
            }
            or service_name in {
                "https",
                "ssl",
                "tls",
            }
        )

        services.append(
            DiscoveredService(
                host=port.hostname,
                ip=port.address,
                port=port.port,
                transport=port.protocol,
                service=port.service_name,
                product=port.product,
                version=port.version,
                tls_hint=tls_hint,
                state=port.state,
            )
        )

    return (
        scanner_version,
        ServiceInventory(
            services=tuple(services),
        ),
    )


def _validated_explicit_ports(
    ports: tuple[int, ...],
) -> tuple[int, ...]:
    """Validate bounded Engine v2 explicit-port discovery."""

    if not ports:
        raise NmapScannerError(
            "Normal Nmap discovery requires explicit ports."
        )

    validated: set[int] = set()

    for port in ports:
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or port < 1
            or port > 65535
        ):
            raise NmapScannerError(
                f"Nmap port {port} is outside the valid range."
            )

        validated.add(port)

    maximum = settings.nmap_max_explicit_ports

    if maximum < 1:
        raise NmapScannerError(
            "NMAP_MAX_EXPLICIT_PORTS must be positive."
        )

    if len(validated) > maximum:
        raise NmapScannerError(
            "Nmap normal discovery received too many "
            "explicit ports."
        )

    return tuple(sorted(validated))


def _validate_full_tcp_target(
    target: str,
) -> None:
    """Require a literal IP address or CIDR for full TCP mode."""

    candidate = target.strip()

    try:
        if "/" in candidate:
            ip_network(
                candidate,
                strict=False,
            )
        else:
            ip_address(candidate)
    except ValueError as exc:
        raise NmapScannerError(
            "Full TCP discovery requires a literal "
            "IP address or CIDR."
        ) from exc


def run_nmap_discovery(
    *,
    target: str,
    ports: tuple[int, ...],
    full_tcp: bool,
    timeout_seconds: int,
) -> NmapDiscoveryResult:
    """Run Engine v2 Nmap discovery under an explicit port policy."""

    if timeout_seconds <= 0:
        raise NmapScannerError(
            "Nmap timeout must be positive."
        )

    if full_tcp:
        if ports:
            raise NmapScannerError(
                "Full TCP discovery must not include "
                "explicit ports."
            )

        _validate_full_tcp_target(
            target
        )

        port_argument = "1-65535"
    else:
        validated_ports = (
            _validated_explicit_ports(
                ports
            )
        )

        port_argument = ",".join(
            str(port)
            for port in validated_ports
        )

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "--open",
        "--noninteractive",
        "-p",
        port_argument,
        "-oX",
        "-",
        "--",
        target,
    ]

    environment = {
        **os.environ,
        "LC_ALL": "C",
        "LANG": "C",
    }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise NmapScannerError(
            "The Nmap executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapScannerError(
            "The Nmap scan exceeded its configured timeout."
        ) from exc

    if result.returncode != 0:
        error_message = result.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise NmapScannerError(
            "Nmap exited unsuccessfully"
            + (
                f": {error_message[:1000]}"
                if error_message
                else "."
            )
        )

    scanner_version, service_inventory = (
        parse_nmap_service_inventory(
            result.stdout,
            requested_hostname=target,
        )
    )

    if full_tcp:
        command_summary = (
            "TCP connect and light service detection "
            "on ports 1-65535"
        )
    else:
        command_summary = (
            "TCP connect and light service detection "
            f"on ports {port_argument}"
        )

    return NmapDiscoveryResult(
        scanner_version=scanner_version,
        command_summary=command_summary,
        raw_xml=result.stdout,
        service_inventory=service_inventory,
    )


def run_nmap_web_discovery(
    hostname: str,
) -> NmapScanResult:
    """Run a fixed, non-root web-service discovery profile."""

    ports = configured_nmap_ports()
    port_argument = ",".join(
        str(port)
        for port in ports
    )

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "--open",
        "--noninteractive",
        "-p",
        port_argument,
        "-oX",
        "-",
        "--",
        hostname,
    ]

    environment = {
        **os.environ,
        "LC_ALL": "C",
        "LANG": "C",
    }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=settings.nmap_timeout_seconds,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise NmapScannerError(
            "The Nmap executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapScannerError(
            "The Nmap scan exceeded its configured timeout."
        ) from exc

    if result.returncode != 0:
        error_message = result.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise NmapScannerError(
            "Nmap exited unsuccessfully"
            + (
                f": {error_message[:1000]}"
                if error_message
                else "."
            )
        )

    scanner_version, open_ports = parse_nmap_xml(
        result.stdout,
        requested_hostname=hostname,
    )

    return NmapScanResult(
        scanner_version=scanner_version,
        command_summary=(
            "TCP connect and light service detection "
            f"on ports {port_argument}"
        ),
        raw_xml=result.stdout,
        open_ports=open_ports,
    )


def store_nmap_xml(
    scan_id: str,
    raw_xml: bytes,
) -> str:
    """Store raw XML and return its relative path."""

    root = Path(
        settings.raw_storage_path
    ).resolve()

    scan_directory = (
        root / scan_id
    ).resolve()

    if (
        scan_directory != root
        and root not in scan_directory.parents
    ):
        raise NmapScannerError(
            "The raw-output path is outside its storage root."
        )

    scan_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination = scan_directory / "nmap.xml"
    temporary = scan_directory / "nmap.xml.tmp"

    temporary.write_bytes(raw_xml)
    temporary.chmod(0o600)
    temporary.replace(destination)

    return f"{scan_id}/nmap.xml"
