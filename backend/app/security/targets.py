from dataclasses import dataclass
from hashlib import sha256
import hmac
from ipaddress import ip_address
import secrets
import socket
from urllib.parse import urlsplit, urlunsplit

import dns.exception
import dns.resolver
import httpx

from app.config import settings


class TargetValidationError(ValueError):
    """Raised when a submitted target is unsafe or invalid."""


class OwnershipVerificationError(ValueError):
    """Raised when ownership verification cannot be completed."""


@dataclass(frozen=True)
class NormalizedTarget:
    """Validated and normalized target components."""

    original_url: str
    normalized_url: str
    hostname: str
    scheme: str
    port: int
    origin: str


def allowed_target_ports() -> set[int]:
    """Return the configured set of allowed web ports."""

    ports: set[int] = set()

    for value in settings.target_allowed_ports.split(","):
        value = value.strip()

        if value:
            ports.add(int(value))

    return ports


def allowed_lab_hostnames() -> set[str]:
    """Return explicitly configured development-lab hostnames."""

    return {
        hostname.strip().lower()
        for hostname in settings.lab_allowed_hosts.split(",")
        if hostname.strip()
    }


def is_allowed_lab_target(hostname: str) -> bool:
    """Check whether a hostname is an explicit development exception."""

    return (
        settings.environment.lower() == "development"
        and settings.allow_lab_targets
        and hostname.lower() in allowed_lab_hostnames()
    )


def normalize_target_url(raw_url: str) -> NormalizedTarget:
    """Normalize a user-submitted HTTP or HTTPS target."""

    original_url = raw_url.strip()

    if not original_url:
        raise TargetValidationError("The target URL cannot be empty.")

    try:
        parsed = urlsplit(original_url)
        explicit_port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(
            "The target URL contains an invalid port."
        ) from exc

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise TargetValidationError(
            "Only http:// and https:// targets are supported."
        )

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "Credentials must not be included inside the target URL."
        )

    if parsed.query:
        raise TargetValidationError(
            "Query strings are not permitted in registered target URLs."
        )

    if parsed.fragment:
        raise TargetValidationError(
            "URL fragments are not permitted in registered target URLs."
        )

    if parsed.hostname is None:
        raise TargetValidationError(
            "The target URL must include a hostname."
        )

    try:
        hostname = (
            parsed.hostname
            .rstrip(".")
            .encode("idna")
            .decode("ascii")
            .lower()
        )
    except UnicodeError as exc:
        raise TargetValidationError(
            "The target hostname is not valid."
        ) from exc

    if not hostname:
        raise TargetValidationError(
            "The target hostname cannot be empty."
        )

    default_port = 443 if scheme == "https" else 80
    port = explicit_port or default_port

    if port not in allowed_target_ports():
        raise TargetValidationError(
            f"Port {port} is not permitted. "
            f"Allowed ports: {sorted(allowed_target_ports())}."
        )

    display_hostname = (
        f"[{hostname}]"
        if ":" in hostname
        else hostname
    )

    netloc = display_hostname

    if port != default_port:
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    normalized_path = path.rstrip("/") or "/"

    normalized_url = urlunsplit(
        (
            scheme,
            netloc,
            normalized_path,
            "",
            "",
        )
    )

    origin = urlunsplit(
        (
            scheme,
            netloc,
            "",
            "",
            "",
        )
    )

    return NormalizedTarget(
        original_url=original_url,
        normalized_url=normalized_url,
        hostname=hostname,
        scheme=scheme,
        port=port,
        origin=origin,
    )


def resolve_target_addresses(
    hostname: str,
    port: int,
) -> list[str]:
    """Resolve a target and return all unique IP addresses."""

    try:
        literal_address = ip_address(hostname)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        return [str(literal_address)]

    try:
        address_information = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise TargetValidationError(
            "The target hostname could not be resolved."
        ) from exc

    addresses = sorted(
        {
            item[4][0]
            for item in address_information
        }
    )

    if not addresses:
        raise TargetValidationError(
            "The target hostname did not resolve to an IP address."
        )

    return addresses


def validate_target_destination(
    target: NormalizedTarget,
) -> list[str]:
    """Reject unsafe network destinations."""

    if is_allowed_lab_target(target.hostname):
        return resolve_target_addresses(
            target.hostname,
            target.port,
        )

    try:
        ip_address(target.hostname)
        hostname_is_ip_literal = True
    except ValueError:
        hostname_is_ip_literal = False

    if not hostname_is_ip_literal and "." not in target.hostname:
        raise TargetValidationError(
            "Single-label hostnames are not permitted."
        )

    addresses = resolve_target_addresses(
        target.hostname,
        target.port,
    )

    for address_text in addresses:
        address = ip_address(address_text)

        if not address.is_global:
            raise TargetValidationError(
                "The target resolves to a private, local, reserved, "
                "or otherwise non-public IP address."
            )

    return addresses


def generate_verification_value() -> tuple[str, str]:
    """Generate a verification value and its SHA-256 hash."""

    random_token = secrets.token_urlsafe(32)
    verification_value = f"beacon-verification={random_token}"

    return (
        verification_value,
        hash_verification_value(verification_value),
    )


def hash_verification_value(value: str) -> str:
    """Return a SHA-256 hash for a verification value."""

    return sha256(
        value.strip().encode("utf-8")
    ).hexdigest()


def verification_value_matches(
    candidate_value: str,
    expected_hash: str,
) -> bool:
    """Compare a candidate value with a stored token hash."""

    candidate_hash = hash_verification_value(
        candidate_value,
    )

    return hmac.compare_digest(
        candidate_hash,
        expected_hash,
    )


def build_file_verification_url(
    target: NormalizedTarget,
) -> str:
    """Return the target's ownership-verification file URL."""

    return (
        f"{target.origin}"
        "/.well-known/beacon-verification.txt"
    )


def build_dns_verification_record(hostname: str) -> str:
    """Return the required TXT-record name."""

    try:
        ip_address(hostname)
    except ValueError:
        return f"_beacon-verification.{hostname}"

    raise TargetValidationError(
        "DNS verification cannot be used with a raw IP address."
    )


def verify_file_ownership(
    normalized_url: str,
    expected_hash: str,
) -> str:
    """Fetch and validate the target's verification file."""

    target = normalize_target_url(normalized_url)

    # Revalidate immediately before the outbound request.
    validate_target_destination(target)

    verification_url = build_file_verification_url(
        target,
    )

    timeout = httpx.Timeout(
        settings.target_request_timeout_seconds,
    )

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent":
                    "BEACON-Ownership-Verification/0.1",
                "Accept": "text/plain",
            },
        ) as client:
            with client.stream(
                "GET",
                verification_url,
            ) as response:
                if response.is_redirect:
                    raise OwnershipVerificationError(
                        "Verification redirects are not permitted."
                    )

                if response.status_code != 200:
                    raise OwnershipVerificationError(
                        "The verification file returned "
                        f"HTTP status {response.status_code}."
                    )

                content = bytearray()

                for chunk in response.iter_bytes():
                    content.extend(chunk)

                    if (
                        len(content)
                        > settings.verification_file_max_bytes
                    ):
                        raise OwnershipVerificationError(
                            "The verification file is too large."
                        )

    except OwnershipVerificationError:
        raise
    except httpx.HTTPError as exc:
        raise OwnershipVerificationError(
            "BEACON could not retrieve the verification file."
        ) from exc

    try:
        verification_value = bytes(content).decode(
            "utf-8"
        ).strip()
    except UnicodeDecodeError as exc:
        raise OwnershipVerificationError(
            "The verification file is not valid UTF-8 text."
        ) from exc

    if not verification_value_matches(
        verification_value,
        expected_hash,
    ):
        raise OwnershipVerificationError(
            "The verification file does not contain "
            "the expected BEACON value."
        )

    return verification_url


def verify_dns_ownership(
    hostname: str,
    expected_hash: str,
) -> str:
    """Query and validate the target's DNS TXT record."""

    record_name = build_dns_verification_record(
        hostname,
    )

    resolver = dns.resolver.Resolver()
    resolver.timeout = min(
        3.0,
        settings.target_request_timeout_seconds,
    )
    resolver.lifetime = settings.target_request_timeout_seconds

    try:
        answers = resolver.resolve(
            record_name,
            "TXT",
            lifetime=settings.target_request_timeout_seconds,
        )
    except dns.exception.DNSException as exc:
        raise OwnershipVerificationError(
            "The required DNS TXT record could not be retrieved."
        ) from exc

    discovered_values: list[str] = []

    for answer in answers:
        value = "".join(
            part.decode("utf-8")
            for part in answer.strings
        )

        discovered_values.append(value)

        if verification_value_matches(
            value,
            expected_hash,
        ):
            return record_name

    raise OwnershipVerificationError(
        "The DNS TXT record does not contain "
        "the expected BEACON value."
    )
