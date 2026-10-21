from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import importlib.metadata as package_metadata
import json
import os
import re
import subprocess

from app.assessment.handoff import (
    TLSServiceInventory,
)
from app.config import settings


class SslyzeScannerError(RuntimeError):
    """Raised when SSLyze cannot be used safely."""


@dataclass(frozen=True)
class SslyzeDetectionCandidate:
    """Scanner-neutral TLS detection candidate."""

    kind: str
    host: str
    ip: str
    port: int
    evidence_key: str
    evidence_value: str


@dataclass(frozen=True)
class SslyzeServerResult:
    """Normalized result for one authorized TLS service."""

    host: str
    ip: str
    port: int

    connectivity_status: str
    scan_status: str

    connectivity_error: str | None

    highest_tls_version_supported: str | None
    client_auth_requirement: str | None

    supported_protocols: tuple[str, ...]


@dataclass(frozen=True)
class SslyzeAssessmentResult:
    """Normalized SSLyze assessment output."""

    scanner_version: str
    raw_json: bytes
    servers: tuple[SslyzeServerResult, ...]
    detection_candidates: tuple[
        SslyzeDetectionCandidate,
        ...
    ]


_VERSION_PATTERN = re.compile(
    r"\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b"
)


_PROTOCOL_COMMANDS = (
    (
        "tls_1_0_cipher_suites",
        "TLS_1_0",
    ),
    (
        "tls_1_1_cipher_suites",
        "TLS_1_1",
    ),
    (
        "tls_1_2_cipher_suites",
        "TLS_1_2",
    ),
    (
        "tls_1_3_cipher_suites",
        "TLS_1_3",
    ),
)


def _optional_string(
    value: object,
) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _normalized_host(
    value: str,
) -> str:
    return value.strip().rstrip(".").lower()


def build_sslyze_targets(
    inventory: TLSServiceInventory,
) -> tuple[str, ...]:
    """Build SSLyze targets with the authorized IP pinned."""

    targets: list[str] = []
    seen: set[str] = set()

    for service in inventory.services:
        host = service.host.strip()

        if not host:
            raise SslyzeScannerError(
                "SSLyze TLS service contains an empty host."
            )

        if any(
            character in host
            for character in "\r\n\0{}"
        ):
            raise SslyzeScannerError(
                "SSLyze TLS service contains an invalid host."
            )

        if (
            service.port < 1
            or service.port > 65535
        ):
            raise SslyzeScannerError(
                f"SSLyze port {service.port} is outside "
                "the valid range."
            )

        raw_ip = service.ip.strip()

        try:
            parsed_ip = ip_address(
                raw_ip
            )
        except ValueError as exc:
            raise SslyzeScannerError(
                "SSLyze TLS service contains an invalid IP."
            ) from exc

        target = (
            f"{host}:{service.port}"
            f"{{{parsed_ip}}}"
        )

        if target in seen:
            continue

        seen.add(target)
        targets.append(target)

    return tuple(targets)


def _completed_result(
    scan_result: dict,
    key: str,
) -> dict | None:
    attempt = scan_result.get(
        key
    )

    if not isinstance(
        attempt,
        dict,
    ):
        return None

    if attempt.get("status") != "COMPLETED":
        return None

    result = attempt.get(
        "result"
    )

    if not isinstance(
        result,
        dict,
    ):
        return None

    return result


def _candidate(
    *,
    kind: str,
    host: str,
    ip: str,
    port: int,
    evidence_key: str,
    evidence_value: object,
) -> SslyzeDetectionCandidate:
    return SslyzeDetectionCandidate(
        kind=kind,
        host=host,
        ip=ip,
        port=port,
        evidence_key=evidence_key,
        evidence_value=str(
            evidence_value
        ),
    )


def _protocol_results(
    scan_result: dict,
    *,
    host: str,
    ip: str,
    port: int,
) -> tuple[
    tuple[str, ...],
    list[SslyzeDetectionCandidate],
]:
    supported: list[str] = []
    candidates: list[
        SslyzeDetectionCandidate
    ] = []

    for (
        command_name,
        protocol_name,
    ) in _PROTOCOL_COMMANDS:
        result = _completed_result(
            scan_result,
            command_name,
        )

        if result is None:
            continue

        if (
            result.get(
                "is_tls_version_supported"
            )
            is not True
        ):
            continue

        supported.append(
            protocol_name
        )

        if protocol_name in {
            "TLS_1_0",
            "TLS_1_1",
        }:
            candidates.append(
                _candidate(
                    kind="legacy_tls_protocol",
                    host=host,
                    ip=ip,
                    port=port,
                    evidence_key="protocol",
                    evidence_value=protocol_name,
                )
            )

    return (
        tuple(supported),
        candidates,
    )


def _known_vulnerability_candidates(
    scan_result: dict,
    *,
    host: str,
    ip: str,
    port: int,
) -> list[SslyzeDetectionCandidate]:
    candidates: list[
        SslyzeDetectionCandidate
    ] = []

    heartbleed = _completed_result(
        scan_result,
        "heartbleed",
    )

    if (
        heartbleed is not None
        and heartbleed.get(
            "is_vulnerable_to_heartbleed"
        )
        is True
    ):
        candidates.append(
            _candidate(
                kind="heartbleed",
                host=host,
                ip=ip,
                port=port,
                evidence_key=(
                    "is_vulnerable_to_heartbleed"
                ),
                evidence_value=True,
            )
        )

    ccs = _completed_result(
        scan_result,
        "openssl_ccs_injection",
    )

    if (
        ccs is not None
        and ccs.get(
            "is_vulnerable_to_ccs_injection"
        )
        is True
    ):
        candidates.append(
            _candidate(
                kind="openssl_ccs_injection",
                host=host,
                ip=ip,
                port=port,
                evidence_key=(
                    "is_vulnerable_to_ccs_injection"
                ),
                evidence_value=True,
            )
        )

    robot = _completed_result(
        scan_result,
        "robot",
    )

    if robot is not None:
        robot_result = _optional_string(
            robot.get(
                "robot_result"
            )
        )

        if robot_result in {
            "VULNERABLE_WEAK_ORACLE",
            "VULNERABLE_STRONG_ORACLE",
        }:
            candidates.append(
                _candidate(
                    kind="robot",
                    host=host,
                    ip=ip,
                    port=port,
                    evidence_key="robot_result",
                    evidence_value=robot_result,
                )
            )

    compression = _completed_result(
        scan_result,
        "tls_compression",
    )

    if (
        compression is not None
        and compression.get(
            "supports_compression"
        )
        is True
    ):
        candidates.append(
            _candidate(
                kind="tls_compression",
                host=host,
                ip=ip,
                port=port,
                evidence_key=(
                    "supports_compression"
                ),
                evidence_value=True,
            )
        )

    renegotiation = _completed_result(
        scan_result,
        "session_renegotiation",
    )

    if renegotiation is not None:
        if (
            renegotiation.get(
                "supports_secure_renegotiation"
            )
            is False
        ):
            candidates.append(
                _candidate(
                    kind="insecure_renegotiation",
                    host=host,
                    ip=ip,
                    port=port,
                    evidence_key=(
                        "supports_secure_renegotiation"
                    ),
                    evidence_value=False,
                )
            )

        if (
            renegotiation.get(
                "is_vulnerable_to_"
                "client_renegotiation_dos"
            )
            is True
        ):
            candidates.append(
                _candidate(
                    kind=(
                        "client_renegotiation_dos"
                    ),
                    host=host,
                    ip=ip,
                    port=port,
                    evidence_key=(
                        "is_vulnerable_to_"
                        "client_renegotiation_dos"
                    ),
                    evidence_value=True,
                )
            )

    return candidates


def _certificate_candidates(
    scan_result: dict,
    *,
    host: str,
    ip: str,
    port: int,
) -> list[SslyzeDetectionCandidate]:
    candidates: list[
        SslyzeDetectionCandidate
    ] = []

    certificate_info = _completed_result(
        scan_result,
        "certificate_info",
    )

    if certificate_info is None:
        return candidates

    deployments = certificate_info.get(
        "certificate_deployments"
    )

    if not isinstance(
        deployments,
        list,
    ):
        return candidates

    seen_errors: set[str] = set()

    for deployment in deployments:
        if not isinstance(
            deployment,
            dict,
        ):
            continue

        validation_results = deployment.get(
            "path_validation_results"
        )

        if not isinstance(
            validation_results,
            list,
        ):
            continue

        for validation in validation_results:
            if not isinstance(
                validation,
                dict,
            ):
                continue

            if (
                validation.get(
                    "was_validation_successful"
                )
                is not False
            ):
                continue

            error = (
                _optional_string(
                    validation.get(
                        "validation_error"
                    )
                )
                or "certificate path validation failed"
            )

            if error in seen_errors:
                continue

            seen_errors.add(
                error
            )

            candidates.append(
                _candidate(
                    kind=(
                        "certificate_path_validation"
                    ),
                    host=host,
                    ip=ip,
                    port=port,
                    evidence_key=(
                        "validation_error"
                    ),
                    evidence_value=error,
                )
            )

    return candidates


def parse_sslyze_json(
    raw_json: bytes,
    *,
    authorized_services: TLSServiceInventory,
    max_output_bytes: int,
) -> SslyzeAssessmentResult:
    """Parse bounded SSLyze JSON under exact service scope."""

    if max_output_bytes <= 0:
        raise SslyzeScannerError(
            "SSLyze output limit must be positive."
        )

    if len(raw_json) > max_output_bytes:
        raise SslyzeScannerError(
            "SSLyze output exceeded its configured "
            "output limit."
        )

    try:
        payload = json.loads(
            raw_json
        )
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise SslyzeScannerError(
            "SSLyze returned invalid JSON."
        ) from exc

    if not isinstance(
        payload,
        dict,
    ):
        raise SslyzeScannerError(
            "SSLyze output must be a JSON object."
        )

    server_scan_results = payload.get(
        "server_scan_results"
    )

    if not isinstance(
        server_scan_results,
        list,
    ):
        raise SslyzeScannerError(
            "SSLyze output is missing a valid "
            "server_scan_results array."
        )

    scanner_version = (
        _optional_string(
            payload.get(
                "sslyze_version"
            )
        )
        or "unknown"
    )

    authorized = {
        (
            _normalized_host(
                service.host
            ),
            service.ip.strip(),
            service.port,
        )
        for service in authorized_services.services
    }

    servers: list[
        SslyzeServerResult
    ] = []

    candidates: list[
        SslyzeDetectionCandidate
    ] = []

    for record in server_scan_results:
        if not isinstance(
            record,
            dict,
        ):
            continue

        location = record.get(
            "server_location"
        )

        if not isinstance(
            location,
            dict,
        ):
            continue

        host = _optional_string(
            location.get(
                "hostname"
            )
        )

        raw_ip = _optional_string(
            location.get(
                "ip_address"
            )
        )

        port_value = location.get(
            "port"
        )

        if (
            host is None
            or raw_ip is None
            or isinstance(
                port_value,
                bool,
            )
        ):
            continue

        try:
            port = int(
                port_value
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        identity = (
            _normalized_host(
                host
            ),
            raw_ip,
            port,
        )

        if identity not in authorized:
            continue

        connectivity_status = (
            _optional_string(
                record.get(
                    "connectivity_status"
                )
            )
            or "UNKNOWN"
        )

        scan_status = (
            _optional_string(
                record.get(
                    "scan_status"
                )
            )
            or "UNKNOWN"
        )

        connectivity_error = (
            _optional_string(
                record.get(
                    "connectivity_error_trace"
                )
            )
        )

        connectivity_result = record.get(
            "connectivity_result"
        )

        if isinstance(
            connectivity_result,
            dict,
        ):
            highest_tls_version = (
                _optional_string(
                    connectivity_result.get(
                        "highest_tls_version_supported"
                    )
                )
            )

            client_auth_requirement = (
                _optional_string(
                    connectivity_result.get(
                        "client_auth_requirement"
                    )
                )
            )
        else:
            highest_tls_version = None
            client_auth_requirement = None

        scan_result = record.get(
            "scan_result"
        )

        supported_protocols: tuple[
            str,
            ...
        ] = ()

        server_candidates: list[
            SslyzeDetectionCandidate
        ] = []

        if isinstance(
            scan_result,
            dict,
        ):
            (
                supported_protocols,
                protocol_candidates,
            ) = _protocol_results(
                scan_result,
                host=host,
                ip=raw_ip,
                port=port,
            )

            server_candidates.extend(
                protocol_candidates
            )

            server_candidates.extend(
                _known_vulnerability_candidates(
                    scan_result,
                    host=host,
                    ip=raw_ip,
                    port=port,
                )
            )

            server_candidates.extend(
                _certificate_candidates(
                    scan_result,
                    host=host,
                    ip=raw_ip,
                    port=port,
                )
            )

        servers.append(
            SslyzeServerResult(
                host=host,
                ip=raw_ip,
                port=port,
                connectivity_status=(
                    connectivity_status
                ),
                scan_status=scan_status,
                connectivity_error=(
                    connectivity_error
                ),
                highest_tls_version_supported=(
                    highest_tls_version
                ),
                client_auth_requirement=(
                    client_auth_requirement
                ),
                supported_protocols=(
                    supported_protocols
                ),
            )
        )

        candidates.extend(
            server_candidates
        )

    return SslyzeAssessmentResult(
        scanner_version=scanner_version,
        raw_json=raw_json,
        servers=tuple(
            servers
        ),
        detection_candidates=tuple(
            candidates
        ),
    )


def get_sslyze_version() -> str:
    """Return the installed SSLyze distribution version."""

    try:
        return package_metadata.version(
            "sslyze"
        )
    except package_metadata.PackageNotFoundError as exc:
        raise SslyzeScannerError(
            "SSLyze Python distribution is unavailable."
        ) from exc


def run_sslyze_assessment(
    *,
    inventory: TLSServiceInventory,
    timeout_seconds: int,
    max_output_bytes: int,
) -> SslyzeAssessmentResult:
    """Run a bounded SSLyze assessment on pinned TLS services."""

    if timeout_seconds <= 0:
        raise SslyzeScannerError(
            "SSLyze timeout must be positive."
        )

    if max_output_bytes <= 0:
        raise SslyzeScannerError(
            "SSLyze output limit must be positive."
        )

    targets = build_sslyze_targets(
        inventory
    )

    if not targets:
        return SslyzeAssessmentResult(
            scanner_version="unknown",
            raw_json=b"",
            servers=(),
            detection_candidates=(),
        )

    command = [
        settings.sslyze_binary,
        "--json_out",
        "-",
        "--slow_connection",
        "--mozilla_config",
        "disable",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--certinfo",
        "--heartbleed",
        "--openssl_ccs",
        "--robot",
        "--compression",
        "--reneg",
        *targets,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env={
                **os.environ,
                "LC_ALL": "C",
                "LANG": "C",
            },
        )
    except FileNotFoundError as exc:
        raise SslyzeScannerError(
            "SSLyze executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SslyzeScannerError(
            "SSLyze assessment exceeded its "
            "configured timeout."
        ) from exc

    if result.returncode != 0:
        error_message = result.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise SslyzeScannerError(
            "SSLyze exited unsuccessfully"
            + (
                f": {error_message[:1000]}"
                if error_message
                else "."
            )
        )

    return parse_sslyze_json(
        result.stdout,
        authorized_services=inventory,
        max_output_bytes=max_output_bytes,
    )
