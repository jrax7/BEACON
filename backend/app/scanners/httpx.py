from __future__ import annotations

import json
import os
import re
import subprocess
from urllib.parse import urljoin, urlsplit

from app.assessment.handoff import (
    HTTPService,
    HTTPServiceInventory,
    ServiceInventory,
)
from app.config import settings


class HttpxScannerError(RuntimeError):
    """Raised when ProjectDiscovery httpx cannot be used safely."""


_VERSION_PATTERN = re.compile(
    r"\bv\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b"
)


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None

    value = value.strip()

    return value or None


def _integer_value(value: object) -> int | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalized_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _safe_candidate_host(host: str) -> str:
    candidate = host.strip()

    if not candidate:
        raise HttpxScannerError(
            "HTTP service contains an empty host."
        )

    if any(character in candidate for character in "\r\n\0"):
        raise HttpxScannerError(
            "HTTP service contains an invalid host."
        )

    if ":" in candidate:
        if candidate.startswith("[") and candidate.endswith("]"):
            return candidate

        return f"[{candidate}]"

    return candidate


def build_httpx_candidates(
    inventory: ServiceInventory,
) -> tuple[str, ...]:
    """Build bounded probe targets only from Nmap's typed handoff."""

    candidates: list[str] = []
    seen: set[str] = set()

    for service in inventory.services:
        if service.transport.lower() != "tcp":
            continue

        if service.state.lower() != "open":
            continue

        if service.port < 1 or service.port > 65535:
            raise HttpxScannerError(
                f"HTTP candidate port {service.port} "
                "is outside the valid range."
            )

        host = _safe_candidate_host(service.host)

        candidate = f"{host}:{service.port}"

        if candidate in seen:
            continue

        seen.add(candidate)
        candidates.append(candidate)

    return tuple(candidates)


def _redirect_chain(
    payload: dict,
    *,
    original_url: str,
) -> tuple[str, ...]:
    chain: list[str] = [original_url]

    reported_chain = payload.get("chain")

    if isinstance(reported_chain, list):
        for entry in reported_chain:
            candidate: str | None = None

            if isinstance(entry, str):
                candidate = _optional_string(entry)

            elif isinstance(entry, dict):
                candidate = (
                    _optional_string(entry.get("url"))
                    or _optional_string(
                        entry.get("location")
                    )
                )

            if candidate is None:
                continue

            candidate = urljoin(
                chain[-1],
                candidate,
            )

            if candidate != chain[-1]:
                chain.append(candidate)

    final_url = _optional_string(
        payload.get("final_url")
    )

    if final_url:
        final_url = urljoin(
            original_url,
            final_url,
        )

        if final_url != chain[-1]:
            chain.append(final_url)

    elif location := _optional_string(
        payload.get("location")
    ):
        location = urljoin(
            original_url,
            location,
        )

        if location != chain[-1]:
            chain.append(location)

    return tuple(chain)


def _effective_url(
    payload: dict,
    *,
    original_url: str,
    original_host: str,
) -> str:
    final_url = _optional_string(
        payload.get("final_url")
    )

    if not final_url:
        return original_url

    final_url = urljoin(
        original_url,
        final_url,
    )

    parsed = urlsplit(final_url)

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or parsed.hostname is None
    ):
        return original_url

    if (
        _normalized_host(parsed.hostname)
        != _normalized_host(original_host)
    ):
        # Redirects outside the authorized host are evidence only.
        # They never become a new effective assessment target.
        return original_url

    return final_url


def parse_httpx_jsonl(
    raw_output: bytes,
    *,
    max_output_bytes: int,
) -> HTTPServiceInventory:
    """Parse bounded ProjectDiscovery httpx JSONL output."""

    if max_output_bytes <= 0:
        raise HttpxScannerError(
            "HTTPX output limit must be positive."
        )

    if len(raw_output) > max_output_bytes:
        raise HttpxScannerError(
            "HTTPX output exceeded its configured output limit."
        )

    services: list[HTTPService] = []

    for line_number, raw_line in enumerate(
        raw_output.splitlines(),
        start=1,
    ):
        raw_line = raw_line.strip()

        if not raw_line:
            continue

        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise HttpxScannerError(
                "HTTPX returned invalid JSONL "
                f"at line {line_number}."
            ) from exc

        if not isinstance(payload, dict):
            raise HttpxScannerError(
                "HTTPX JSONL record must be a JSON object."
            )

        if payload.get("failed") is True:
            continue

        raw_url = _optional_string(
            payload.get("url")
        )

        if raw_url is None:
            raise HttpxScannerError(
                "HTTPX JSONL record is missing a URL."
            )

        parsed = urlsplit(raw_url)

        scheme = parsed.scheme.lower()

        if (
            scheme not in {"http", "https"}
            or parsed.hostname is None
        ):
            raise HttpxScannerError(
                "HTTPX returned an invalid HTTP service URL."
            )

        host = parsed.hostname

        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise HttpxScannerError(
                "HTTPX returned an invalid service port."
            ) from exc

        port = (
            parsed_port
            or _integer_value(payload.get("port"))
            or (443 if scheme == "https" else 80)
        )

        if port < 1 or port > 65535:
            raise HttpxScannerError(
                "HTTPX returned a service port outside "
                "the valid range."
            )

        technology_value = payload.get("tech")

        if isinstance(technology_value, list):
            technology_hints = tuple(
                item.strip()
                for item in technology_value
                if isinstance(item, str)
                and item.strip()
            )
        elif isinstance(technology_value, str):
            technology_hints = (
                technology_value.strip(),
            ) if technology_value.strip() else ()
        else:
            technology_hints = ()

        service = HTTPService(
            url=raw_url,
            host=host,
            port=port,
            scheme=scheme,
            status_code=_integer_value(
                payload.get("status_code")
            ),
            title=_optional_string(
                payload.get("title")
            ),
            effective_url=_effective_url(
                payload,
                original_url=raw_url,
                original_host=host,
            ),
            redirect_chain=_redirect_chain(
                payload,
                original_url=raw_url,
            ),
            server=(
                _optional_string(
                    payload.get("webserver")
                )
                or _optional_string(
                    payload.get("server")
                )
            ),
            technology_hints=technology_hints,
            content_type=_optional_string(
                payload.get("content_type")
            ),
        )

        services.append(service)

    return HTTPServiceInventory(
        services=tuple(services),
    )


def get_httpx_version() -> str:
    """Return the ProjectDiscovery httpx runtime version."""

    command = [
        settings.httpx_binary,
        "-version",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=15,
            env={
                **os.environ,
                "LC_ALL": "C",
                "LANG": "C",
            },
        )
    except FileNotFoundError as exc:
        raise HttpxScannerError(
            "ProjectDiscovery httpx executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HttpxScannerError(
            "ProjectDiscovery httpx version check timed out."
        ) from exc

    output = (
        result.stdout
        + b"\n"
        + result.stderr
    ).decode(
        "utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise HttpxScannerError(
            "ProjectDiscovery httpx version check failed."
        )

    match = _VERSION_PATTERN.search(output)

    if match is None:
        raise HttpxScannerError(
            "ProjectDiscovery httpx returned an "
            "unrecognized version."
        )

    return match.group(0)


def run_httpx_probe(
    *,
    inventory: ServiceInventory,
    timeout_seconds: int,
    request_rate: int,
    max_output_bytes: int,
) -> HTTPServiceInventory:
    """Classify discovered services with bounded PD httpx probes."""

    if timeout_seconds <= 0:
        raise HttpxScannerError(
            "HTTPX timeout must be positive."
        )

    if request_rate <= 0:
        raise HttpxScannerError(
            "HTTPX request rate must be positive."
        )

    if max_output_bytes <= 0:
        raise HttpxScannerError(
            "HTTPX output limit must be positive."
        )

    candidates = build_httpx_candidates(
        inventory
    )

    if not candidates:
        return HTTPServiceInventory()

    command = [
        settings.httpx_binary,
        "-json",
        "-silent",
        "-duc",
        "-nc",
        "-fhr",
        "-include-chain",
        "-sc",
        "-title",
        "-server",
        "-td",
        "-ct",
        "-ip",
        "-location",
        "-retries",
        "0",
        "-maxr",
        str(settings.httpx_max_redirects),
        "-rstr",
        str(settings.httpx_max_response_bytes),
        "-rl",
        str(request_rate),
    ]

    standard_input = (
        "\n".join(candidates)
        + "\n"
    ).encode("utf-8")

    try:
        result = subprocess.run(
            command,
            input=standard_input,
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
        raise HttpxScannerError(
            "ProjectDiscovery httpx executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HttpxScannerError(
            "ProjectDiscovery httpx probe exceeded "
            "its configured timeout."
        ) from exc

    if result.returncode != 0:
        error_message = result.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise HttpxScannerError(
            "ProjectDiscovery httpx exited unsuccessfully"
            + (
                f": {error_message[:1000]}"
                if error_message
                else "."
            )
        )

    return parse_httpx_jsonl(
        result.stdout,
        max_output_bytes=max_output_bytes,
    )
