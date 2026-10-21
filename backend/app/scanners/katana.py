from __future__ import annotations

import json
import os
import re
import subprocess
from urllib.parse import (
    parse_qsl,
    urljoin,
    urlsplit,
)

from app.assessment.handoff import (
    HTTPServiceInventory,
    WebEndpoint,
    WebEndpointInventory,
)
from app.config import settings


class KatanaScannerError(RuntimeError):
    """Raised when Katana cannot be used safely."""


_VERSION_PATTERN = re.compile(
    r"\bv\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b"
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


def build_katana_inputs(
    inventory: HTTPServiceInventory,
) -> tuple[str, ...]:
    """Build crawl inputs only from classified HTTP services."""

    inputs: list[str] = []
    seen: set[str] = set()

    for service in inventory.services:
        raw_url = service.url.strip()

        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            raise KatanaScannerError(
                "Katana input contains an invalid URL."
            ) from exc

        scheme = parsed.scheme.lower()

        if scheme not in {
            "http",
            "https",
        }:
            raise KatanaScannerError(
                "Katana inputs must use HTTP or HTTPS."
            )

        if parsed.hostname is None:
            raise KatanaScannerError(
                "Katana input is missing a hostname."
            )

        if (
            _normalized_host(parsed.hostname)
            != _normalized_host(service.host)
        ):
            raise KatanaScannerError(
                "Katana input URL does not match its "
                "authorized HTTP service host."
            )

        if raw_url in seen:
            continue

        seen.add(raw_url)
        inputs.append(raw_url)

    return tuple(inputs)


def _endpoint_url(
    payload: dict,
) -> str | None:
    request = payload.get("request")

    if not isinstance(request, dict):
        return None

    endpoint = (
        _optional_string(
            request.get("endpoint")
        )
        or _optional_string(
            request.get("url")
        )
    )

    if endpoint is None:
        return None

    source = _optional_string(
        payload.get("source")
    )

    if source:
        endpoint = urljoin(
            source,
            endpoint,
        )

    return endpoint


def _discovery_method(
    payload: dict,
) -> str | None:
    tag = _optional_string(
        payload.get("tag")
    )

    attribute = _optional_string(
        payload.get("attribute")
    )

    if tag and attribute:
        return f"{tag}:{attribute}"

    return tag or attribute


def parse_katana_jsonl(
    raw_output: bytes,
    *,
    authorized_hosts: tuple[str, ...],
    max_output_bytes: int,
) -> WebEndpointInventory:
    """Parse bounded Katana JSONL under exact-FQDN scope."""

    if max_output_bytes <= 0:
        raise KatanaScannerError(
            "Katana output limit must be positive."
        )

    if len(raw_output) > max_output_bytes:
        raise KatanaScannerError(
            "Katana output exceeded its configured "
            "output limit."
        )

    authorized = {
        _normalized_host(host)
        for host in authorized_hosts
        if host.strip()
    }

    endpoints: list[WebEndpoint] = []
    seen: set[tuple[str, str]] = set()

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
            raise KatanaScannerError(
                "Katana returned invalid JSONL "
                f"at line {line_number}."
            ) from exc

        if not isinstance(payload, dict):
            raise KatanaScannerError(
                "Katana JSONL record must be "
                "a JSON object."
            )

        endpoint_url = _endpoint_url(
            payload
        )

        if endpoint_url is None:
            continue

        try:
            parsed = urlsplit(
                endpoint_url
            )
        except ValueError:
            continue

        scheme = parsed.scheme.lower()

        if (
            scheme not in {
                "http",
                "https",
            }
            or parsed.hostname is None
        ):
            continue

        host = _normalized_host(
            parsed.hostname
        )

        # Exact FQDN only. Child/sibling domains and redirects
        # never expand the authorized crawl scope.
        if host not in authorized:
            continue

        request = payload.get("request")

        if not isinstance(request, dict):
            continue

        method = (
            _optional_string(
                request.get("method")
            )
            or "GET"
        ).upper()

        parameter_names = tuple(
            sorted(
                {
                    key
                    for key, _ in parse_qsl(
                        parsed.query,
                        keep_blank_values=True,
                    )
                    if key
                }
            )
        )

        source_url = _optional_string(
            payload.get("source")
        )

        key = (
            method,
            endpoint_url,
        )

        if key in seen:
            continue

        seen.add(key)

        endpoints.append(
            WebEndpoint(
                url=endpoint_url,
                method=method,
                parameter_names=parameter_names,
                source_url=source_url,
                discovery_method=(
                    _discovery_method(
                        payload
                    )
                ),
            )
        )

    return WebEndpointInventory(
        endpoints=tuple(endpoints),
    )


def get_katana_version() -> str:
    """Return the pinned Katana runtime version."""

    command = [
        settings.katana_binary,
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
        raise KatanaScannerError(
            "Katana executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise KatanaScannerError(
            "Katana version check timed out."
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
        raise KatanaScannerError(
            "Katana version check failed."
        )

    match = _VERSION_PATTERN.search(
        output
    )

    if match is None:
        raise KatanaScannerError(
            "Katana returned an unrecognized version."
        )

    return match.group(0)


def run_katana_crawl(
    *,
    inventory: HTTPServiceInventory,
    depth: int,
    crawl_duration_seconds: int,
    request_rate: int,
    max_response_bytes: int,
    max_output_bytes: int,
    timeout_seconds: int,
) -> WebEndpointInventory:
    """Run bounded standard-mode exact-FQDN discovery."""

    if depth <= 0:
        raise KatanaScannerError(
            "Katana depth must be positive."
        )

    if crawl_duration_seconds <= 0:
        raise KatanaScannerError(
            "Katana crawl duration must be positive."
        )

    if request_rate <= 0:
        raise KatanaScannerError(
            "Katana request rate must be positive."
        )

    if max_response_bytes <= 0:
        raise KatanaScannerError(
            "Katana response size must be positive."
        )

    if max_output_bytes <= 0:
        raise KatanaScannerError(
            "Katana output limit must be positive."
        )

    if timeout_seconds <= 0:
        raise KatanaScannerError(
            "Katana timeout must be positive."
        )

    inputs = build_katana_inputs(
        inventory
    )

    if not inputs:
        return WebEndpointInventory()

    authorized_hosts = tuple(
        dict.fromkeys(
            _normalized_host(
                service.host
            )
            for service in inventory.services
        )
    )

    command = [
        settings.katana_binary,
        "-jsonl",
        "-silent",
        "-duc",
        "-nc",
        "-fs",
        "fqdn",
        "-d",
        str(depth),
        "-ct",
        f"{crawl_duration_seconds}s",
        "-mrs",
        str(max_response_bytes),
        "-rl",
        str(request_rate),
        "-retry",
        "0",
        "-or",
        "-ob",
    ]

    standard_input = (
        "\n".join(inputs)
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
        raise KatanaScannerError(
            "Katana executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise KatanaScannerError(
            "Katana crawl exceeded its "
            "configured timeout."
        ) from exc

    if result.returncode != 0:
        error_message = result.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()

        raise KatanaScannerError(
            "Katana exited unsuccessfully"
            + (
                f": {error_message[:1000]}"
                if error_message
                else "."
            )
        )

    return parse_katana_jsonl(
        result.stdout,
        authorized_hosts=authorized_hosts,
        max_output_bytes=max_output_bytes,
    )
