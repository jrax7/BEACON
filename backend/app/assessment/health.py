from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
import json
import os
import re
import subprocess
from typing import (
    Callable,
    Literal,
    Mapping,
)
from urllib.request import urlopen

from pydantic import BaseModel

from app.scanners.httpx import (
    get_httpx_version,
)
from app.scanners.katana import (
    get_katana_version,
)
from app.scanners.nikto import (
    get_nikto_version,
)
from app.scanners.sslyze import (
    get_sslyze_version,
)


ScannerRuntimeStatus = Literal[
    "healthy",
    "unavailable",
]

ScannerInventoryStatus = Literal[
    "healthy",
    "degraded",
    "unavailable",
]


ENGINE_ORDER = (
    "nmap",
    "httpx",
    "katana",
    "sslyze",
    "nuclei",
    "zap",
    "nikto",
)


class ScannerHealthEngine(BaseModel):
    """One scanner runtime version probe."""

    engine: str

    status: ScannerRuntimeStatus

    version: str | None

    error: str | None


class ScannerHealthInventory(BaseModel):
    """Aggregated runtime health for all Engine v2 scanners."""

    status: ScannerInventoryStatus

    checked_at: datetime

    engines: list[
        ScannerHealthEngine
    ]


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _bounded_version_command(
    command: list[str],
    *,
    engine: str,
    timeout_seconds: float = 5.0,
) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        raise RuntimeError(
            f"{engine} version probe "
            f"failed: {exc}"
        ) from exc

    output = "\n".join(
        part.strip()
        for part
        in (
            completed.stdout,
            completed.stderr,
        )
        if part
        and part.strip()
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"{engine} version probe "
            f"returned exit code "
            f"{completed.returncode}: "
            f"{output[:300]}"
        )

    if not output:
        raise RuntimeError(
            f"{engine} version probe "
            "returned no output."
        )

    return output


def _nmap_version() -> str:
    output = (
        _bounded_version_command(
            [
                "nmap",
                "--version",
            ],
            engine="nmap",
        )
    )

    match = re.search(
        r"Nmap version\s+"
        r"([0-9]+(?:\.[0-9]+)+)",
        output,
        re.IGNORECASE,
    )

    if match is None:
        raise RuntimeError(
            "Nmap returned an "
            "unrecognized version."
        )

    return match.group(
        1
    )


def _nuclei_version() -> str:
    output = (
        _bounded_version_command(
            [
                "nuclei",
                "-version",
            ],
            engine="nuclei",
        )
    )

    match = re.search(
        r"\bv?"
        r"([0-9]+\.[0-9]+\.[0-9]+)"
        r"\b",
        output,
    )

    if match is None:
        raise RuntimeError(
            "Nuclei returned an "
            "unrecognized version."
        )

    return match.group(
        1
    )


def _zap_version() -> str:
    url = os.environ.get(
        "BEACON_ZAP_VERSION_URL",
        (
            "http://zap:8080/"
            "JSON/core/view/version/"
        ),
    )

    try:
        with urlopen(
            url,
            timeout=3.0,
        ) as response:
            payload = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )
    except Exception as exc:
        raise RuntimeError(
            "ZAP runtime version "
            f"probe failed: {exc}"
        ) from exc

    version = payload.get(
        "version"
    )

    if (
        not isinstance(
            version,
            str,
        )
        or not version.strip()
    ):
        raise RuntimeError(
            "ZAP runtime version "
            "response was invalid."
        )

    return version.strip()


def _required_version(
    provider: Callable[
        [],
        object,
    ],
    *,
    engine: str,
) -> str:
    value = provider()

    if value is None:
        raise RuntimeError(
            f"{engine} version "
            "is unavailable."
        )

    normalized = str(
        value
    ).strip()

    if not normalized:
        raise RuntimeError(
            f"{engine} version "
            "is unavailable."
        )

    return normalized


def _default_providers(
) -> dict[
    str,
    Callable[
        [],
        str,
    ],
]:
    return {
        "nmap":
            _nmap_version,

        "httpx":
            lambda:
                _required_version(
                    get_httpx_version,
                    engine="httpx",
                ),

        "katana":
            lambda:
                _required_version(
                    get_katana_version,
                    engine="katana",
                ),

        "sslyze":
            lambda:
                _required_version(
                    get_sslyze_version,
                    engine="sslyze",
                ),

        "nuclei":
            _nuclei_version,

        "zap":
            _zap_version,

        "nikto":
            lambda:
                _required_version(
                    get_nikto_version,
                    engine="nikto",
                ),
    }


def collect_scanner_health(
    *,
    providers: Mapping[
        str,
        Callable[
            [],
            object,
        ],
    ]
    | None = None,
    clock: Callable[
        [],
        datetime,
    ] = _utc_now,
) -> ScannerHealthInventory:
    """Collect every scanner independently and never fail globally."""

    selected = (
        dict(
            _default_providers()
        )
        if providers is None
        else dict(
            providers
        )
    )

    engines: list[
        ScannerHealthEngine
    ] = []

    healthy_count = 0

    for engine in ENGINE_ORDER:
        provider = (
            selected.get(
                engine
            )
        )

        if provider is None:
            engines.append(
                ScannerHealthEngine(
                    engine=engine,
                    status="unavailable",
                    version=None,
                    error=(
                        "No runtime version "
                        "provider is configured."
                    ),
                )
            )

            continue

        try:
            version = (
                _required_version(
                    provider,
                    engine=engine,
                )
            )
        except Exception as exc:
            engines.append(
                ScannerHealthEngine(
                    engine=engine,
                    status="unavailable",
                    version=None,
                    error=(
                        str(
                            exc
                        )[:1000]
                    ),
                )
            )

            continue

        healthy_count += 1

        engines.append(
            ScannerHealthEngine(
                engine=engine,
                status="healthy",
                version=version,
                error=None,
            )
        )

    if healthy_count == len(
        ENGINE_ORDER
    ):
        overall_status: (
            ScannerInventoryStatus
        ) = "healthy"

    elif healthy_count == 0:
        overall_status = (
            "unavailable"
        )

    else:
        overall_status = (
            "degraded"
        )

    return ScannerHealthInventory(
        status=overall_status,
        checked_at=clock(),
        engines=engines,
    )
