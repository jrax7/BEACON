from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True)
class ScannerHealth:
    """Health snapshot for one scanner runtime."""

    name: str
    version: str | None
    healthy: bool
    message: str | None
    checked_at: datetime


@dataclass(frozen=True)
class ScannerArtifact:
    """Metadata describing one scanner-produced artifact."""

    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class ScannerExecutionContext:
    """Bounded execution context supplied to one scanner adapter."""

    scan_id: UUID
    target_host: str
    workspace: str
    timeout_seconds: int


class ScannerAdapter(Protocol):
    """Common contract implemented by Engine v2 scanner adapters."""

    def runtime_version(self) -> str | None:
        """Return the scanner runtime version."""

        ...

    def health_check(self) -> ScannerHealth:
        """Return the scanner runtime health state."""

        ...
