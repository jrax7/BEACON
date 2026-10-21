import shutil
from pathlib import Path
from uuid import UUID

from app.config import settings


class ScanArtifactCleanupError(RuntimeError):
    """Raised when a configured scan storage path is unsafe."""


def _scan_directory(
    root_value: str,
    scan_id: UUID,
) -> Path:
    """Resolve the UUID-named scan directory under one storage root."""

    root = Path(root_value).resolve()
    candidate = (root / str(scan_id)).resolve()

    if candidate.parent != root:
        raise ScanArtifactCleanupError(
            "The scan artifact directory resolved outside "
            "the configured storage root."
        )

    return candidate


def cleanup_scan_artifacts(
    scan_id: UUID,
) -> list[str]:
    """Remove raw and report directories for a deleted scan.

    Database deletion is intentionally handled separately. Cleanup
    failures are returned as warnings so the API can preserve an audit
    trail instead of hiding partial filesystem cleanup.
    """

    locations = (
        (
            "reports",
            settings.report_storage_path,
        ),
        (
            "raw scanner evidence",
            settings.raw_storage_path,
        ),
    )

    warnings: list[str] = []

    for label, root_value in locations:
        try:
            directory = _scan_directory(
                root_value,
                scan_id,
            )

            if not directory.exists():
                continue

            if not directory.is_dir():
                warnings.append(
                    f"The {label} path exists but is not a directory."
                )
                continue

            shutil.rmtree(directory)
        except (OSError, ScanArtifactCleanupError) as exc:
            warnings.append(
                f"Unable to remove {label}: {str(exc)[:500]}"
            )

    return warnings
