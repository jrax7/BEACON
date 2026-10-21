from pathlib import Path

from app.reporting.generator import (
    ReportGenerationError,
    report_storage_root,
    resolve_report_path,
)


class ReportArtifactCleanupError(RuntimeError):
    """Raised when a stored report artifact cannot be removed safely."""


def cleanup_report_artifact(
    relative_path: str,
) -> list[str]:
    """Remove one report artifact and prune empty scan directories.

    Missing files are treated as already removed. Unsafe configured paths
    are surfaced as cleanup warnings rather than followed.
    """

    warnings: list[str] = []

    try:
        root = report_storage_root()
        report_path = resolve_report_path(relative_path)
    except ReportGenerationError as exc:
        return [f"Unable to resolve report artifact safely: {str(exc)[:500]}"]

    try:
        if report_path.exists():
            if not report_path.is_file():
                return ["The stored report artifact path is not a regular file."]
            report_path.unlink()

        parent = report_path.parent
        while parent != root and root in parent.parents:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent
    except OSError as exc:
        warnings.append(
            f"Unable to remove report artifact: {str(exc)[:500]}"
        )

    return warnings
