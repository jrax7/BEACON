from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    select_autoescape,
)
from weasyprint import HTML

from app.config import settings
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_run import ScanToolRun
from app.models.user import User
from app.services.finding_aggregation import (
    SEVERITY_LEVELS,
    aggregate_findings,
    build_summary,
)


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be generated safely."""


@dataclass(frozen=True)
class GeneratedReportArtifact:
    """A generated report file and its integrity metadata."""

    format: str
    relative_path: str
    checksum_sha256: str
    size_bytes: int
    generated_at: datetime


TEMPLATE_ROOT = (
    Path(__file__).resolve().parents[1]
    / "templates"
)

template_environment = Environment(
    loader=FileSystemLoader(
        str(TEMPLATE_ROOT)
    ),
    autoescape=select_autoescape(
        enabled_extensions=("html", "xml"),
        default_for_string=True,
    ),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    auto_reload=False,
)


def format_datetime(
    value: datetime | None,
) -> str:
    """Format a timestamp consistently for reports."""

    if value is None:
        return "Not available"

    return value.astimezone(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


template_environment.filters[
    "report_datetime"
] = format_datetime


def format_tool_name(
    value: str | None,
) -> str:
    """Return the human-readable scanner name used in reports."""

    normalized = (
        value or ""
    ).strip().lower()

    names = {
        "nmap": "Nmap",
        "zap": "OWASP ZAP",
        "nikto": "Nikto",
    }

    return names.get(
        normalized,
        value or "Scanner",
    )


template_environment.filters[
    "report_tool_name"
] = format_tool_name


def report_storage_root() -> Path:
    """Return and initialize the configured report root."""

    root = Path(
        settings.report_storage_path
    ).resolve()

    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    return root


def resolve_report_path(
    relative_path: str,
) -> Path:
    """Resolve a report path without allowing directory traversal."""

    root = report_storage_root()
    candidate = (
        root / relative_path
    ).resolve()

    if candidate != root and root not in candidate.parents:
        raise ReportGenerationError(
            "The stored report path is outside "
            "the configured report directory."
        )

    return candidate


def safe_filename_component(
    value: str,
) -> str:
    """Convert a value into a safe filename component."""

    safe_value = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        value,
    ).strip(
        "-._"
    )

    return safe_value[:80] or "target"


def deny_external_url_fetcher(
    url: str,
    **_: object,
) -> dict[str, Any]:
    """Prevent reports from retrieving external resources."""

    raise ReportGenerationError(
        "External resources are not permitted "
        f"during report rendering: {url}"
    )


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 checksum of bytes."""

    return sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Calculate a file checksum without loading it all at once."""

    digest = sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(
            lambda: file_handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def atomic_write(
    destination: Path,
    content: bytes,
) -> None:
    """Write a complete file before replacing its final path."""

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = destination.with_suffix(
        destination.suffix + ".tmp"
    )

    with temporary_path.open("wb") as file_handle:
        file_handle.write(content)
        file_handle.flush()

    temporary_path.chmod(0o600)
    temporary_path.replace(destination)


def build_report_context(
    *,
    scan: Scan,
    target: Target,
    user: User,
    findings: list[Finding],
    tool_runs: list[ScanToolRun],
    generated_at: datetime,
) -> dict[str, Any]:
    """Build trusted template context from database records."""

    grouped_issues = aggregate_findings(
        findings
    )

    for issue in grouped_issues:
        issue["sample_affected_urls"] = (
            issue["sample_affected_urls"][
                :settings.report_max_sample_urls
            ]
        )

    security_issues = [
        issue
        for issue in grouped_issues
        if issue["classification"]
        == "security_issue"
    ]

    attack_surface = [
        issue
        for issue in grouped_issues
        if issue["classification"]
        == "attack_surface"
    ]

    observations = [
        issue
        for issue in grouped_issues
        if issue["classification"]
        == "observation"
    ]

    limitations = [
        issue
        for issue in grouped_issues
        if issue["classification"]
        == "limitation"
    ]

    return {
        "report_title":
            "BEACON Security Assessment Report",
        "report_version": "1.0",
        "generated_at": generated_at,
        "scan": scan,
        "target": target,
        "user": user,
        "summary": build_summary(findings),
        "issues": grouped_issues,
        "security_issues": security_issues,
        "attack_surface": attack_surface,
        "observations": observations,
        "limitations": limitations,
        "tool_runs": tool_runs,
        "severity_order": SEVERITY_LEVELS,
    }


def render_report_html(
    context: dict[str, Any],
) -> str:
    """Render the trusted BEACON report template."""

    template = template_environment.get_template(
        "reports/security_assessment.html"
    )

    return template.render(**context)


def generate_report_artifacts(
    *,
    scan: Scan,
    target: Target,
    user: User,
    findings: list[Finding],
    tool_runs: list[ScanToolRun],
    formats: list[str],
) -> list[GeneratedReportArtifact]:
    """Generate requested HTML and PDF report artifacts."""

    requested_formats = list(
        dict.fromkeys(
            report_format.lower()
            for report_format in formats
        )
    )

    unsupported = set(
        requested_formats
    ) - {"html", "pdf"}

    if unsupported:
        raise ReportGenerationError(
            "Unsupported report formats: "
            + ", ".join(sorted(unsupported))
        )

    if not requested_formats:
        raise ReportGenerationError(
            "At least one report format is required."
        )

    generated_at = datetime.now(
        timezone.utc
    )

    context = build_report_context(
        scan=scan,
        target=target,
        user=user,
        findings=findings,
        tool_runs=tool_runs,
        generated_at=generated_at,
    )

    rendered_html = render_report_html(
        context
    )

    html_bytes = rendered_html.encode(
        "utf-8"
    )

    target_component = safe_filename_component(
        target.hostname
    )

    timestamp_component = generated_at.strftime(
        "%Y%m%dT%H%M%SZ"
    )

    random_component = uuid4().hex[:8]

    base_filename = (
        f"beacon-{target_component}-"
        f"{str(scan.id)[:8]}-"
        f"{timestamp_component}-"
        f"{random_component}"
    )

    scan_directory = Path(str(scan.id))
    artifacts: list[GeneratedReportArtifact] = []

    for report_format in requested_formats:
        if report_format == "html":
            content = html_bytes
        else:
            generated_pdf = HTML(
                string=rendered_html,
                url_fetcher=deny_external_url_fetcher,
            ).write_pdf()

            if not isinstance(
                generated_pdf,
                bytes,
            ):
                raise ReportGenerationError(
                    "WeasyPrint did not return PDF bytes."
                )

            content = generated_pdf

        relative_path = (
            scan_directory
            / f"{base_filename}.{report_format}"
        )

        destination = resolve_report_path(
            relative_path.as_posix()
        )

        atomic_write(
            destination,
            content,
        )

        artifacts.append(
            GeneratedReportArtifact(
                format=report_format,
                relative_path=relative_path.as_posix(),
                checksum_sha256=sha256_bytes(
                    content
                ),
                size_bytes=len(content),
                generated_at=generated_at,
            )
        )

    return artifacts


def cleanup_report_artifacts(
    artifacts: list[GeneratedReportArtifact],
) -> None:
    """Remove files after a failed database transaction."""

    for artifact in artifacts:
        try:
            path = resolve_report_path(
                artifact.relative_path
            )

            path.unlink(
                missing_ok=True
            )
        except OSError:
            pass
