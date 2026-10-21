from datetime import datetime, timezone
from hashlib import sha256
from time import sleep
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import UUID

from app.celery_app import celery_app
from app.database import SessionLocal
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_run import ScanToolRun
from app.scanners.nikto import (
    NiktoFindingResult,
    NiktoProgress,
    run_nikto_scan,
    store_nikto_json,
)
from app.scanners.nmap import (
    NmapPortResult,
    run_nmap_web_discovery,
    store_nmap_xml,
)
from app.scanners.zap import ZapClient
from app.security.targets import (
    normalize_target_url,
    validate_target_destination,
)


@celery_app.task(
    name="beacon.test_task",
    queue="control",
)
def test_task(
    first_number: int,
    second_number: int,
) -> dict:
    """Temporary task used to verify the worker."""

    sleep(3)

    return {
        "first_number": first_number,
        "second_number": second_number,
        "result": first_number + second_number,
        "message": "BEACON background worker is operational.",
    }


def normalize_severity(value: object) -> str:
    """Convert a ZAP risk value into BEACON's severity vocabulary."""

    normalized = str(
        value or "informational"
    ).strip().lower()

    aliases = {
        "info": "informational",
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }

    return aliases.get(
        normalized,
        "informational",
    )


def optional_text(value: object) -> str | None:
    """Return a stripped string or None."""

    if value is None:
        return None

    text = str(value).strip()

    return text or None


def normalize_nmap_service(
    scan_id: UUID,
    tool_run_id: UUID,
    service: NmapPortResult,
) -> dict[str, Any]:
    """Convert one open Nmap service into a BEACON observation."""

    service_name = service.service_name or "unknown"

    fingerprint_material = "|".join(
        [
            "nmap",
            service.hostname,
            service.protocol,
            str(service.port),
        ]
    )

    fingerprint = sha256(
        fingerprint_material.encode("utf-8")
    ).hexdigest()

    version_parts = [
        value
        for value in [
            service.product,
            service.version,
            service.extra_info,
        ]
        if value
    ]

    detected_software = (
        " ".join(version_parts)
        if version_parts
        else "No software version was identified."
    )

    evidence = {
        "hostname": service.hostname,
        "resolved_address": service.address,
        "protocol": service.protocol,
        "port": service.port,
        "state": service.state,
        "service_name": service.service_name,
        "product": service.product,
        "version": service.version,
        "extra_info": service.extra_info,
        "tunnel": service.tunnel,
        "detection_method": service.detection_method,
        "detection_confidence":
            service.detection_confidence,
    }

    evidence = {
        key: value
        for key, value in evidence.items()
        if value is not None
    }

    scheme = (
        "https"
        if service.port == 443
        or service.tunnel == "ssl"
        else "http"
    )

    affected_url = (
        f"{scheme}://{service.hostname}/"
    )

    return {
        "scan_id": scan_id,
        "tool_run_id": tool_run_id,
        "tool_name": "nmap",
        "external_finding_id": (
            f"{service.protocol}-{service.port}"
        ),
        "title": (
            "Open TCP service detected: "
            f"{service.port}/{service_name}"
        )[:500],
        "description": (
            f"Nmap detected an open {service.protocol.upper()} "
            f"service on port {service.port}. "
            f"Detected software: {detected_software}"
        ),
        "severity": "informational",
        "confidence": (
            str(service.detection_confidence)
            if service.detection_confidence is not None
            else None
        ),
        "affected_url": affected_url,
        "affected_port": service.port,
        "evidence": evidence,
        "remediation": (
            "Confirm that this network service is required, "
            "supported, patched, and restricted to the "
            "intended users and networks."
        ),
        "cwe_id": None,
        "cvss_score": None,
        "fingerprint": fingerprint,
        "status": "open",
    }


def normalize_zap_alert(
    scan_id: UUID,
    tool_run_id: UUID,
    alert: dict[str, Any],
) -> dict[str, Any]:
    """Convert one raw ZAP alert into a BEACON finding."""

    plugin_id = optional_text(
        alert.get("pluginId")
    )

    affected_url = optional_text(
        alert.get("url")
    )

    parameter = optional_text(
        alert.get("param")
    )

    fingerprint_material = "|".join(
        [
            "zap",
            plugin_id or "",
            affected_url or "",
            parameter or "",
        ]
    )

    fingerprint = sha256(
        fingerprint_material.encode("utf-8")
    ).hexdigest()

    cwe_value = optional_text(
        alert.get("cweid")
    )

    cwe_id = None

    if cwe_value not in {
        None,
        "",
        "0",
        "-1",
    }:
        cwe_id = f"CWE-{cwe_value}"

    evidence = {
        "parameter": parameter,
        "evidence": optional_text(
            alert.get("evidence")
        ),
        "attack": optional_text(
            alert.get("attack")
        ),
        "reference": optional_text(
            alert.get("reference")
        ),
        "message_id": optional_text(
            alert.get("messageId")
        ),
        "source_id": optional_text(
            alert.get("sourceid")
        ),
    }

    evidence = {
        key: value
        for key, value in evidence.items()
        if value is not None
    }

    title = optional_text(
        alert.get("alert")
    ) or "ZAP security observation"

    return {
        "scan_id": scan_id,
        "tool_run_id": tool_run_id,
        "tool_name": "zap",
        "external_finding_id": plugin_id,
        "title": title[:500],
        "description": optional_text(
            alert.get("description")
        ),
        "severity": normalize_severity(
            alert.get("risk")
        ),
        "confidence": optional_text(
            alert.get("confidence")
        ),
        "affected_url": affected_url,
        "affected_port": None,
        "evidence": evidence or None,
        "remediation": optional_text(
            alert.get("solution")
        ),
        "cwe_id": cwe_id,
        "cvss_score": None,
        "fingerprint": fingerprint,
        "status": "open",
    }


def effective_url_port(
    value: str,
) -> int:
    """Return the explicit or default HTTP port for a URL."""

    parsed = urlsplit(value)

    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "The URL contains an invalid port."
        ) from exc

    if explicit_port is not None:
        return explicit_port

    if parsed.scheme.lower() == "https":
        return 443

    return 80


def build_nikto_affected_url(
    target_url: str,
    reported_path: str,
) -> str:
    """Build an in-scope URL from a Nikto-reported path."""

    base = urlsplit(target_url)

    if (
        base.scheme not in {"http", "https"}
        or base.hostname is None
    ):
        raise ValueError(
            "The Nikto base target URL is invalid."
        )

    base_origin = urlunsplit(
        (
            base.scheme,
            base.netloc,
            "/",
            "",
            "",
        )
    )

    candidate = urljoin(
        base_origin,
        reported_path or "/",
    )

    parsed_candidate = urlsplit(
        candidate
    )

    same_origin = (
        parsed_candidate.scheme == base.scheme
        and parsed_candidate.hostname == base.hostname
        and effective_url_port(candidate)
        == effective_url_port(target_url)
    )

    if not same_origin:
        return base_origin

    return candidate


def normalize_nikto_severity(
    message: str,
) -> str:
    """Assign a conservative severity to a Nikto observation."""

    normalized = message.strip().lower()

    medium_markers = (
        "contains authorization information",
        "shell history was retrieved",
        "should not be accessible via the web",
    )

    low_markers = (
        "suggested security header missing",
        "access-control-allow-origin header: *",
        "uncommon header",
        "robots.txt",
        "this might be interesting",
    )

    if any(
        marker in normalized
        for marker in medium_markers
    ):
        return "medium"

    if any(
        marker in normalized
        for marker in low_markers
    ):
        return "low"

    return "informational"


def nikto_remediation(
    message: str,
) -> str:
    """Return conservative remediation guidance."""

    normalized = message.strip().lower()

    if (
        "contains authorization information"
        in normalized
        or "shell history was retrieved"
        in normalized
        or "should not be accessible via the web"
        in normalized
    ):
        return (
            "Immediately verify whether the reported file is "
            "publicly accessible. Remove it from the web root, "
            "deny external access, rotate any exposed secrets, "
            "and review access logs for unauthorized retrieval."
        )

    if "suggested security header missing" in normalized:
        return (
            "Confirm whether the referenced security header is "
            "applicable, then configure it with a policy suitable "
            "for the application and test the application after "
            "deployment."
        )

    if "access-control-allow-origin header: *" in normalized:
        return (
            "Review the CORS policy and replace the wildcard origin "
            "with an explicit allowlist when cross-origin access "
            "does not need to be public."
        )

    return (
        "Manually validate this Nikto observation, determine whether "
        "the exposed resource or configuration is required, and "
        "restrict or remove it when unnecessary."
    )


def normalize_nikto_finding(
    scan_id: UUID,
    tool_run_id: UUID,
    target_url: str,
    target_port: int | None,
    finding: NiktoFindingResult,
    *,
    soft_404_detected: bool = False,
) -> dict[str, Any]:
    """Convert one Nikto result into a BEACON finding."""

    affected_url = build_nikto_affected_url(
        target_url,
        finding.path,
    )

    normalized_message = (
        finding.message.strip()
        or "Nikto reported a web-server observation."
    )

    message_digest = sha256(
        normalized_message.lower().encode(
            "utf-8"
        )
    ).hexdigest()[:12]

    external_finding_id = (
        f"{finding.finding_id}-{message_digest}"
    )

    fingerprint_material = "|".join(
        [
            "nikto",
            external_finding_id,
            affected_url,
            finding.method.upper(),
        ]
    )

    fingerprint = sha256(
        fingerprint_material.encode("utf-8")
    ).hexdigest()

    path_confidence_reduced = (
        soft_404_detected
        and finding.path not in {"", "/"}
    )

    evidence: dict[str, Any] = {
        "nikto_id": finding.finding_id,
        "method": finding.method.upper(),
        "reported_path": finding.path,
        "message": normalized_message,
        "soft_404_detected": soft_404_detected,
    }

    if finding.references:
        evidence["references"] = finding.references

    return {
        "scan_id": scan_id,
        "tool_run_id": tool_run_id,
        "tool_name": "nikto",
        "external_finding_id":
            external_finding_id[:255],
        "title": (
            f"Nikto: {normalized_message}"
        )[:500],
        "description": (
            "Nikto reported the following observation while "
            "running BEACON's constrained, unauthenticated "
            f"web-server profile: {normalized_message}"
            + (
                " The target also returned the same HTTP 200 "
                "response body for a random nonexistent path, "
                "so this path-based observation requires manual "
                "validation for SPA/soft-404 behavior."
                if path_confidence_reduced
                else ""
            )
        ),
        "severity": normalize_nikto_severity(
            normalized_message
        ),
        "confidence": (
            "low"
            if path_confidence_reduced
            else "medium"
        ),
        "affected_url": affected_url,
        "affected_port": (
            target_port
            if target_port is not None
            else effective_url_port(target_url)
        ),
        "evidence": evidence,
        "remediation": nikto_remediation(
            normalized_message
        ),
        "cwe_id": None,
        "cvss_score": None,
        "fingerprint": fingerprint,
        "status": "open",
    }


@celery_app.task(
    name="beacon.run_basic_scan",
    queue="scanner",
)
def run_basic_scan(scan_id: str) -> dict:
    """Run constrained Nmap, ZAP, and Nikto analysis."""

    database = SessionLocal()
    scan_uuid = UUID(scan_id)
    active_tool_run_id: UUID | None = None

    try:
        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The requested scan record does not exist."
            )

        target = database.get(
            Target,
            scan.target_id,
        )

        if target is None:
            raise RuntimeError(
                "The scan target no longer exists."
            )

        if (
            scan.organization_id
            != target.organization_id
        ):
            raise RuntimeError(
                "The scan and target belong to "
                "different organizations."
            )

        now = datetime.now(timezone.utc)

        if target.verification_status != "verified":
            raise RuntimeError(
                "The target is not ownership-verified."
            )

        if (
            target.verification_expires_at is None
            or target.verification_expires_at <= now
        ):
            target.verification_status = "expired"
            database.commit()

            raise RuntimeError(
                "The target ownership verification has expired."
            )

        normalized_target = normalize_target_url(
            target.normalized_url
        )

        validate_target_destination(
            normalized_target
        )

        scan.status = "running"
        scan.progress = 5
        scan.started_at = now
        scan.completed_at = None
        scan.failure_reason = None

        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=scan.user_id,
                target_id=target.id,
                scan_id=scan.id,
                action="scan.started",
                details={
                    "tools": [
                        "nmap",
                        "zap",
                        "nikto",
                    ],
                    "scan_level": scan.scan_level,
                },
            )
        )

        database.commit()

        # -------------------------------------------------
        # Nmap: constrained web-service discovery
        # -------------------------------------------------

        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The scan state could not be reloaded."
            )

        scan.progress = 10

        nmap_tool_run = ScanToolRun(
            scan_id=scan.id,
            tool_name="nmap",
            status="running",
            started_at=datetime.now(timezone.utc),
        )

        database.add(nmap_tool_run)
        database.flush()

        active_tool_run_id = nmap_tool_run.id

        database.commit()

        nmap_result = run_nmap_web_discovery(
            target.hostname
        )

        raw_nmap_path = store_nmap_xml(
            str(scan.id),
            nmap_result.raw_xml,
        )

        scan = database.get(
            Scan,
            scan_uuid,
        )

        nmap_tool_run = database.get(
            ScanToolRun,
            active_tool_run_id,
        )

        if scan is None or nmap_tool_run is None:
            raise RuntimeError(
                "The Nmap execution state could not be reloaded."
            )

        for service in nmap_result.open_ports:
            database.add(
                Finding(
                    **normalize_nmap_service(
                        scan.id,
                        nmap_tool_run.id,
                        service,
                    )
                )
            )

        nmap_completed_at = datetime.now(
            timezone.utc
        )

        nmap_tool_run.tool_version = (
            nmap_result.scanner_version
        )
        nmap_tool_run.status = "completed"
        nmap_tool_run.exit_code = 0
        nmap_tool_run.raw_output_path = raw_nmap_path
        nmap_tool_run.completed_at = nmap_completed_at

        scan.progress = 25

        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=scan.user_id,
                target_id=target.id,
                scan_id=scan.id,
                action="scan.tool_completed",
                details={
                    "tool": "nmap",
                    "tool_version":
                        nmap_result.scanner_version,
                    "open_service_count":
                        len(nmap_result.open_ports),
                    "profile":
                        nmap_result.command_summary,
                    "raw_output_path":
                        raw_nmap_path,
                },
            )
        )

        database.commit()
        active_tool_run_id = None

        # -------------------------------------------------
        # ZAP: crawl and passive HTTP analysis
        # -------------------------------------------------

        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The scan state could not be reloaded."
            )

        scan.progress = 30

        zap_tool_run = ScanToolRun(
            scan_id=scan.id,
            tool_name="zap",
            status="running",
            started_at=datetime.now(timezone.utc),
        )

        database.add(zap_tool_run)
        database.flush()

        active_tool_run_id = zap_tool_run.id

        database.commit()

        with ZapClient() as zap:
            zap_result = zap.run_passive_scan(
                target.normalized_url
            )

        scan = database.get(
            Scan,
            scan_uuid,
        )

        zap_tool_run = database.get(
            ScanToolRun,
            active_tool_run_id,
        )

        if scan is None or zap_tool_run is None:
            raise RuntimeError(
                "The ZAP execution state could not be reloaded."
            )

        scan.status = "processing"
        scan.progress = 65

        zap_tool_run.tool_version = (
            zap_result.version
        )

        unique_zap_findings: dict[
            str,
            dict[str, Any],
        ] = {}

        for alert in zap_result.alerts:
            normalized = normalize_zap_alert(
                scan.id,
                zap_tool_run.id,
                alert,
            )

            fingerprint = normalized["fingerprint"]

            if fingerprint not in unique_zap_findings:
                unique_zap_findings[
                    fingerprint
                ] = normalized

        for finding_data in (
            unique_zap_findings.values()
        ):
            database.add(
                Finding(**finding_data)
            )

        zap_completed_at = datetime.now(
            timezone.utc
        )

        zap_tool_run.status = "completed"
        zap_tool_run.exit_code = 0
        zap_tool_run.completed_at = zap_completed_at

        scan.status = "processing"
        scan.progress = 70

        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=scan.user_id,
                target_id=target.id,
                scan_id=scan.id,
                action="scan.tool_completed",
                details={
                    "tool": "zap",
                    "tool_version":
                        zap_result.version,
                    "spider_scan_id":
                        zap_result.spider_scan_id,
                    "finding_count":
                        len(unique_zap_findings),
                },
            )
        )

        database.commit()
        active_tool_run_id = None

        # -------------------------------------------------
        # Nikto: constrained web-server assessment
        # -------------------------------------------------

        nikto_result = None
        raw_nikto_path: str | None = None

        unique_nikto_findings: dict[
            str,
            dict[str, Any],
        ] = {}

        nikto_error: str | None = None
        nikto_status = "skipped"

        nikto_target_port = effective_url_port(
            target.normalized_url
        )

        nmap_confirmed_target_port = any(
            service.protocol.lower() == "tcp"
            and service.port == nikto_target_port
            for service in nmap_result.open_ports
        )

        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The scan state could not be reloaded "
                "before Nikto execution."
            )

        scan.progress = 75

        if not nmap_confirmed_target_port:
            skipped_at = datetime.now(
                timezone.utc
            )

            nikto_tool_run = ScanToolRun(
                scan_id=scan.id,
                tool_name="nikto",
                status="skipped",
                error_message=(
                    "Nmap did not confirm that the verified "
                    "target web port was open."
                ),
                started_at=skipped_at,
                completed_at=skipped_at,
            )

            database.add(nikto_tool_run)

            scan.progress = 95

            database.add(
                AuditLog(
                    organization_id=scan.organization_id,
                    user_id=scan.user_id,
                    target_id=scan.target_id,
                    scan_id=scan.id,
                    action="scan.tool_skipped",
                    details={
                        "tool": "nikto",
                        "reason": (
                            "Nmap did not confirm the target "
                            f"port {nikto_target_port} as open."
                        ),
                    },
                )
            )

            database.commit()

        else:
            nikto_tool_run = ScanToolRun(
                scan_id=scan.id,
                tool_name="nikto",
                status="running",
                started_at=datetime.now(
                    timezone.utc
                ),
            )

            database.add(nikto_tool_run)
            database.flush()

            active_tool_run_id = (
                nikto_tool_run.id
            )

            database.commit()

            last_nikto_progress: dict[str, int | None] = {
                "completed_requests": 0,
                "percent": None,
            }

            def record_nikto_progress(
                progress: NiktoProgress,
            ) -> None:
                """Persist sparse, safe Nikto progress for the GUI."""

                if (
                    progress.completed_requests
                    <= int(
                        last_nikto_progress[
                            "completed_requests"
                        ]
                        or 0
                    )
                ):
                    return

                try:
                    progress_scan = database.get(
                        Scan,
                        scan_uuid,
                    )

                    if progress_scan is None:
                        return

                    effective_percent = (
                        progress.percent
                        if progress.percent is not None
                        else last_nikto_progress[
                            "percent"
                        ]
                    )

                    if effective_percent is not None:
                        weighted_progress = min(
                            94,
                            75
                            + round(
                                effective_percent
                                * 0.19
                            ),
                        )

                        progress_scan.progress = max(
                            progress_scan.progress,
                            weighted_progress,
                        )

                    database.add(
                        AuditLog(
                            organization_id=progress_scan.organization_id,
                            user_id=progress_scan.user_id,
                            target_id=progress_scan.target_id,
                            scan_id=progress_scan.id,
                            action="scan.tool_progress",
                            details={
                                "tool": "nikto",
                                "completed_requests": (
                                    progress.completed_requests
                                ),
                                "percent": effective_percent,
                                "estimated_total_requests": (
                                    progress.estimated_total_requests
                                ),
                                "message": progress.message[:500],
                            },
                        )
                    )

                    database.commit()

                    last_nikto_progress[
                        "completed_requests"
                    ] = progress.completed_requests
                    if progress.percent is not None:
                        last_nikto_progress[
                            "percent"
                        ] = progress.percent

                except Exception:
                    database.rollback()

            try:
                nikto_result = run_nikto_scan(
                    target.normalized_url,
                    progress_callback=(
                        record_nikto_progress
                    ),
                )

                raw_nikto_path = store_nikto_json(
                    str(scan.id),
                    nikto_result.raw_json,
                )

                scan = database.get(
                    Scan,
                    scan_uuid,
                )

                nikto_tool_run = database.get(
                    ScanToolRun,
                    active_tool_run_id,
                )

                if (
                    scan is None
                    or nikto_tool_run is None
                ):
                    raise RuntimeError(
                        "The Nikto execution state "
                        "could not be reloaded."
                    )

                for finding in (
                    nikto_result.findings
                ):
                    normalized = (
                        normalize_nikto_finding(
                            scan.id,
                            nikto_tool_run.id,
                            target.normalized_url,
                            nikto_result.port,
                            finding,
                            soft_404_detected=(
                                nikto_result.soft_404_detected
                            ),
                        )
                    )

                    fingerprint = normalized[
                        "fingerprint"
                    ]

                    if (
                        fingerprint
                        not in unique_nikto_findings
                    ):
                        unique_nikto_findings[
                            fingerprint
                        ] = normalized

                for finding_data in (
                    unique_nikto_findings.values()
                ):
                    database.add(
                        Finding(**finding_data)
                    )

                nikto_completed_at = (
                    datetime.now(timezone.utc)
                )

                nikto_tool_run.tool_version = (
                    nikto_result.scanner_version
                )
                nikto_tool_run.status = "completed"
                nikto_tool_run.exit_code = 0
                nikto_tool_run.raw_output_path = (
                    raw_nikto_path
                )
                nikto_tool_run.completed_at = (
                    nikto_completed_at
                )

                scan.progress = 95
                nikto_status = "completed"

                database.add(
                    AuditLog(
                        organization_id=scan.organization_id,
                        user_id=scan.user_id,
                        target_id=scan.target_id,
                        scan_id=scan.id,
                        action="scan.tool_completed",
                        details={
                            "tool": "nikto",
                            "tool_version": (
                                nikto_result
                                .scanner_version
                            ),
                            "finding_count": len(
                                unique_nikto_findings
                            ),
                            "reached_max_time": (
                                nikto_result
                                .reached_max_time
                            ),
                            "soft_404_detected": (
                                nikto_result
                                .soft_404_detected
                            ),
                            "profile": (
                                nikto_result
                                .command_summary
                            ),
                            "raw_output_path":
                                raw_nikto_path,
                            "completed_requests": (
                                nikto_result
                                .completed_requests
                            ),
                            "request_error_count": (
                                nikto_result
                                .request_error_count
                            ),
                        },
                    )
                )

                database.commit()
                active_tool_run_id = None

            except Exception as nikto_exc:
                database.rollback()
                database.expire_all()

                nikto_error = str(
                    nikto_exc
                )[:2000]

                failed_nikto_scan = database.get(
                    Scan,
                    scan_uuid,
                )

                failed_nikto_run = database.get(
                    ScanToolRun,
                    active_tool_run_id,
                )

                if (
                    failed_nikto_scan is None
                    or failed_nikto_run is None
                ):
                    raise RuntimeError(
                        "The failed Nikto state "
                        "could not be reloaded."
                    ) from nikto_exc

                failed_at = datetime.now(
                    timezone.utc
                )

                failed_nikto_run.status = "failed"
                failed_nikto_run.exit_code = 1
                failed_nikto_run.error_message = (
                    nikto_error
                )
                failed_nikto_run.completed_at = (
                    failed_at
                )

                failed_nikto_scan.status = (
                    "processing"
                )
                failed_nikto_scan.progress = 95

                database.add(
                    AuditLog(
                        organization_id=failed_nikto_scan.organization_id,
                        user_id=(
                            failed_nikto_scan.user_id
                        ),
                        target_id=(
                            failed_nikto_scan.target_id
                        ),
                        scan_id=failed_nikto_scan.id,
                        action="scan.tool_failed",
                        details={
                            "tool": "nikto",
                            "reason": (
                                nikto_error[:1000]
                            ),
                            "scan_continued": True,
                        },
                    )
                )

                database.commit()
                active_tool_run_id = None
                nikto_status = "failed"

        # -------------------------------------------------
        # Final scan completion
        # -------------------------------------------------

        scan = database.get(
            Scan,
            scan_uuid,
        )

        if scan is None:
            raise RuntimeError(
                "The final scan state could not be reloaded."
            )

        completed_at = datetime.now(
            timezone.utc
        )

        scan.status = "completed"
        scan.progress = 100
        scan.completed_at = completed_at
        scan.failure_reason = None

        completion_details: dict[
            str,
            Any,
        ] = {
            "tools": [
                "nmap",
                "zap",
                "nikto",
            ],
            "nmap_open_service_count":
                len(nmap_result.open_ports),
            "zap_finding_count":
                len(unique_zap_findings),
            "nikto_status":
                nikto_status,
            "nikto_finding_count":
                len(unique_nikto_findings),
            "total_new_findings": (
                len(nmap_result.open_ports)
                + len(unique_zap_findings)
                + len(unique_nikto_findings)
            ),
        }

        if nikto_error is not None:
            completion_details[
                "nikto_error"
            ] = nikto_error[:1000]

        database.add(
            AuditLog(
                organization_id=scan.organization_id,
                user_id=scan.user_id,
                target_id=scan.target_id,
                scan_id=scan.id,
                action="scan.completed",
                details=completion_details,
            )
        )

        database.commit()

        return {
            "scan_id": str(scan.id),
            "status": "completed",
            "tools": {
                "nmap": {
                    "status": "completed",
                    "version":
                        nmap_result.scanner_version,
                    "open_service_count":
                        len(nmap_result.open_ports),
                    "raw_output_path":
                        raw_nmap_path,
                },
                "zap": {
                    "status": "completed",
                    "version":
                        zap_result.version,
                    "finding_count":
                        len(unique_zap_findings),
                },
                "nikto": {
                    "status": nikto_status,
                    "version": (
                        nikto_result.scanner_version
                        if nikto_result is not None
                        else None
                    ),
                    "finding_count":
                        len(unique_nikto_findings),
                    "raw_output_path":
                        raw_nikto_path,
                    "reached_max_time": (
                        nikto_result.reached_max_time
                        if nikto_result is not None
                        else False
                    ),
                    "error": nikto_error,
                },
            },
        }

    except Exception as exc:
        database.rollback()
        database.expire_all()

        failed_scan = database.get(
            Scan,
            scan_uuid,
        )

        if failed_scan is not None:
            failed_scan.status = "failed"
            failed_scan.progress = 100
            failed_scan.completed_at = datetime.now(
                timezone.utc
            )
            failed_scan.failure_reason = str(exc)[:2000]

            if active_tool_run_id is not None:
                failed_tool_run = database.get(
                    ScanToolRun,
                    active_tool_run_id,
                )

                if failed_tool_run is not None:
                    failed_tool_run.status = "failed"
                    failed_tool_run.exit_code = 1
                    failed_tool_run.error_message = str(
                        exc
                    )[:2000]
                    failed_tool_run.completed_at = (
                        datetime.now(timezone.utc)
                    )

            database.add(
                AuditLog(
                    organization_id=failed_scan.organization_id,
                    user_id=failed_scan.user_id,
                    target_id=failed_scan.target_id,
                    scan_id=failed_scan.id,
                    action="scan.failed",
                    details={
                        "reason": str(exc)[:1000],
                    },
                )
            )

            database.commit()

        raise

    finally:
        database.close()
