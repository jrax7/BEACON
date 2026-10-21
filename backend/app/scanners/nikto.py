from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import (
    urljoin,
    urlsplit,
    urlunsplit,
)
import json
import os
import re
import secrets
import selectors
import subprocess
import time
from typing import Any, Callable

import httpx

from app.assessment.handoff import HTTPServiceInventory
from app.assessment.profiles import get_assessment_profile
from app.config import settings


class NiktoScannerError(RuntimeError):
    """Raised when the constrained Nikto scan fails."""


@dataclass(frozen=True)
class NiktoFindingResult:
    """One finding reported by Nikto."""

    finding_id: str
    method: str
    path: str
    message: str
    references: list[str]


@dataclass(frozen=True)
class NiktoProgress:
    """One safe progress update parsed from Nikto stdout."""

    completed_requests: int
    percent: int | None
    estimated_total_requests: int | None
    message: str


@dataclass(frozen=True)
class NiktoScanResult:
    """Parsed output from BEACON's constrained Nikto profile."""

    scanner_version: str
    command_summary: str
    target_url: str
    host: str | None
    ip_address: str | None
    port: int | None
    server_banner: str | None
    start_time: str | None
    end_time: str | None
    raw_json: bytes
    console_output: str
    reached_max_time: bool
    soft_404_detected: bool
    completed_requests: int | None
    request_error_count: int | None
    findings: list[NiktoFindingResult]


@dataclass(frozen=True)
class NiktoDetectionCandidate:
    """One Engine v2 detection candidate produced from Nikto evidence."""

    finding_id: str
    title: str
    severity: str
    confidence: str
    affected_url: str
    affected_port: int | None
    method: str
    message: str
    references: tuple[str, ...]
    remediation: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class NiktoAssessmentResult:
    """Engine v2 Nikto results before persistence."""

    scan_results: tuple[NiktoScanResult, ...] = ()
    raw_evidence: tuple[bytes, ...] = ()
    detection_candidates: tuple[
        NiktoDetectionCandidate,
        ...
    ] = ()


def non_empty_string(
    value: Any,
) -> str | None:
    """Return a stripped string or None."""

    if value is None:
        return None

    text = str(value).strip()

    return text or None


def optional_integer(
    value: Any,
) -> int | None:
    """Return an integer when conversion is possible."""

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_references(
    value: Any,
) -> list[str]:
    """Normalize Nikto reference data into a string list."""

    if value is None:
        return []

    if isinstance(value, str):
        value = value.strip()

        return [value] if value else []

    if isinstance(value, list):
        references: list[str] = []

        for item in value:
            normalized = non_empty_string(item)

            if normalized is not None:
                references.append(normalized)

        return references

    normalized = non_empty_string(value)

    return [normalized] if normalized is not None else []


def validate_nikto_target_url(
    target_url: str,
) -> str:
    """Validate the URL supplied to Nikto."""

    normalized = target_url.strip()

    if not normalized:
        raise NiktoScannerError(
            "The Nikto target URL is empty."
        )

    parsed = urlsplit(normalized)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise NiktoScannerError(
            "Nikto targets must use HTTP or HTTPS."
        )

    if parsed.hostname is None:
        raise NiktoScannerError(
            "The Nikto target URL has no hostname."
        )

    if (
        parsed.username is not None
        or parsed.password is not None
    ):
        raise NiktoScannerError(
            "Nikto target URLs cannot contain credentials."
        )

    if parsed.fragment:
        raise NiktoScannerError(
            "Nikto target URLs cannot contain fragments."
        )

    return normalized


def response_prefix(
    client: httpx.Client,
    url: str,
    *,
    limit: int = 65_536,
) -> tuple[int, bytes, str | None]:
    """Read a bounded response prefix for soft-404 detection."""

    collected = bytearray()

    with client.stream(
        "GET",
        url,
        headers={
            "User-Agent": settings.nikto_user_agent,
        },
    ) as response:
        for chunk in response.iter_bytes():
            if not chunk:
                continue

            remaining = limit - len(collected)

            if remaining <= 0:
                break

            collected.extend(chunk[:remaining])

            if len(collected) >= limit:
                break

        return (
            response.status_code,
            bytes(collected),
            response.headers.get("content-type"),
        )


def detect_soft_404(
    target_url: str,
) -> bool:
    """Detect a SPA/wildcard success page without blocking the scan."""

    parsed = urlsplit(target_url)

    if parsed.hostname is None:
        return False

    probe_url = (
        f"{parsed.scheme}://{parsed.netloc}/"
        f"beacon-nonexistent-{secrets.token_hex(8)}"
    )

    timeout = httpx.Timeout(
        max(
            1.0,
            min(
                float(settings.nikto_request_timeout_seconds),
                5.0,
            ),
        )
    )

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            target_status, target_body, target_type = response_prefix(
                client,
                target_url,
            )
            probe_status, probe_body, probe_type = response_prefix(
                client,
                probe_url,
            )
    except httpx.HTTPError:
        return False

    if target_status != 200 or probe_status != 200:
        return False

    if not target_body or not probe_body:
        return False

    target_media = (target_type or "").split(";", 1)[0].strip().lower()
    probe_media = (probe_type or "").split(";", 1)[0].strip().lower()

    if target_media and probe_media and target_media != probe_media:
        return False

    return target_body == probe_body


def configured_nikto_tuning() -> str:
    """Return BEACON's validated low-impact Nikto tuning profile."""

    tuning = settings.nikto_tuning.strip()

    permitted_categories = set("123b")

    if not tuning:
        raise NiktoScannerError(
            "The Nikto tuning profile is empty."
        )

    invalid_categories = sorted(
        set(tuning) - permitted_categories
    )

    if invalid_categories:
        raise NiktoScannerError(
            "The Nikto tuning profile contains prohibited "
            "categories: "
            + ", ".join(invalid_categories)
        )

    return "".join(
        character
        for character in "123b"
        if character in tuning
    )


def get_nikto_version() -> str:
    """Read the installed Nikto version."""

    command = [
        settings.nikto_binary,
        "-Version",
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
        raise NiktoScannerError(
            "The Nikto executable is unavailable."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise NiktoScannerError(
            "Nikto version detection timed out."
        ) from exc

    output = (
        result.stdout + result.stderr
    ).decode(
        "utf-8",
        errors="replace",
    ).strip()

    if result.returncode != 0:
        raise NiktoScannerError(
            "Nikto version detection failed"
            + (
                f": {output[:500]}"
                if output
                else "."
            )
        )

    first_line = (
        output.splitlines()[0].strip()
        if output
        else ""
    )

    if first_line.lower().startswith("nikto "):
        return first_line[6:].strip()

    return first_line or "unknown"


def parse_nikto_json(
    raw_json: bytes,
) -> tuple[
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
    str | None,
    list[NiktoFindingResult],
]:
    """Parse Nikto 2.6 structured JSON output."""

    try:
        decoded: Any = json.loads(
            raw_json.decode(
                "utf-8",
                errors="strict",
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise NiktoScannerError(
            "Nikto returned invalid JSON output."
        ) from exc

    if not isinstance(decoded, list):
        raise NiktoScannerError(
            "Nikto JSON must contain a top-level list."
        )

    if len(decoded) != 1:
        raise NiktoScannerError(
            "Nikto JSON must contain exactly one host record."
        )

    host_record = decoded[0]

    if not isinstance(host_record, dict):
        raise NiktoScannerError(
            "Nikto returned an invalid host record."
        )

    vulnerabilities = host_record.get(
        "vulnerabilities",
        [],
    )

    if not isinstance(vulnerabilities, list):
        raise NiktoScannerError(
            "Nikto returned an invalid vulnerabilities collection."
        )

    findings: list[NiktoFindingResult] = []

    for index, item in enumerate(
        vulnerabilities,
        start=1,
    ):
        if not isinstance(item, dict):
            raise NiktoScannerError(
                "Nikto returned an invalid vulnerability "
                f"record at position {index}."
            )

        finding_id = (
            non_empty_string(
                item.get("id")
            )
            or f"unknown-{index}"
        )

        method = (
            non_empty_string(
                item.get("method")
            )
            or "GET"
        ).upper()

        path = (
            non_empty_string(
                item.get("url")
            )
            or "/"
        )

        message = (
            non_empty_string(
                item.get("msg")
            )
            or "Nikto reported a web-server observation."
        )

        findings.append(
            NiktoFindingResult(
                finding_id=finding_id,
                method=method,
                path=path,
                message=message,
                references=normalize_references(
                    item.get("references")
                ),
            )
        )

    return (
        non_empty_string(
            host_record.get("host")
        ),
        non_empty_string(
            host_record.get("ip")
        ),
        optional_integer(
            host_record.get("port")
        ),
        non_empty_string(
            host_record.get("server_banner")
        ),
        non_empty_string(
            host_record.get("start_time")
        ),
        non_empty_string(
            host_record.get("end_time")
        ),
        findings,
    )


PROGRESS_PATTERN = re.compile(
    r"STATUS:\s+Completed\s+(?P<completed>\d+)\s+requests"
    r"(?:\s+\(~(?P<percent>\d+)%\s+complete[^)]*\))?",
    re.IGNORECASE,
)

SUMMARY_PATTERN = re.compile(
    r"(?P<requests>\d+)\s+requests:\s+"
    r"(?P<errors>\d+)\s+errors?\s+and\s+"
    r"(?P<items>\d+)\s+items?\s+reported",
    re.IGNORECASE,
)


def parse_nikto_progress(
    line: str,
) -> NiktoProgress | None:
    """Parse a user-safe progress line emitted by ``-Display P``."""

    match = PROGRESS_PATTERN.search(line)

    if match is None:
        return None

    completed_requests = int(
        match.group("completed")
    )

    percent_value = match.group(
        "percent"
    )

    percent = (
        int(percent_value)
        if percent_value is not None
        else None
    )

    estimated_total = None

    if percent and percent > 0:
        estimated_total = max(
            completed_requests,
            round(
                completed_requests
                / (percent / 100)
            ),
        )

    return NiktoProgress(
        completed_requests=completed_requests,
        percent=percent,
        estimated_total_requests=estimated_total,
        message=line.strip(),
    )


def parse_nikto_summary(
    console_output: str,
) -> tuple[int | None, int | None]:
    """Return final request and error counts when Nikto reports them."""

    matches = list(
        SUMMARY_PATTERN.finditer(
            console_output
        )
    )

    if not matches:
        return None, None

    match = matches[-1]

    return (
        int(match.group("requests")),
        int(match.group("errors")),
    )


def terminate_process(
    process: subprocess.Popen[bytes],
) -> None:
    """Terminate a child scanner process without leaving it behind."""

    if process.poll() is not None:
        return

    process.terminate()

    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_nikto_scan(
    target_url: str,
    progress_callback: Callable[
        [NiktoProgress],
        None,
    ] | None = None,
    cancellation_callback: Callable[
        [],
        bool,
    ] | None = None,
) -> NiktoScanResult:
    """Run BEACON's fixed, low-impact Nikto profile with live progress."""

    validated_target = validate_nikto_target_url(
        target_url
    )

    tuning = configured_nikto_tuning()
    scanner_version = get_nikto_version()
    soft_404_detected = detect_soft_404(
        validated_target
    )

    with TemporaryDirectory(
        prefix="beacon-nikto-"
    ) as temporary_directory:
        output_prefix = (
            Path(temporary_directory)
            / "nikto"
        )

        output_path = Path(
            f"{output_prefix}.json"
        )

        command = [
            settings.nikto_binary,
            "-host",
            validated_target,
            "-Format",
            "json",
            "-output",
            str(output_prefix),
            "-maxtime",
            f"{settings.nikto_max_time_seconds}s",
            "-timeout",
            str(
                settings.nikto_request_timeout_seconds
            ),
            "-Tuning",
            tuning,
            "-Cgidirs",
            "none",
            "-nointeractive",
            "-nocheck",
            "-Display",
            "P",
            "-useragent",
            settings.nikto_user_agent,
        ]

        environment = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
        }

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise NiktoScannerError(
                "The Nikto executable is unavailable."
            ) from exc

        if process.stdout is None:
            terminate_process(process)

            raise NiktoScannerError(
                "Nikto stdout could not be captured."
            )

        selector = selectors.DefaultSelector()
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
        )

        console_chunks: list[bytes] = []
        console_size = 0
        console_limit = min(
            settings.nikto_max_output_bytes,
            1_000_000,
        )
        line_buffer = b""
        deadline = (
            time.monotonic()
            + settings.nikto_process_timeout_seconds
        )

        def handle_line(
            raw_line: bytes,
        ) -> None:
            line = raw_line.decode(
                "utf-8",
                errors="replace",
            ).strip()

            if (
                not line
                or progress_callback is None
            ):
                return

            progress = parse_nikto_progress(
                line
            )

            if progress is None:
                return

            try:
                progress_callback(progress)
            except Exception:
                # Telemetry is best-effort. A database/UI update must
                # never interrupt the scanner itself.
                return

        try:
            while True:
                if (
                    cancellation_callback
                    is not None
                ):
                    try:
                        cancellation_requested = bool(
                            cancellation_callback()
                        )
                    except Exception:
                        terminate_process(
                            process
                        )
                        raise

                    if cancellation_requested:
                        terminate_process(
                            process
                        )

                        raise NiktoScannerError(
                            "The Nikto process "
                            "was cancelled."
                        )

                remaining = (
                    deadline
                    - time.monotonic()
                )

                if remaining <= 0:
                    terminate_process(process)

                    raise NiktoScannerError(
                        "The Nikto process exceeded its hard timeout."
                    )

                events = selector.select(
                    timeout=min(1.0, remaining)
                )

                if events:
                    chunk = os.read(
                        process.stdout.fileno(),
                        8192,
                    )

                    if chunk:
                        if console_size < console_limit:
                            allowed = (
                                console_limit
                                - console_size
                            )
                            stored = chunk[:allowed]
                            console_chunks.append(
                                stored
                            )
                            console_size += len(
                                stored
                            )

                        line_buffer += chunk

                        while b"\n" in line_buffer:
                            raw_line, line_buffer = (
                                line_buffer.split(
                                    b"\n",
                                    1,
                                )
                            )
                            handle_line(raw_line)

                        continue

                if process.poll() is not None:
                    trailing = os.read(
                        process.stdout.fileno(),
                        8192,
                    )

                    if trailing:
                        if console_size < console_limit:
                            allowed = (
                                console_limit
                                - console_size
                            )
                            stored = trailing[:allowed]
                            console_chunks.append(
                                stored
                            )
                            console_size += len(
                                stored
                            )

                        line_buffer += trailing
                        continue

                    break
        finally:
            selector.close()

        if line_buffer:
            handle_line(line_buffer)

        return_code = process.wait(timeout=5)

        console_output = b"".join(
            console_chunks
        ).decode(
            "utf-8",
            errors="replace",
        ).strip()

        if return_code != 0:
            raise NiktoScannerError(
                "Nikto exited unsuccessfully"
                + (
                    f": {console_output[-1500:]}"
                    if console_output
                    else "."
                )
            )

        if not output_path.is_file():
            raise NiktoScannerError(
                "Nikto did not create its JSON report."
            )

        output_size = output_path.stat().st_size

        if output_size <= 0:
            raise NiktoScannerError(
                "Nikto created an empty JSON report."
            )

        if (
            output_size
            > settings.nikto_max_output_bytes
        ):
            raise NiktoScannerError(
                "Nikto JSON output exceeded the configured "
                "size limit."
            )

        raw_json = output_path.read_bytes()

    (
        host,
        ip_address,
        port,
        server_banner,
        start_time,
        end_time,
        findings,
    ) = parse_nikto_json(
        raw_json
    )

    reached_max_time = (
        "maximum execution time"
        in console_output.lower()
    )

    (
        completed_requests,
        request_error_count,
    ) = parse_nikto_summary(
        console_output
    )

    return NiktoScanResult(
        scanner_version=scanner_version,
        command_summary=(
            "Low-impact web-server checks using "
            f"Nikto tuning profile {tuning}"
        ),
        target_url=validated_target,
        host=host,
        ip_address=ip_address,
        port=port,
        server_banner=server_banner,
        start_time=start_time,
        end_time=end_time,
        raw_json=raw_json,
        console_output=console_output,
        reached_max_time=reached_max_time,
        soft_404_detected=soft_404_detected,
        completed_requests=completed_requests,
        request_error_count=request_error_count,
        findings=findings,
    )

def _nikto_candidate_affected_url(
    target_url: str,
    reported_path: str,
) -> str:
    """Build an affected URL without allowing origin escape."""

    parsed = urlsplit(
        target_url
    )

    origin = urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/",
            "",
            "",
        )
    )

    candidate = urljoin(
        origin,
        reported_path or "/",
    )

    parsed_candidate = urlsplit(
        candidate
    )

    if (
        parsed_candidate.username is not None
        or parsed_candidate.password is not None
    ):
        return origin

    try:
        target_port = parsed.port
        candidate_port = parsed_candidate.port
    except ValueError:
        return origin

    if target_port is None:
        target_port = (
            443
            if parsed.scheme.lower() == "https"
            else 80
        )

    if candidate_port is None:
        candidate_port = (
            443
            if parsed_candidate.scheme.lower() == "https"
            else 80
        )

    if not (
        parsed_candidate.scheme.lower()
        == parsed.scheme.lower()
        and parsed_candidate.hostname
        == parsed.hostname
        and candidate_port
        == target_port
    ):
        return origin

    return candidate


def _nikto_candidate_severity(
    message: str,
) -> str:
    """Assign conservative source severity to one Nikto observation."""

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


def _nikto_candidate_remediation(
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

    if (
        "suggested security header missing"
        in normalized
    ):
        return (
            "Confirm whether the referenced security header is "
            "applicable, then configure it with a policy suitable "
            "for the application and test the application after "
            "deployment."
        )

    if (
        "access-control-allow-origin header: *"
        in normalized
    ):
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


def _nikto_detection_candidates(
    scan_result: NiktoScanResult,
) -> tuple[NiktoDetectionCandidate, ...]:
    """Convert Nikto results without creating canonical Finding rows."""

    candidates: list[
        NiktoDetectionCandidate
    ] = []

    for finding in scan_result.findings:
        message = (
            finding.message.strip()
            or "Nikto reported a web-server observation."
        )

        evidence: dict[str, Any] = {
            "nikto_id": finding.finding_id,
            "method": finding.method.upper(),
            "reported_path": finding.path,
            "message": message,
            "soft_404_detected": (
                scan_result.soft_404_detected
            ),
        }

        if finding.references:
            evidence["references"] = tuple(
                finding.references
            )

        candidates.append(
            NiktoDetectionCandidate(
                finding_id=finding.finding_id,
                title=message,
                severity=_nikto_candidate_severity(
                    message
                ),
                confidence=(
                    "low"
                    if (
                        scan_result.soft_404_detected
                        and finding.path
                        not in {
                            "",
                            "/",
                        }
                    )
                    else "medium"
                ),
                affected_url=(
                    _nikto_candidate_affected_url(
                        scan_result.target_url,
                        finding.path,
                    )
                ),
                affected_port=scan_result.port,
                method=finding.method.upper(),
                message=message,
                references=tuple(
                    finding.references
                ),
                remediation=(
                    _nikto_candidate_remediation(
                        message
                    )
                ),
                evidence=evidence,
            )
        )

    return tuple(
        candidates
    )


def run_nikto_assessment(
    *,
    profile_name: str,
    inventory: HTTPServiceInventory,
    progress_callback: Callable[
        [NiktoProgress],
        None,
    ] | None = None,
    cancellation_callback: Callable[
        [],
        bool,
    ] | None = None,
) -> NiktoAssessmentResult:
    """Run Nikto through the Engine v2 HTTP-service handoff."""

    profile = get_assessment_profile(
        profile_name
    )

    nikto_policy = profile.engines[
        "nikto"
    ]

    if not nikto_policy.enabled:
        return NiktoAssessmentResult()

    def run_service(
        service,
    ) -> NiktoScanResult:
        if cancellation_callback is None:
            return run_nikto_scan(
                service.url,
                progress_callback=(
                    progress_callback
                ),
            )

        return run_nikto_scan(
            service.url,
            progress_callback=(
                progress_callback
            ),
            cancellation_callback=(
                cancellation_callback
            ),
        )

    scan_results = tuple(
        run_service(
            service
        )
        for service
        in inventory.services
    )

    detection_candidates = tuple(
        candidate
        for scan_result in scan_results
        for candidate in _nikto_detection_candidates(
            scan_result
        )
    )

    return NiktoAssessmentResult(
        scan_results=scan_results,
        raw_evidence=tuple(
            scan_result.raw_json
            for scan_result in scan_results
        ),
        detection_candidates=(
            detection_candidates
        ),
    )


def store_nikto_json(
    scan_id: str,
    raw_json: bytes,
) -> str:
    """Store raw Nikto JSON and return its relative path."""

    root = Path(
        settings.raw_storage_path
    ).resolve()

    scan_directory = (
        root / scan_id
    ).resolve()

    try:
        scan_directory.relative_to(root)
    except ValueError as exc:
        raise NiktoScannerError(
            "The Nikto storage path is invalid."
        ) from exc

    scan_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        scan_directory / "nikto.json"
    )

    temporary_path = (
        scan_directory / "nikto.json.tmp"
    )

    temporary_path.write_bytes(
        raw_json
    )

    os.chmod(
        temporary_path,
        0o600,
    )

    os.replace(
        temporary_path,
        output_path,
    )

    return str(
        output_path.relative_to(root)
    )
