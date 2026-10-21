from dataclasses import dataclass
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.assessment.handoff import (
    WebEndpointInventory,
)
from app.assessment.scope import (
    host_is_within_exact_fqdn,
)
from app.assessment.zap_policy import (
    ZapPolicy,
    build_zap_scope_selection,
)
from app.config import settings


class ZapScannerError(RuntimeError):
    """Raised when ZAP cannot complete a scan."""


@dataclass(frozen=True)
class ZapScanResult:
    """Raw result returned by the passive ZAP workflow."""

    version: str
    spider_scan_id: str
    alerts: list[dict[str, Any]]


@dataclass(frozen=True)
class ZapAssessmentRequest:
    """Engine v2 input for one governed ZAP assessment."""

    authorized_host: str
    web_inventory: WebEndpointInventory
    policy_version: str
    active_scan_enabled: bool

    active_policy: ZapPolicy | None = None
    execution_id: str | None = None


@dataclass(frozen=True)
class ZapAssessmentResult:
    """Engine v2 result from one governed ZAP assessment."""

    version: str
    policy_version: str
    active_scan_enabled: bool

    included_endpoint_count: int
    excluded_endpoint_count: int

    spider_scan_ids: tuple[str, ...]
    raw_alerts: tuple[dict[str, Any], ...]
    detections: tuple["ZapDetectionCandidate", ...]


@dataclass(frozen=True)
class ZapDetectionCandidate:
    """Scanner-neutral candidate parsed from one ZAP alert."""

    plugin_id: str | None
    title: str
    severity: str
    confidence: str | None
    affected_url: str
    cwe_id: str | None

    http_method: str | None
    parameter: str | None
    evidence: str | None
    attack: str | None
    description: str | None
    remediation: str | None
    reference: str | None
    message_id: str | None
    source_id: str | None
    wasc_id: str | None


def _optional_text(
    value: object,
) -> str | None:
    if value is None:
        return None

    text = str(value).strip()

    return text or None


def _normalize_zap_severity(
    value: object,
) -> str:
    normalized = (
        _optional_text(value)
        or "informational"
    ).lower()

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


def _zap_alert_is_in_scope(
    *,
    url: str,
    authorized_host: str,
) -> bool:
    parsed = urlsplit(
        url
    )

    return (
        parsed.scheme.lower() in {
            "http",
            "https",
        }
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and host_is_within_exact_fqdn(
            parsed.hostname,
            authorized_host,
        )
    )


def _zap_origin(
    url: str,
) -> str:
    """Return one deterministic HTTP origin seed."""

    parsed = urlsplit(
        url
    )

    if (
        parsed.scheme.lower()
        not in {
            "http",
            "https",
        }
        or parsed.hostname is None
    ):
        raise ZapScannerError(
            "Authorized ZAP endpoint has an invalid HTTP URL."
        )

    host = (
        parsed.hostname
        .strip()
        .rstrip(".")
        .lower()
    )

    try:
        port = parsed.port
    except ValueError as exc:
        raise ZapScannerError(
            "Authorized ZAP endpoint contains an invalid port."
        ) from exc

    scheme = parsed.scheme.lower()

    default_port = (
        443
        if scheme == "https"
        else 80
    )

    if (
        port is None
        or port == default_port
    ):
        authority = host
    else:
        authority = (
            f"{host}:{port}"
        )

    return (
        f"{scheme}://"
        f"{authority}/"
    )


def parse_zap_alerts(
    *,
    alerts: list[dict[str, Any]],
    authorized_host: str,
) -> tuple[ZapDetectionCandidate, ...]:
    """Parse in-scope ZAP alerts into Engine v2 candidates."""

    candidates: list[
        ZapDetectionCandidate
    ] = []

    for alert in alerts:
        affected_url = _optional_text(
            alert.get("url")
        )

        if affected_url is None:
            continue

        if not _zap_alert_is_in_scope(
            url=affected_url,
            authorized_host=authorized_host,
        ):
            continue

        cwe_value = _optional_text(
            alert.get("cweid")
        )

        if cwe_value in {
            None,
            "0",
            "-1",
        }:
            cwe_id = None
        else:
            cwe_id = (
                f"CWE-{cwe_value}"
            )

        severity = _normalize_zap_severity(
            alert.get("risk")
        )

        confidence_value = _optional_text(
            alert.get("confidence")
        )

        candidates.append(
            ZapDetectionCandidate(
                plugin_id=_optional_text(
                    alert.get("pluginId")
                ),
                title=(
                    _optional_text(
                        alert.get("alert")
                    )
                    or "ZAP security observation"
                ),
                severity=severity,
                confidence=(
                    confidence_value.lower()
                    if confidence_value
                    else None
                ),
                affected_url=affected_url,
                cwe_id=cwe_id,
                http_method=_optional_text(
                    alert.get("method")
                ),
                parameter=_optional_text(
                    alert.get("param")
                ),
                evidence=_optional_text(
                    alert.get("evidence")
                ),
                attack=_optional_text(
                    alert.get("attack")
                ),
                description=_optional_text(
                    alert.get("description")
                ),
                remediation=_optional_text(
                    alert.get("solution")
                ),
                reference=_optional_text(
                    alert.get("reference")
                ),
                message_id=_optional_text(
                    alert.get("messageId")
                ),
                source_id=_optional_text(
                    alert.get("sourceid")
                ),
                wasc_id=_optional_text(
                    alert.get("wascid")
                ),
            )
        )

    return tuple(
        candidates
    )


class ZapClient:
    """Small controlled client for BEACON's internal ZAP daemon."""

    def __init__(self) -> None:
        self.base_url = settings.zap_api_url.rstrip("/")
        self.api_key = settings.zap_api_key

        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(30.0),
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "BEACON-ZAP-Orchestrator/0.1",
                "Accept": "application/json",
                "X-ZAP-API-Key": self.api_key,
            },
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""

        self.client.close()

    def __enter__(self) -> "ZapClient":
        return self

    def __exit__(
        self,
        exception_type: object,
        exception_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def _request(
        self,
        path: str,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        """Send one request to the internal ZAP API."""

        request_parameters: dict[str, object] = {}

        if parameters:
            request_parameters.update(parameters)

        try:
            response = self.client.get(
                path,
                params=request_parameters,
            )

            response.raise_for_status()
            data = response.json()
        except (
            httpx.HTTPError,
            ValueError,
        ) as exc:
            raise ZapScannerError(
                f"ZAP API request failed for {path}."
            ) from exc

        if not isinstance(data, dict):
            raise ZapScannerError(
                "ZAP returned an unexpected response."
            )

        if "code" in data and "message" in data:
            raise ZapScannerError(
                f"ZAP error: {data.get('message')} "
                f"({data.get('code')})."
            )

        return data

    def wait_until_ready(self) -> str:
        """Wait until the ZAP daemon starts accepting API requests."""

        deadline = (
            time.monotonic()
            + settings.zap_startup_timeout_seconds
        )

        last_error: Exception | None = None

        while time.monotonic() < deadline:
            try:
                response = self._request(
                    "/JSON/core/view/version/"
                )

                version = str(response.get("version", "")).strip()

                if version:
                    return version
            except ZapScannerError as exc:
                last_error = exc

            time.sleep(
                settings.zap_poll_interval_seconds
            )

        raise ZapScannerError(
            "ZAP did not become ready before the startup timeout."
        ) from last_error

    def start_new_session(
        self,
        session_name: str | None = None,
    ) -> None:
        """Create a fresh ZAP session."""

        self._request(
            "/JSON/core/action/newSession/",
            {
                "name": (
                    session_name
                    if session_name is not None
                    else ""
                ),
                "overwrite": "true",
            },
        )

    def access_target(self, target_url: str) -> None:
        """Send the initial request through ZAP."""

        self._request(
            "/JSON/core/action/accessUrl/",
            {
                "url": target_url,
                "followRedirects": "false",
            },
        )

    def start_spider(self, target_url: str) -> str:
        """Start a traditional spider restricted to the target subtree."""

        response = self._request(
            "/JSON/spider/action/scan/",
            {
                "url": target_url,
                "recurse": "true",
                "subtreeOnly": "true",
            },
        )

        scan_id = str(response.get("scan", "")).strip()

        if not scan_id:
            raise ZapScannerError(
                "ZAP did not return a spider scan identifier."
            )

        return scan_id

    def wait_for_spider(self, scan_id: str) -> None:
        """Wait for the ZAP spider to finish."""

        deadline = (
            time.monotonic()
            + settings.zap_spider_timeout_seconds
        )

        while time.monotonic() < deadline:
            response = self._request(
                "/JSON/spider/view/status/",
                {
                    "scanId": scan_id,
                },
            )

            try:
                progress = int(response.get("status", 0))
            except (TypeError, ValueError):
                progress = 0

            if progress >= 100:
                return

            time.sleep(
                settings.zap_poll_interval_seconds
            )

        try:
            self._request(
                "/JSON/spider/action/stop/",
                {
                    "scanId": scan_id,
                },
            )
        except ZapScannerError:
            pass

        raise ZapScannerError(
            "The ZAP spider exceeded its configured timeout."
        )

    def wait_for_passive_scan(self) -> None:
        """Wait until ZAP's passive-scanning queue is empty."""

        deadline = (
            time.monotonic()
            + settings.zap_passive_scan_timeout_seconds
        )

        while time.monotonic() < deadline:
            response = self._request(
                "/JSON/pscan/view/recordsToScan/"
            )

            try:
                remaining = int(
                    response.get("recordsToScan", 0)
                )
            except (TypeError, ValueError):
                remaining = 0

            if remaining == 0:
                return

            time.sleep(
                settings.zap_poll_interval_seconds
            )

        raise ZapScannerError(
            "ZAP passive scanning exceeded its configured timeout."
        )

    def get_alerts(
        self,
        target_url: str,
    ) -> list[dict[str, Any]]:
        """Retrieve alerts belonging to the scanned target."""

        response = self._request(
            "/JSON/core/view/alerts/",
            {
                "baseurl": target_url,
                "start": 0,
                "count": 5000,
            },
        )

        alerts = response.get("alerts", [])

        if not isinstance(alerts, list):
            raise ZapScannerError(
                "ZAP returned an invalid alerts collection."
            )

        return [
            alert
            for alert in alerts
            if isinstance(alert, dict)
        ]

    def wait_for_active_scan(
        self,
        *,
        scan_id: str,
        timeout_seconds: float | None = None,
    ) -> None:
        """Wait for active-scan completion within a wall-clock bound."""

        timeout = (
            settings.zap_active_scan_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )

        if timeout <= 0:
            raise ZapScannerError(
                "ZAP active-scan timeout must "
                "be greater than zero."
            )

        started_at = time.monotonic()

        while True:
            response = self._request(
                "/JSON/ascan/view/status/",
                {
                    "scanId": scan_id,
                },
            )

            status = _optional_text(
                response.get("status")
            )

            try:
                progress = (
                    int(status)
                    if status is not None
                    else None
                )
            except ValueError:
                progress = None

            if (
                progress is None
                or progress < 0
                or progress > 100
            ):
                raise ZapScannerError(
                    "ZAP returned an invalid "
                    "active-scan status."
                )

            if progress == 100:
                return

            if (
                time.monotonic()
                - started_at
                >= timeout
            ):
                try:
                    self._request(
                        "/JSON/ascan/action/stop/",
                        {
                            "scanId": scan_id,
                        },
                    )
                except Exception:
                    pass

                raise ZapScannerError(
                    "ZAP active scan timed out."
                )

            time.sleep(
                settings.zap_poll_interval_seconds
            )

    def start_active_scan(
        self,
        *,
        target_url: str,
        authorized_host: str,
        context_id: str,
        scan_policy_name: str,
        policy: ZapPolicy,
    ) -> str:
        """Start one governed ZAP active scan."""

        if (
            not policy.active_scan_enabled
            or not policy.active_rules
        ):
            raise ZapScannerError(
                "ZAP active scanning is disabled "
                "for this assessment policy."
            )

        normalized_target = (
            target_url.strip()
        )

        if not _zap_alert_is_in_scope(
            url=normalized_target,
            authorized_host=authorized_host,
        ):
            raise ZapScannerError(
                "The ZAP active-scan target is "
                "outside the authorized scope."
            )

        normalized_context_id = (
            context_id.strip()
        )

        if not normalized_context_id:
            raise ZapScannerError(
                "A valid ZAP context ID is required "
                "for active scanning."
            )

        normalized_policy_name = (
            scan_policy_name.strip()
        )

        if not normalized_policy_name:
            raise ZapScannerError(
                "A named ZAP active-scan policy "
                "is required."
            )

        response = self._request(
            "/JSON/ascan/action/scan/",
            {
                "url": normalized_target,
                "recurse": "true",
                "inScopeOnly": "true",
                "scanPolicyName": (
                    normalized_policy_name
                ),
                "contextId": (
                    normalized_context_id
                ),
            },
        )

        scan_id = _optional_text(
            response.get("scan")
        )

        if scan_id is None:
            raise ZapScannerError(
                "ZAP did not return an active-scan ID."
            )

        return scan_id

    def create_assessment_context(
        self,
        *,
        context_name: str,
        authorized_host: str,
        origins: tuple[str, ...],
    ) -> str:
        """Create one fresh exact-origin ZAP assessment context."""

        normalized_name = (
            context_name.strip()
        )

        if not normalized_name:
            raise ZapScannerError(
                "A named authorized ZAP context is required."
            )

        if not origins:
            raise ZapScannerError(
                "The assessment has no authorized ZAP context origins."
            )

        include_regexes: list[str] = []

        for origin in origins:
            if not _zap_alert_is_in_scope(
                url=origin,
                authorized_host=authorized_host,
            ):
                raise ZapScannerError(
                    "An origin is outside the authorized ZAP context."
                )

            parsed = urlsplit(
                origin
            )

            scheme = parsed.scheme.lower()

            host = (
                parsed.hostname
                .strip()
                .rstrip(".")
                .lower()
            )

            try:
                port = parsed.port
            except ValueError as exc:
                raise ZapScannerError(
                    "An origin has an invalid authorized "
                    "ZAP context port."
                ) from exc

            default_port = (
                443
                if scheme == "https"
                else 80
            )

            if (
                port is None
                or port == default_port
            ):
                authority = host
            else:
                authority = (
                    f"{host}:{port}"
                )

            normalized_origin = (
                f"{scheme}://"
                f"{authority}"
            )

            include_regex = (
                "^"
                + re.escape(
                    normalized_origin
                )
                + r"(?:/.*)?$"
            )

            if include_regex not in include_regexes:
                include_regexes.append(
                    include_regex
                )

        response = self._request(
            "/JSON/context/action/newContext/",
            {
                "contextName": normalized_name,
            },
        )

        context_id = _optional_text(
            response.get("contextId")
        )

        if context_id is None:
            raise ZapScannerError(
                "ZAP did not return a context ID "
                "for the assessment context."
            )

        for include_regex in include_regexes:
            self._request(
                (
                    "/JSON/context/action/"
                    "includeInContext/"
                ),
                {
                    "contextName": normalized_name,
                    "regex": include_regex,
                },
            )

        self._request(
            (
                "/JSON/context/action/"
                "setContextInScope/"
            ),
            {
                "contextName": normalized_name,
                "booleanInScope": "true",
            },
        )

        return context_id

    def configure_active_scan_limits(
        self,
        *,
        policy: ZapPolicy,
    ) -> None:
        """Apply bounded daemon-level limits for active scanning."""

        if (
            not policy.active_scan_enabled
            or not policy.active_rules
        ):
            raise ZapScannerError(
                "ZAP active scanning is disabled "
                "for this assessment policy."
            )

        self._request(
            (
                "/JSON/ascan/action/"
                "setOptionMaxRuleDurationInMins/"
            ),
            {
                "Integer": (
                    policy.max_rule_duration_minutes
                ),
            },
        )

        self._request(
            (
                "/JSON/ascan/action/"
                "setOptionMaxScanDurationInMins/"
            ),
            {
                "Integer": (
                    policy.max_scan_duration_minutes
                ),
            },
        )

        self._request(
            (
                "/JSON/ascan/action/"
                "setOptionMaxAlertsPerRule/"
            ),
            {
                "Integer": (
                    policy.max_alerts_per_rule
                ),
            },
        )

    def configure_active_scan_policy(
        self,
        *,
        scan_policy_name: str,
        policy: ZapPolicy,
    ) -> None:
        """Configure one closed BEACON active-scan policy."""

        if (
            not policy.active_scan_enabled
            or not policy.active_rules
        ):
            raise ZapScannerError(
                "ZAP active scanning is disabled "
                "for this assessment policy."
            )

        normalized_name = (
            scan_policy_name.strip()
        )

        if not normalized_name:
            raise ZapScannerError(
                "A named ZAP active-scan policy is required."
            )

        self._request(
            "/JSON/ascan/action/addScanPolicy/",
            {
                "scanPolicyName": normalized_name,
                "alertThreshold": (
                    policy.default_alert_threshold
                ),
                "attackStrength": (
                    policy.default_attack_strength
                ),
            },
        )

        # Defense in depth:
        # explicitly disable the full installed scanner
        # universe before enabling BEACON's closed allowlist.
        self._request(
            "/JSON/ascan/action/disableAllScanners/",
            {
                "scanPolicyName": normalized_name,
            },
        )

        approved_ids = ",".join(
            str(rule.rule_id)
            for rule in policy.active_rules
        )

        self._request(
            "/JSON/ascan/action/enableScanners/",
            {
                "ids": approved_ids,
                "scanPolicyName": normalized_name,
            },
        )

        for rule in policy.active_rules:
            self._request(
                (
                    "/JSON/ascan/action/"
                    "setScannerAlertThreshold/"
                ),
                {
                    "id": str(rule.rule_id),
                    "alertThreshold": (
                        rule.alert_threshold
                    ),
                    "scanPolicyName": normalized_name,
                },
            )

            self._request(
                (
                    "/JSON/ascan/action/"
                    "setScannerAttackStrength/"
                ),
                {
                    "id": str(rule.rule_id),
                    "attackStrength": (
                        rule.attack_strength
                    ),
                    "scanPolicyName": normalized_name,
                },
            )

    def run_assessment(
        self,
        request: ZapAssessmentRequest,
    ) -> ZapAssessmentResult:
        """Run one governed Engine v2 ZAP assessment."""

        if (
            request.active_scan_enabled
            and request.active_policy is None
        ):
            raise ZapScannerError(
                "Active assessment requires "
                "a resolved ZAP policy."
            )

        normalized_execution_id = (
            (request.execution_id or "").strip()
            if request.active_scan_enabled
            else ""
        )

        if (
            request.active_scan_enabled
            and not normalized_execution_id
        ):
            raise ZapScannerError(
                "Active assessment requires "
                "a nonempty execution ID."
            )

        scope = build_zap_scope_selection(
            authorized_host=request.authorized_host,
            inventory=request.web_inventory,
        )

        if not scope.included_endpoints:
            raise ZapScannerError(
                "The assessment has no authorized ZAP scope."
            )

        origins: list[str] = []

        for endpoint in scope.included_endpoints:
            origin = _zap_origin(
                endpoint.url
            )

            if origin not in origins:
                origins.append(
                    origin
                )

        version = self.wait_until_ready()

        if request.active_scan_enabled:
            self.start_new_session(
                session_name=(
                    f"beacon-{normalized_execution_id}"
                )
            )
        else:
            self.start_new_session()

        spider_scan_ids: list[str] = []

        for origin in origins:
            self.access_target(
                origin
            )

            spider_scan_id = self.start_spider(
                origin
            )

            spider_scan_ids.append(
                spider_scan_id
            )

            self.wait_for_spider(
                spider_scan_id
            )

        self.wait_for_passive_scan()

        if request.active_scan_enabled:
            policy = request.active_policy

            if policy is None:
                raise ZapScannerError(
                    "Active assessment requires "
                    "a resolved ZAP policy."
                )

            context_name = (
                f"beacon-{normalized_execution_id}"
            )

            scan_policy_name = (
                f"{context_name}-"
                f"{policy.profile_name}"
            )

            context_id = (
                self.create_assessment_context(
                    context_name=context_name,
                    authorized_host=(
                        request.authorized_host
                    ),
                    origins=tuple(origins),
                )
            )

            self.configure_active_scan_policy(
                scan_policy_name=(
                    scan_policy_name
                ),
                policy=policy,
            )

            self.configure_active_scan_limits(
                policy=policy,
            )

            for origin in origins:
                active_scan_id = (
                    self.start_active_scan(
                        target_url=origin,
                        authorized_host=(
                            request.authorized_host
                        ),
                        context_id=context_id,
                        scan_policy_name=(
                            scan_policy_name
                        ),
                        policy=policy,
                    )
                )

                self.wait_for_active_scan(
                    scan_id=active_scan_id,
                )

            self.wait_for_passive_scan()

        raw_alerts: list[
            dict[str, Any]
        ] = []

        for origin in origins:
            raw_alerts.extend(
                self.get_alerts(
                    origin
                )
            )

        detections = parse_zap_alerts(
            alerts=raw_alerts,
            authorized_host=request.authorized_host,
        )

        return ZapAssessmentResult(
            version=version,
            policy_version=request.policy_version,
            active_scan_enabled=(
                request.active_scan_enabled
            ),
            included_endpoint_count=len(
                scope.included_endpoints
            ),
            excluded_endpoint_count=len(
                scope.excluded_endpoints
            ),
            spider_scan_ids=tuple(
                spider_scan_ids
            ),
            raw_alerts=tuple(
                raw_alerts
            ),
            detections=detections,
        )

    def run_passive_scan(
        self,
        target_url: str,
    ) -> ZapScanResult:
        """Run BEACON's initial non-active ZAP workflow."""

        version = self.wait_until_ready()

        self.start_new_session()
        self.access_target(target_url)

        spider_scan_id = self.start_spider(
            target_url
        )

        self.wait_for_spider(
            spider_scan_id
        )

        self.wait_for_passive_scan()

        alerts = self.get_alerts(
            target_url
        )

        return ZapScanResult(
            version=version,
            spider_scan_id=spider_scan_id,
            alerts=alerts,
        )
