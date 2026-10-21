from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


CORRELATION_VERSION = "correlation-v2"


@dataclass(frozen=True)
class CorrelationInput:
    """Scanner-neutral input used only for correlation identity."""

    detection_id: str | None = None
    engine: str = ""
    rule_id: str | None = None
    title: str = ""
    canonical_type: str | None = None
    asset_identity: str | None = None
    affected_service: str | None = None
    affected_port: int | None = None
    affected_location: str | None = None
    affected_parameter: str | None = None
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    source_metadata: Mapping[str, object] | None = None


@dataclass(frozen=True)
class CorrelationDecisionResult:
    """Explainable pairwise correlation result."""

    strategy_version: str
    strategy: str
    decision: str
    reason: str
    candidate_identity: str | None
    confidence: str
    detection_a_id: str | None
    detection_b_id: str | None
    details: dict[str, object]


def _text(
    value: object,
) -> str:
    if value is None:
        return ""

    return str(
        value
    ).strip()


def _lower(
    value: object,
) -> str:
    return _text(
        value
    ).lower()


def _asset(
    value: object,
) -> str:
    return _lower(
        value
    )


def _service(
    value: object,
) -> str:
    return _lower(
        value
    )


def _rule(
    value: object,
) -> str:
    return _lower(
        value
    )


def _canonical_type(
    value: object,
) -> str:
    return (
        _lower(
            value
        )
        .replace("-", "_")
        .replace(" ", "_")
    )


def _location(
    value: object,
) -> str:
    raw = _text(
        value
    )

    if not raw:
        return ""

    try:
        parsed = urlsplit(
            raw
        )
    except ValueError:
        return raw

    if (
        not parsed.scheme
        or not parsed.netloc
    ):
        return raw

    host = (
        parsed.hostname or ""
    ).lower()

    if not host:
        return raw

    try:
        port = parsed.port
    except ValueError:
        return raw

    scheme = parsed.scheme.lower()

    default_port = (
        443
        if scheme == "https"
        else 80
        if scheme == "http"
        else None
    )

    netloc = host

    if (
        port is not None
        and port != default_port
    ):
        netloc = (
            f"{host}:{port}"
        )

    return urlunsplit(
        (
            scheme,
            netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _normalized_cves(
    value: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _text(
                    item
                ).upper()
                for item in value
                if _text(
                    item
                )
            }
        )
    )


def _normalized_cwes(
    value: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                _text(
                    item
                ).upper()
                for item in value
                if _text(
                    item
                )
            }
        )
    )


def _metadata_text(
    item: CorrelationInput,
    *keys: str,
) -> str:
    metadata = item.source_metadata

    if not isinstance(
        metadata,
        Mapping,
    ):
        return ""

    for key in keys:
        value = metadata.get(
            key
        )

        normalized = _text(
            value
        )

        if normalized:
            return normalized

    return ""


def _result(
    *,
    strategy: str,
    decision: str,
    reason: str,
    first: CorrelationInput,
    second: CorrelationInput,
    candidate_identity: str | None = None,
    confidence: str = "high",
    details: dict[str, object] | None = None,
) -> CorrelationDecisionResult:
    result_details = {
        "strategy": strategy,
    }

    if details:
        result_details.update(
            details
        )

    return CorrelationDecisionResult(
        strategy_version=CORRELATION_VERSION,
        strategy=strategy,
        decision=decision,
        reason=reason,
        candidate_identity=candidate_identity,
        confidence=confidence,
        detection_a_id=first.detection_id,
        detection_b_id=second.detection_id,
        details=result_details,
    )


class CVECorrelation:
    """Correlate one exact CVE on one exact service identity."""

    name = "CVECorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        first_cves = _normalized_cves(
            first.cve_ids
        )

        second_cves = _normalized_cves(
            second.cve_ids
        )

        if (
            len(first_cves) != 1
            or len(second_cves) != 1
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "CVE correlation requires exactly one "
                    "explicit CVE on each detection."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if first_cves != second_cves:
            return _result(
                strategy=self.name,
                decision="separate",
                reason="CVE identifiers differ.",
                first=first,
                second=second,
            )

        first_context = (
            _asset(
                first.asset_identity
            ),
            first.affected_port,
            _service(
                first.affected_service
            ),
        )

        second_context = (
            _asset(
                second.asset_identity
            ),
            second.affected_port,
            _service(
                second.affected_service
            ),
        )

        if (
            not first_context[0]
            or first_context[1] is None
            or not first_context[2]
            or not second_context[0]
            or second_context[1] is None
            or not second_context[2]
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "CVE correlation requires complete "
                    "asset and service context."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if first_context != second_context:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "CVE matches but asset or service context differs."
                ),
                first=first,
                second=second,
            )

        identity = (
            "cve|"
            f"{first_context[0]}|"
            f"{first_context[1]}|"
            f"{first_context[2]}|"
            f"{first_cves[0]}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same explicit CVE on the same asset and service context."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
            details={
                "cve": first_cves[0],
                "asset": first_context[0],
                "port": first_context[1],
                "service": first_context[2],
            },
        )


def _endpoint(
    value: object,
) -> str:
    """Normalize a web endpoint without volatile query values."""

    raw = _location(
        value
    )

    if not raw:
        return ""

    try:
        parsed = urlsplit(
            raw
        )
    except ValueError:
        return raw

    if (
        not parsed.scheme
        or not parsed.netloc
    ):
        return raw

    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            "",
            "",
        )
    )


def _weakness(
    item: CorrelationInput,
) -> str:
    explicit = _metadata_text(
        item,
        "weakness",
        "weakness_key",
        "canonical_weakness",
    )

    if explicit:
        return _lower(
            explicit
        )

    cwes = _normalized_cwes(
        item.cwe_ids
    )

    if len(cwes) == 1:
        return (
            f"cwe:{cwes[0]}"
        ).lower()

    return ""


class WebParameterCorrelation:
    """Correlate an exact weakness at one web method/endpoint/parameter."""

    name = "WebParameterCorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        if (
            _canonical_type(
                first.canonical_type
            ) != "web_parameter"
            or _canonical_type(
                second.canonical_type
            ) != "web_parameter"
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Both detections must explicitly be "
                    "web-parameter findings."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        fields_a = {
            "asset":
                _asset(
                    first.asset_identity
                ),
            "method":
                _metadata_text(
                    first,
                    "http_method",
                    "method",
                ).upper(),
            "endpoint":
                _endpoint(
                    first.affected_location
                ),
            "parameter":
                _text(
                    first.affected_parameter
                ),
            "weakness":
                _weakness(
                    first
                ),
        }

        fields_b = {
            "asset":
                _asset(
                    second.asset_identity
                ),
            "method":
                _metadata_text(
                    second,
                    "http_method",
                    "method",
                ).upper(),
            "endpoint":
                _endpoint(
                    second.affected_location
                ),
            "parameter":
                _text(
                    second.affected_parameter
                ),
            "weakness":
                _weakness(
                    second
                ),
        }

        missing = [
            key
            for key, value in fields_a.items()
            if not value
        ] + [
            key
            for key, value in fields_b.items()
            if not value
        ]

        if missing:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Web-parameter correlation requires "
                    "asset, method, endpoint, parameter, "
                    "and weakness."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        for key in (
            "asset",
            "method",
            "endpoint",
            "parameter",
            "weakness",
        ):
            if (
                fields_a[key]
                != fields_b[key]
            ):
                return _result(
                    strategy=self.name,
                    decision="separate",
                    reason=(
                        f"Web-parameter {key} differs."
                    ),
                    first=first,
                    second=second,
                )

        identity = (
            "web-parameter|"
            f"{fields_a['asset']}|"
            f"{fields_a['method']}|"
            f"{fields_a['endpoint']}|"
            f"{fields_a['parameter']}|"
            f"{fields_a['weakness']}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same weakness on the same web "
                "method, endpoint, and parameter."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
            details=fields_a,
        )


class HTTPHeaderCorrelation:
    """Correlate an exact canonical header weakness per application."""

    name = "HTTPHeaderCorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        if (
            _canonical_type(
                first.canonical_type
            ) != "http_header"
            or _canonical_type(
                second.canonical_type
            ) != "http_header"
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Both detections must explicitly be "
                    "HTTP-header findings."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        fields_a = {
            "asset":
                _asset(
                    first.asset_identity
                ),
            "header":
                _lower(
                    _metadata_text(
                        first,
                        "header_name",
                        "header",
                    )
                ),
            "weakness":
                _weakness(
                    first
                ),
        }

        fields_b = {
            "asset":
                _asset(
                    second.asset_identity
                ),
            "header":
                _lower(
                    _metadata_text(
                        second,
                        "header_name",
                        "header",
                    )
                ),
            "weakness":
                _weakness(
                    second
                ),
        }

        if not all(
            fields_a.values()
        ) or not all(
            fields_b.values()
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "HTTP-header correlation requires "
                    "application, header, and weakness identity."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if fields_a != fields_b:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Application, header, or header weakness differs."
                ),
                first=first,
                second=second,
            )

        identity = (
            "http-header|"
            f"{fields_a['asset']}|"
            f"{fields_a['header']}|"
            f"{fields_a['weakness']}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same canonical HTTP-header weakness "
                "on the same application."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
            details=fields_a,
        )


class TLSCorrelation:
    """Correlate an exact TLS weakness per host and port."""

    name = "TLSCorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        if (
            _canonical_type(
                first.canonical_type
            ) != "tls"
            or _canonical_type(
                second.canonical_type
            ) != "tls"
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Both detections must explicitly "
                    "be TLS findings."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        fields_a = {
            "asset":
                _asset(
                    first.asset_identity
                ),
            "port":
                first.affected_port,
            "weakness":
                _weakness(
                    first
                ),
        }

        fields_b = {
            "asset":
                _asset(
                    second.asset_identity
                ),
            "port":
                second.affected_port,
            "weakness":
                _weakness(
                    second
                ),
        }

        if (
            not fields_a["asset"]
            or fields_a["port"] is None
            or not fields_a["weakness"]
            or not fields_b["asset"]
            or fields_b["port"] is None
            or not fields_b["weakness"]
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "TLS correlation requires host, port, "
                    "and canonical weakness."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if fields_a != fields_b:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "TLS host, port, or weakness differs."
                ),
                first=first,
                second=second,
            )

        identity = (
            "tls|"
            f"{fields_a['asset']}|"
            f"{fields_a['port']}|"
            f"{fields_a['weakness']}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same TLS weakness on the same host and port."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
            details=fields_a,
        )


class ServiceConfigurationCorrelation:
    """Correlate exact service-configuration weaknesses."""

    name = "ServiceConfigurationCorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        if (
            _canonical_type(
                first.canonical_type
            ) != "service_configuration"
            or _canonical_type(
                second.canonical_type
            ) != "service_configuration"
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Both detections must explicitly be "
                    "service-configuration findings."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        fields_a = {
            "asset":
                _asset(
                    first.asset_identity
                ),
            "port":
                first.affected_port,
            "service":
                _service(
                    first.affected_service
                ),
            "weakness":
                _weakness(
                    first
                ),
        }

        fields_b = {
            "asset":
                _asset(
                    second.asset_identity
                ),
            "port":
                second.affected_port,
            "service":
                _service(
                    second.affected_service
                ),
            "weakness":
                _weakness(
                    second
                ),
        }

        if (
            not fields_a["asset"]
            or fields_a["port"] is None
            or not fields_a["service"]
            or not fields_a["weakness"]
            or not fields_b["asset"]
            or fields_b["port"] is None
            or not fields_b["service"]
            or not fields_b["weakness"]
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Service-configuration correlation "
                    "requires asset, port, service, and weakness."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if fields_a != fields_b:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Service configuration asset, port, "
                    "service, or weakness differs."
                ),
                first=first,
                second=second,
            )

        identity = (
            "service-config|"
            f"{fields_a['asset']}|"
            f"{fields_a['port']}|"
            f"{fields_a['service']}|"
            f"{fields_a['weakness']}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same service-configuration weakness "
                "on the same asset, port, and service."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
            details=fields_a,
        )


class GenericCorrelation:
    """Conservative same-engine fallback for exact scanner identity."""

    name = "GenericCorrelation"

    def decide(
        self,
        first: CorrelationInput,
        second: CorrelationInput,
    ) -> CorrelationDecisionResult:
        first_type = _canonical_type(
            first.canonical_type
        )

        second_type = _canonical_type(
            second.canonical_type
        )

        if (
            first_type
            and second_type
            and first_type != second_type
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason="Canonical detection types differ.",
                first=first,
                second=second,
            )

        engine_a = _lower(
            first.engine
        )
        engine_b = _lower(
            second.engine
        )

        rule_a = _rule(
            first.rule_id
        )
        rule_b = _rule(
            second.rule_id
        )

        asset_a = _asset(
            first.asset_identity
        )
        asset_b = _asset(
            second.asset_identity
        )

        if (
            not engine_a
            or not engine_b
            or not rule_a
            or not rule_b
            or not asset_a
            or not asset_b
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Generic correlation requires explicit "
                    "engine, rule, and asset identity."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if (
            engine_a != engine_b
            or rule_a != rule_b
            or asset_a != asset_b
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Generic scanner identity differs."
                ),
                first=first,
                second=second,
            )

        context_a = (
            _service(
                first.affected_service
            ),
            first.affected_port,
            _location(
                first.affected_location
            ),
            _text(
                first.affected_parameter
            ),
        )

        context_b = (
            _service(
                second.affected_service
            ),
            second.affected_port,
            _location(
                second.affected_location
            ),
            _text(
                second.affected_parameter
            ),
        )

        if not any(
            value not in {
                "",
                None,
            }
            for value in context_a
        ):
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Generic correlation requires explicit "
                    "service or location context."
                ),
                first=first,
                second=second,
                confidence="low",
            )

        if context_a != context_b:
            return _result(
                strategy=self.name,
                decision="separate",
                reason=(
                    "Generic scanner context differs."
                ),
                first=first,
                second=second,
            )

        identity = (
            "generic|"
            f"{engine_a}|"
            f"{rule_a}|"
            f"{asset_a}|"
            f"{context_a[0]}|"
            f"{context_a[1]}|"
            f"{context_a[2]}|"
            f"{context_a[3]}"
        )

        return _result(
            strategy=self.name,
            decision="merge",
            reason=(
                "Same scanner rule on the same asset "
                "and exact service/location context."
            ),
            first=first,
            second=second,
            candidate_identity=identity,
        )


_CVE_STRATEGY = CVECorrelation()
_WEB_PARAMETER_STRATEGY = WebParameterCorrelation()
_HTTP_HEADER_STRATEGY = HTTPHeaderCorrelation()
_TLS_STRATEGY = TLSCorrelation()
_SERVICE_CONFIGURATION_STRATEGY = (
    ServiceConfigurationCorrelation()
)
_GENERIC_STRATEGY = GenericCorrelation()


_STRATEGY_BY_TYPE = {
    "web_parameter":
        _WEB_PARAMETER_STRATEGY,
    "http_header":
        _HTTP_HEADER_STRATEGY,
    "tls":
        _TLS_STRATEGY,
    "service_configuration":
        _SERVICE_CONFIGURATION_STRATEGY,
}


def resolve_strategy(
    first: CorrelationInput,
    second: CorrelationInput,
):
    """Choose the strongest conservative strategy available."""

    if (
        _normalized_cves(
            first.cve_ids
        )
        or _normalized_cves(
            second.cve_ids
        )
    ):
        return _CVE_STRATEGY

    first_type = _canonical_type(
        first.canonical_type
    )

    second_type = _canonical_type(
        second.canonical_type
    )

    if (
        first_type
        and first_type == second_type
        and first_type
        in _STRATEGY_BY_TYPE
    ):
        return _STRATEGY_BY_TYPE[
            first_type
        ]

    if (
        first_type
        in _STRATEGY_BY_TYPE
        and not second_type
    ):
        return _STRATEGY_BY_TYPE[
            first_type
        ]

    if (
        second_type
        in _STRATEGY_BY_TYPE
        and not first_type
    ):
        return _STRATEGY_BY_TYPE[
            second_type
        ]

    return _GENERIC_STRATEGY


def decide_correlation(
    first: CorrelationInput,
    second: CorrelationInput,
) -> CorrelationDecisionResult:
    """Return one deterministic merge/separate decision."""

    strategy = resolve_strategy(
        first,
        second,
    )

    return strategy.decide(
        first,
        second,
    )



_LEGACY_ZAP_CANONICAL_RULES: dict[
    str,
    dict[str, str],
] = {
    "10038": {
        "issue_key":
            "missing-security-header:csp",
        "title":
            "Content Security Policy Header Missing",
        "cwe_id":
            "CWE-693",
    },
    "10035": {
        "issue_key":
            "missing-security-header:hsts",
        "title":
            "Strict Transport Security Header Missing",
        "cwe_id":
            "CWE-319",
    },
    "10021": {
        "issue_key":
            "missing-security-header:x-content-type-options",
        "title":
            "X-Content-Type-Options Header Missing",
        "cwe_id":
            "CWE-693",
    },
}


_LEGACY_NIKTO_HEADER_RULES: dict[
    str,
    dict[str, str],
] = {
    "content-security-policy": {
        "issue_key":
            "missing-security-header:csp",
        "title":
            "Content Security Policy Header Missing",
        "cwe_id":
            "CWE-693",
    },
    "strict-transport-security": {
        "issue_key":
            "missing-security-header:hsts",
        "title":
            "Strict Transport Security Header Missing",
        "cwe_id":
            "CWE-319",
    },
    "x-content-type-options": {
        "issue_key":
            "missing-security-header:x-content-type-options",
        "title":
            "X-Content-Type-Options Header Missing",
        "cwe_id":
            "CWE-693",
    },
    "permissions-policy": {
        "issue_key":
            "missing-security-header:permissions-policy",
        "title":
            "Permissions Policy Header Missing",
    },
    "referrer-policy": {
        "issue_key":
            "missing-security-header:referrer-policy",
        "title":
            "Referrer Policy Header Missing",
    },
}


_LEGACY_CORS_WILDCARD_RULE = {
    "issue_key":
        "cors:wildcard-origin",
    "title":
        "Overly Permissive CORS Policy",
}


def _legacy_has_wildcard_cors_evidence(
    finding,
) -> bool:
    evidence = getattr(
        finding,
        "evidence",
        None,
    )

    if not isinstance(
        evidence,
        dict,
    ):
        return False

    raw = evidence.get(
        "evidence"
    )

    if not isinstance(
        raw,
        str,
    ):
        return False

    normalized = (
        raw
        .strip()
        .lower()
        .replace(
            " ",
            "",
        )
    )

    return (
        normalized
        == "access-control-allow-origin:*"
    )


def _legacy_is_nikto_wildcard_cors(
    finding,
) -> bool:
    if (
        _lower(
            getattr(
                finding,
                "tool_name",
                "",
            )
        )
        != "nikto"
    ):
        return False

    title = _lower(
        getattr(
            finding,
            "title",
            "",
        )
    )

    return title == (
        "nikto: retrieved "
        "access-control-allow-origin "
        "header: *."
    )


def legacy_canonical_issue_for_finding(
    finding,
) -> dict[str, str] | None:
    """Return exact legacy canonical identity via correlation v2."""

    tool = _lower(
        getattr(
            finding,
            "tool_name",
            "",
        )
    )

    external_id = _text(
        getattr(
            finding,
            "external_finding_id",
            "",
        )
    )

    if tool == "zap":
        if (
            external_id == "10098"
            and _legacy_has_wildcard_cors_evidence(
                finding
            )
        ):
            return dict(
                _LEGACY_CORS_WILDCARD_RULE
            )

        mapping = (
            _LEGACY_ZAP_CANONICAL_RULES.get(
                external_id
            )
        )

        if mapping is None:
            return None

        return dict(
            mapping
        )

    if tool != "nikto":
        return None

    if _legacy_is_nikto_wildcard_cors(
        finding
    ):
        return dict(
            _LEGACY_CORS_WILDCARD_RULE
        )

    title = _lower(
        getattr(
            finding,
            "title",
            "",
        )
    )

    prefix = (
        "nikto: suggested security header missing:"
    )

    if not title.startswith(
        prefix
    ):
        return None

    header = (
        title[
            len(prefix):
        ]
        .strip()
        .rstrip(".")
    )

    mapping = (
        _LEGACY_NIKTO_HEADER_RULES.get(
            header
        )
    )

    if mapping is None:
        return None

    return dict(
        mapping
    )
