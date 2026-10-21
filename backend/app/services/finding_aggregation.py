from collections import Counter
from hashlib import sha256
from typing import Any

from app.assessment import correlation as correlation_v2
from app.models.finding import Finding


SEVERITY_LEVELS = [
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]

SEVERITY_RANK = {
    severity: len(SEVERITY_LEVELS) - index
    for index, severity in enumerate(SEVERITY_LEVELS)
}


ISSUE_CLASSIFICATIONS = [
    "security_issue",
    "attack_surface",
    "observation",
    "limitation",
]


NIKTO_OBSERVATION_RULE_IDS = {
    "001675",
    "001811",
    "999100",
    "999106",
    "999996",
}


NIKTO_LIMITATION_RULE_IDS = {
    "011799",
}


ZAP_OBSERVATION_RULE_IDS = {
    "10109",
}


def external_rule_base(
    external_finding_id: str,
) -> str:
    """Return the stable scanner rule portion of an external ID."""

    normalized = (
        external_finding_id
        or ""
    ).strip()

    if not normalized:
        return ""

    return normalized.split(
        "-",
        1,
    )[0]


def classify_issue(
    *,
    issue_key: str,
    sources: list[dict[str, Any]],
) -> str:
    """Classify one correlated BEACON result by security meaning."""

    normalized_key = (
        issue_key
        or ""
    ).strip().lower()

    # Nmap open-service observations describe exposed attack
    # surface. They are not vulnerabilities by themselves.
    if normalized_key.startswith(
        "nmap:tcp-"
    ):
        return "attack_surface"

    for source in sources:
        tool_name = (
            str(
                source.get(
                    "tool_name",
                    "",
                )
            )
            .strip()
            .lower()
        )

        external_ids = source.get(
            "external_finding_ids",
            [],
        )

        for external_id in external_ids:
            rule_id = external_rule_base(
                str(external_id)
            )

            if (
                tool_name == "nikto"
                and rule_id
                in NIKTO_LIMITATION_RULE_IDS
            ):
                return "limitation"

            if (
                tool_name == "nikto"
                and rule_id
                in NIKTO_OBSERVATION_RULE_IDS
            ):
                return "observation"

            if (
                tool_name == "zap"
                and rule_id
                in ZAP_OBSERVATION_RULE_IDS
            ):
                return "observation"

    # Conservative fallback: an unknown scanner result stays in
    # the security posture until BEACON explicitly classifies it.
    return "security_issue"


ZAP_CANONICAL_RULES: dict[
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


CORS_WILDCARD_CANONICAL_RULE = {
    "issue_key":
        "cors:wildcard-origin",
    "title":
        "Overly Permissive CORS Policy",
}


def has_wildcard_cors_evidence(
    finding: Finding,
) -> bool:
    """Return whether evidence explicitly proves ACAO wildcard use."""

    evidence = getattr(
        finding,
        "evidence",
        None,
    )

    evidence_text = ""

    if isinstance(evidence, dict):
        raw_evidence = evidence.get(
            "evidence"
        )

        if isinstance(
            raw_evidence,
            str,
        ):
            evidence_text = (
                raw_evidence
            )

    normalized = (
        evidence_text
        .strip()
        .lower()
        .replace(" ", "")
    )

    return (
        normalized
        == "access-control-allow-origin:*"
    )


def is_nikto_wildcard_cors(
    finding: Finding,
) -> bool:
    """Return whether Nikto explicitly reported wildcard ACAO."""

    if (
        finding.tool_name
        .strip()
        .lower()
        != "nikto"
    ):
        return False

    normalized_title = (
        finding.title
        or ""
    ).strip().lower()

    return (
        normalized_title
        == (
            "nikto: retrieved "
            "access-control-allow-origin "
            "header: *."
        )
    )


NIKTO_MISSING_HEADER_RULES: dict[
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


def normalize_severity(
    value: str | None,
) -> str:
    """Normalize a stored severity value."""

    normalized = (
        value or "informational"
    ).strip().lower()

    if normalized not in SEVERITY_RANK:
        return "informational"

    return normalized


def confidence_rank(
    value: str | None,
) -> int:
    """Return a comparable scanner-confidence rank."""

    if value is None:
        return 0

    normalized = value.strip().lower()

    named_ranks = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    if normalized in named_ranks:
        return named_ranks[normalized]

    try:
        numeric_value = float(
            normalized
        )
    except ValueError:
        return 0

    if numeric_value >= 8:
        return 3

    if numeric_value >= 5:
        return 2

    if numeric_value > 0:
        return 1

    return 0


def canonical_issue_for_finding(
    finding: Finding,
) -> dict[str, str] | None:
    """Return an exact canonical mapping through correlation v2."""

    return (
        correlation_v2
        .legacy_canonical_issue_for_finding(
            finding
        )
    )


def build_issue_key(
    finding: Finding,
) -> str:
    """Build a stable identifier for a grouped security issue."""

    canonical_issue = (
        canonical_issue_for_finding(
            finding
        )
    )

    if canonical_issue is not None:
        return canonical_issue[
            "issue_key"
        ]

    tool_name = (
        finding.tool_name
        .strip()
        .lower()
    )

    if finding.external_finding_id:
        rule_identifier = (
            finding.external_finding_id
            .strip()
        )
    else:
        normalized_title = (
            finding.title
            .strip()
            .lower()
        )

        rule_identifier = sha256(
            normalized_title.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

    return (
        f"{tool_name}:"
        f"{rule_identifier}"
    )


def requires_manual_validation(
    finding: Finding,
) -> bool:
    """Detect explicit validation requirements in evidence text."""

    searchable_values = [
        finding.title,
        finding.description,
        finding.remediation,
    ]

    text = " ".join(
        value
        for value in searchable_values
        if isinstance(value, str)
    ).lower()

    indicators = (
        "manual validation",
        "manually validate",
        "requires manual",
        "should be manually viewed",
    )

    return any(
        indicator in text
        for indicator in indicators
    )


def aggregate_findings(
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """Correlate raw scanner observations into BEACON issues."""

    groups: dict[
        str,
        dict[str, Any],
    ] = {}

    for finding in findings:
        canonical_issue = (
            canonical_issue_for_finding(
                finding
            )
        )

        issue_key = build_issue_key(
            finding
        )

        severity = normalize_severity(
            finding.severity
        )

        canonical_title = (
            canonical_issue["title"]
            if canonical_issue
            else finding.title
        )

        canonical_cwe = (
            canonical_issue.get(
                "cwe_id"
            )
            if canonical_issue
            else None
        )

        if issue_key not in groups:
            groups[issue_key] = {
                "issue_key":
                    issue_key,
                "tool_name":
                    finding.tool_name,
                "external_finding_id":
                    finding.external_finding_id,
                "title":
                    canonical_title,
                "severity":
                    severity,
                "confidence":
                    finding.confidence,
                "cwe_id":
                    canonical_cwe
                    or finding.cwe_id,
                "description":
                    finding.description,
                "remediation":
                    finding.remediation,
                "occurrence_count":
                    0,
                "requires_manual_validation":
                    False,
                "_affected_urls":
                    set(),
                "_sources":
                    {},
            }

        group = groups[
            issue_key
        ]

        group[
            "occurrence_count"
        ] += 1

        if (
            SEVERITY_RANK[
                severity
            ]
            >
            SEVERITY_RANK[
                str(
                    group["severity"]
                )
            ]
        ):
            group[
                "severity"
            ] = severity

        if (
            confidence_rank(
                finding.confidence
            )
            >
            confidence_rank(
                group["confidence"]
            )
        ):
            group[
                "confidence"
            ] = finding.confidence

        if finding.affected_url:
            group[
                "_affected_urls"
            ].add(
                finding.affected_url
            )

        if (
            group["description"] is None
            and finding.description
            is not None
        ):
            group[
                "description"
            ] = finding.description

        if (
            group["remediation"] is None
            and finding.remediation
            is not None
        ):
            group[
                "remediation"
            ] = finding.remediation

        if (
            group["cwe_id"] is None
            and finding.cwe_id
            is not None
        ):
            group[
                "cwe_id"
            ] = finding.cwe_id

        if requires_manual_validation(
            finding
        ):
            group[
                "requires_manual_validation"
            ] = True

        normalized_tool_name = (
            finding.tool_name
            .strip()
            .lower()
        )

        source = group[
            "_sources"
        ].setdefault(
            normalized_tool_name,
            {
                "tool_name":
                    finding.tool_name,
                "external_finding_ids":
                    set(),
                "occurrence_count":
                    0,
            },
        )

        source[
            "occurrence_count"
        ] += 1

        if finding.external_finding_id:
            source[
                "external_finding_ids"
            ].add(
                finding.external_finding_id
            )

    aggregated: list[
        dict[str, Any]
    ] = []

    for group in groups.values():
        affected_urls = sorted(
            group.pop(
                "_affected_urls"
            )
        )

        group[
            "affected_url_count"
        ] = len(
            affected_urls
        )

        group[
            "sample_affected_urls"
        ] = affected_urls[:20]

        raw_sources = group.pop(
            "_sources"
        )

        sources = []

        for source in sorted(
            raw_sources.values(),
            key=lambda item: str(
                item["tool_name"]
            ).lower(),
        ):
            sources.append(
                {
                    "tool_name":
                        source[
                            "tool_name"
                        ],
                    "external_finding_ids":
                        sorted(
                            source[
                                "external_finding_ids"
                            ]
                        ),
                    "occurrence_count":
                        source[
                            "occurrence_count"
                        ],
                }
            )

        group[
            "sources"
        ] = sources

        group[
            "source_count"
        ] = len(
            sources
        )

        group[
            "classification"
        ] = classify_issue(
            issue_key=str(
                group[
                    "issue_key"
                ]
            ),
            sources=sources,
        )

        if len(
            sources
        ) > 1:
            group[
                "tool_name"
            ] = "multiple"

            group[
                "external_finding_id"
            ] = None

            # Exact agreement by independent engines raises
            # confidence, but never severity.
            group[
                "confidence"
            ] = "high"

        aggregated.append(
            group
        )

    aggregated.sort(
        key=lambda issue: (
            -SEVERITY_RANK.get(
                str(
                    issue[
                        "severity"
                    ]
                ),
                0,
            ),
            -int(
                issue[
                    "occurrence_count"
                ]
            ),
            str(
                issue[
                    "title"
                ]
            ).lower(),
        )
    )

    return aggregated


def build_summary(
    findings: list[Finding],
) -> dict[str, Any]:
    """Build instance and correlated-issue counts for one scan."""

    grouped_issues = (
        aggregate_findings(
            findings
        )
    )

    instance_counter = Counter(
        normalize_severity(
            finding.severity
        )
        for finding in findings
    )

    issue_counter = Counter(
        str(
            issue[
                "severity"
            ]
        )
        for issue in grouped_issues
    )

    instances_by_severity = {
        severity:
            instance_counter.get(
                severity,
                0,
            )
        for severity in SEVERITY_LEVELS
    }

    issues_by_severity = {
        severity:
            issue_counter.get(
                severity,
                0,
            )
        for severity in SEVERITY_LEVELS
    }

    highest_severity = "none"

    for severity in SEVERITY_LEVELS:
        if (
            issues_by_severity[
                severity
            ]
            > 0
        ):
            highest_severity = (
                severity
            )
            break

    classification_counter = Counter(
        str(
            issue[
                "classification"
            ]
        )
        for issue in grouped_issues
    )

    security_issues = [
        issue
        for issue in grouped_issues
        if issue[
            "classification"
        ] == "security_issue"
    ]

    security_issue_counter = Counter(
        str(
            issue[
                "severity"
            ]
        )
        for issue in security_issues
    )

    security_issues_by_severity = {
        severity:
            security_issue_counter.get(
                severity,
                0,
            )
        for severity in SEVERITY_LEVELS
    }

    highest_security_severity = "none"

    for severity in SEVERITY_LEVELS:
        if (
            security_issues_by_severity[
                severity
            ]
            > 0
        ):
            highest_security_severity = (
                severity
            )
            break

    return {
        "total_finding_instances":
            len(findings),
        "distinct_issues":
            len(grouped_issues),
        "highest_severity":
            highest_severity,
        "instances_by_severity":
            instances_by_severity,
        "issues_by_severity":
            issues_by_severity,
        "security_issue_count":
            classification_counter.get(
                "security_issue",
                0,
            ),
        "attack_surface_count":
            classification_counter.get(
                "attack_surface",
                0,
            ),
        "observation_count":
            classification_counter.get(
                "observation",
                0,
            ),
        "limitation_count":
            classification_counter.get(
                "limitation",
                0,
            ),
        "highest_security_severity":
            highest_security_severity,
        "security_issues_by_severity":
            security_issues_by_severity,
        "top_issues":
            grouped_issues[:10],
    }
