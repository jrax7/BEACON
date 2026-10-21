import unittest
from types import SimpleNamespace

from app.services.finding_aggregation import (
    aggregate_findings,
    build_issue_key,
    build_summary,
)


def finding(
    *,
    tool: str,
    external_id: str,
    title: str,
    severity: str = "low",
    confidence: str | None = "medium",
    cwe_id: str | None = None,
    url: str = "https://example.test/",
    description: str | None = None,
    remediation: str | None = None,
    evidence: dict | None = None,
):
    """Build a minimal raw finding for aggregation tests."""

    return SimpleNamespace(
        tool_name=tool,
        external_finding_id=external_id,
        title=title,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        affected_url=url,
        description=description,
        remediation=remediation,
        evidence=evidence,
    )


class FindingAggregationTests(
    unittest.TestCase
):
    def test_proven_security_headers_correlate(
        self,
    ):
        rows = [
            finding(
                tool="zap",
                external_id="10038",
                title=(
                    "Content Security Policy (CSP) "
                    "Header Not Set"
                ),
                severity="medium",
                confidence="High",
                cwe_id="CWE-693",
            ),
            finding(
                tool="nikto",
                external_id="nikto-csp",
                title=(
                    "Nikto: Suggested security header "
                    "missing: content-security-policy."
                ),
                severity="low",
            ),
            finding(
                tool="zap",
                external_id="10035",
                title=(
                    "Strict-Transport-Security Header "
                    "Not Set"
                ),
                severity="low",
                confidence="High",
                cwe_id="CWE-319",
            ),
            finding(
                tool="nikto",
                external_id="nikto-hsts",
                title=(
                    "Nikto: Suggested security header "
                    "missing: strict-transport-security."
                ),
            ),
            finding(
                tool="zap",
                external_id="10021",
                title=(
                    "X-Content-Type-Options "
                    "Header Missing"
                ),
                severity="low",
                confidence="Medium",
                cwe_id="CWE-693",
            ),
            finding(
                tool="nikto",
                external_id="nikto-xcto",
                title=(
                    "Nikto: Suggested security header "
                    "missing: x-content-type-options."
                ),
            ),
        ]

        issues = aggregate_findings(
            rows
        )

        self.assertEqual(
            3,
            len(issues),
        )

        by_key = {
            issue["issue_key"]: issue
            for issue in issues
        }

        csp = by_key[
            "missing-security-header:csp"
        ]

        self.assertEqual(
            "Content Security Policy Header Missing",
            csp["title"],
        )

        # Cross-engine agreement raises confidence,
        # but must not inflate severity.
        self.assertEqual(
            "medium",
            csp["severity"],
        )
        self.assertEqual(
            "high",
            csp["confidence"],
        )

        self.assertEqual(
            2,
            csp["source_count"],
        )

        self.assertEqual(
            ["nikto", "zap"],
            [
                source["tool_name"].lower()
                for source
                in csp["sources"]
            ],
        )

        # Correlation must preserve every raw observation.
        self.assertEqual(
            len(rows),
            sum(
                issue["occurrence_count"]
                for issue in issues
            ),
        )

    def test_permissions_policy_is_canonicalized(
        self,
    ):
        row = finding(
            tool="nikto",
            external_id="nikto-permissions",
            title=(
                "Nikto: Suggested security header "
                "missing: permissions-policy."
            ),
        )

        issues = aggregate_findings(
            [row]
        )

        self.assertEqual(
            1,
            len(issues),
        )

        issue = issues[0]

        self.assertEqual(
            "missing-security-header:permissions-policy",
            issue["issue_key"],
        )
        self.assertEqual(
            "Permissions Policy Header Missing",
            issue["title"],
        )
        self.assertEqual(
            1,
            issue["source_count"],
        )
        self.assertIsNone(
            issue["cwe_id"],
        )

    def test_referrer_policy_is_canonicalized(
        self,
    ):
        row = finding(
            tool="nikto",
            external_id="nikto-referrer",
            title=(
                "Nikto: Suggested security header "
                "missing: referrer-policy."
            ),
        )

        issues = aggregate_findings(
            [row]
        )

        self.assertEqual(
            "missing-security-header:referrer-policy",
            issues[0]["issue_key"],
        )
        self.assertEqual(
            "Referrer Policy Header Missing",
            issues[0]["title"],
        )

    def test_wildcard_cors_evidence_correlates(
        self,
    ):
        rows = [
            finding(
                tool="zap",
                external_id="10098",
                title="Cross-Domain Misconfiguration",
                severity="medium",
                confidence="Medium",
                cwe_id="CWE-264",
                evidence={
                    "evidence":
                        "Access-Control-Allow-Origin: *",
                },
            ),
            finding(
                tool="nikto",
                external_id="999986-test",
                title=(
                    "Nikto: Retrieved "
                    "access-control-allow-origin "
                    "header: *."
                ),
                severity="low",
            ),
        ]

        issues = aggregate_findings(
            rows
        )

        self.assertEqual(
            1,
            len(issues),
        )

        issue = issues[0]

        self.assertEqual(
            "cors:wildcard-origin",
            issue["issue_key"],
        )
        self.assertEqual(
            "Overly Permissive CORS Policy",
            issue["title"],
        )
        self.assertEqual(
            "medium",
            issue["severity"],
        )
        self.assertEqual(
            "high",
            issue["confidence"],
        )
        self.assertEqual(
            2,
            issue["source_count"],
        )
        self.assertEqual(
            2,
            issue["occurrence_count"],
        )

    def test_generic_zap_cors_does_not_correlate(
        self,
    ):
        rows = [
            finding(
                tool="zap",
                external_id="10098",
                title="Cross-Domain Misconfiguration",
                severity="medium",
                confidence="Medium",
                cwe_id="CWE-264",
                evidence={
                    "evidence":
                        "Origin reflected dynamically",
                },
            ),
            finding(
                tool="nikto",
                external_id="999986-test",
                title=(
                    "Nikto: Retrieved "
                    "access-control-allow-origin "
                    "header: *."
                ),
                severity="low",
            ),
        ]

        issues = aggregate_findings(
            rows
        )

        self.assertEqual(
            2,
            len(issues),
        )

    def test_unknown_nikto_header_keeps_scanner_key(
        self,
    ):
        row = finding(
            tool="nikto",
            external_id="unknown-header-rule",
            title=(
                "Nikto: Suggested security header "
                "missing: example-future-header."
            ),
        )

        self.assertEqual(
            "nikto:unknown-header-rule",
            build_issue_key(row),
        )

    def test_nmap_service_is_attack_surface(
        self,
    ):
        issue = aggregate_findings(
            [
                finding(
                    tool="nmap",
                    external_id="tcp-443",
                    title=(
                        "Open TCP service detected: "
                        "443/http"
                    ),
                    severity="informational",
                    confidence="10",
                )
            ]
        )[0]

        self.assertEqual(
            "attack_surface",
            issue["classification"],
        )

    def test_modern_web_application_is_observation(
        self,
    ):
        issue = aggregate_findings(
            [
                finding(
                    tool="zap",
                    external_id="10109",
                    title="Modern Web Application",
                    severity="informational",
                )
            ]
        )[0]

        self.assertEqual(
            "observation",
            issue["classification"],
        )

    def test_nikto_http3_gap_is_limitation(
        self,
    ):
        issue = aggregate_findings(
            [
                finding(
                    tool="nikto",
                    external_id="011799-test",
                    title=(
                        "Nikto: An alt-svc header was "
                        "found which is advertising HTTP/3. "
                        "Nikto cannot test HTTP/3 over QUIC."
                    ),
                    severity="informational",
                )
            ]
        )[0]

        self.assertEqual(
            "limitation",
            issue["classification"],
        )

    def test_unknown_rule_defaults_to_security_issue(
        self,
    ):
        issue = aggregate_findings(
            [
                finding(
                    tool="future-scanner",
                    external_id="future-rule",
                    title="New security scanner finding",
                    severity="low",
                )
            ]
        )[0]

        self.assertEqual(
            "security_issue",
            issue["classification"],
        )

    def test_summary_separates_security_posture(
        self,
    ):
        rows = [
            finding(
                tool="zap",
                external_id="10020",
                title="Missing Anti-clickjacking Header",
                severity="medium",
            ),
            finding(
                tool="nmap",
                external_id="tcp-443",
                title=(
                    "Open TCP service detected: "
                    "443/http"
                ),
                severity="informational",
                confidence="10",
            ),
            finding(
                tool="zap",
                external_id="10109",
                title="Modern Web Application",
                severity="critical",
            ),
            finding(
                tool="nikto",
                external_id="011799-test",
                title=(
                    "Nikto cannot test HTTP/3 over QUIC."
                ),
                severity="informational",
            ),
        ]

        summary = build_summary(
            rows
        )

        # Legacy summary remains backward-compatible.
        self.assertEqual(
            4,
            summary["distinct_issues"],
        )
        self.assertEqual(
            "critical",
            summary["highest_severity"],
        )

        # Security posture excludes attack surface,
        # observations, and scanner limitations.
        self.assertEqual(
            1,
            summary["security_issue_count"],
        )
        self.assertEqual(
            1,
            summary["attack_surface_count"],
        )
        self.assertEqual(
            1,
            summary["observation_count"],
        )
        self.assertEqual(
            1,
            summary["limitation_count"],
        )
        self.assertEqual(
            "medium",
            summary[
                "highest_security_severity"
            ],
        )
        self.assertEqual(
            1,
            summary[
                "security_issues_by_severity"
            ][
                "medium"
            ],
        )

    def test_manual_validation_is_explicit(
        self,
    ):
        row = finding(
            tool="nikto",
            external_id="manual-test",
            title=(
                "Nikto: contains 10 entries which "
                "should be manually viewed."
            ),
        )

        issue = aggregate_findings(
            [row]
        )[0]

        self.assertTrue(
            issue[
                "requires_manual_validation"
            ]
        )


if __name__ == "__main__":
    unittest.main()
