import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app.reporting.generator import (
    build_report_context,
    render_report_html,
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
    """Build a minimal raw finding for report tests."""

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


class ReportContextTests(unittest.TestCase):
    def test_context_separates_results_by_classification(
        self,
    ):
        findings = [
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
                    "Nikto cannot test HTTP/3 "
                    "over QUIC."
                ),
                severity="informational",
            ),
        ]

        context = build_report_context(
            scan=SimpleNamespace(
                id="test-scan",
            ),
            target=SimpleNamespace(
                hostname="example.test",
            ),
            user=SimpleNamespace(
                id="test-user",
            ),
            findings=findings,
            tool_runs=[],
            generated_at=datetime.now(
                timezone.utc
            ),
        )

        self.assertEqual(
            1,
            len(context["security_issues"]),
        )
        self.assertEqual(
            1,
            len(context["attack_surface"]),
        )
        self.assertEqual(
            1,
            len(context["observations"]),
        )
        self.assertEqual(
            1,
            len(context["limitations"]),
        )

        self.assertEqual(
            "security_issue",
            context[
                "security_issues"
            ][0]["classification"],
        )

        self.assertEqual(
            "attack_surface",
            context[
                "attack_surface"
            ][0]["classification"],
        )

        self.assertEqual(
            "observation",
            context[
                "observations"
            ][0]["classification"],
        )

        self.assertEqual(
            "limitation",
            context[
                "limitations"
            ][0]["classification"],
        )

        summary = context["summary"]

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
            4,
            len(context["issues"]),
        )


    def test_rendered_report_uses_classified_sections(
        self,
    ):
        findings = [
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
                    "Nikto cannot test HTTP/3 "
                    "over QUIC."
                ),
                severity="informational",
            ),
        ]

        scan = SimpleNamespace(
            id="test-scan",
            scan_level="basic",
            started_at=datetime.now(
                timezone.utc
            ),
            completed_at=datetime.now(
                timezone.utc
            ),
            status="completed",
        )

        target = SimpleNamespace(
            hostname="example.test",
            normalized_url=(
                "https://example.test/"
            ),
            verification_method="file",
            verified_at=datetime.now(
                timezone.utc
            ),
        )

        user = SimpleNamespace(
            id="test-user",
            full_name="BEACON Tester",
            email="tester@example.test",
        )

        context = build_report_context(
            scan=scan,
            target=target,
            user=user,
            findings=findings,
            tool_runs=[],
            generated_at=datetime.now(
                timezone.utc
            ),
        )

        html = render_report_html(
            context
        )

        self.assertIn(
            "Highest Security Severity",
            html,
        )

        self.assertIn(
            "<h2>Security Issues</h2>",
            html,
        )

        self.assertIn(
            "<h2>Attack Surface</h2>",
            html,
        )

        self.assertIn(
            "<h2>Observations</h2>",
            html,
        )

        self.assertIn(
            "<h2>Assessment Limitations</h2>",
            html,
        )

        self.assertNotIn(
            "<h2>Technical Findings</h2>",
            html,
        )


    def test_non_security_results_do_not_raise_security_posture(
        self,
    ):
        findings = [
            finding(
                tool="zap",
                external_id="10109",
                title="Critical Context Observation",
                severity="critical",
            ),
            finding(
                tool="nmap",
                external_id="tcp-443",
                title=(
                    "Open TCP service detected: "
                    "443/http"
                ),
                severity="high",
                confidence="10",
            ),
        ]

        now = datetime.now(
            timezone.utc
        )

        context = build_report_context(
            scan=SimpleNamespace(
                id="zero-security-scan",
                scan_level="basic",
                started_at=now,
                completed_at=now,
                status="completed",
            ),
            target=SimpleNamespace(
                hostname="example.test",
                normalized_url=(
                    "https://example.test/"
                ),
                verification_method="file",
                verified_at=now,
            ),
            user=SimpleNamespace(
                id="test-user",
                full_name="BEACON Tester",
                email="tester@example.test",
            ),
            findings=findings,
            tool_runs=[],
            generated_at=now,
        )

        summary = context["summary"]

        self.assertEqual(
            0,
            summary["security_issue_count"],
        )

        self.assertEqual(
            "none",
            summary[
                "highest_security_severity"
            ],
        )

        self.assertEqual(
            1,
            summary["observation_count"],
        )

        self.assertEqual(
            1,
            summary["attack_surface_count"],
        )

        html = render_report_html(
            context
        )

        self.assertIn(
            "Highest Security Severity",
            html,
        )

        self.assertIn(
            "NONE",
            html,
        )

        self.assertIn(
            (
                "No Security Issues were recorded "
                "by this automated"
            ),
            html,
        )

        security_section = html.split(
            "<h2>Security Issues</h2>",
            1,
        )[1].split(
            "<h2>Observations</h2>",
            1,
        )[0]

        self.assertNotIn(
            "Critical Context Observation",
            security_section,
        )

        observations_section = html.split(
            "<h2>Observations</h2>",
            1,
        )[1]

        self.assertIn(
            "Critical Context Observation",
            observations_section,
        )

        self.assertNotIn(
            "Recommended remediation",
            observations_section,
        )


    def test_report_uses_consistent_assessment_labels_and_row_break_protection(
        self,
    ):
        template_path = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "templates"
            / "reports"
            / "security_assessment.html"
        )

        template = template_path.read_text()

        self.assertIn(
            "Assessment classification breakdown",
            template,
        )

        self.assertIn(
            "Affected Resources",
            template,
        )

        self.assertIn(
            "Total assessment results",
            template,
        )

        self.assertNotIn(
            "Correlated issues",
            template,
        )

        self.assertIn(
            """.issues-table tr {
      page-break-inside: avoid;
    }""",
            template,
        )


if __name__ == "__main__":
    unittest.main()
