import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from app.services import findings_workspace


SCAN_ID = UUID(
    "11111111-1111-1111-1111-111111111111"
)

NOW = datetime(
    2026,
    8,
    22,
    12,
    0,
    tzinfo=timezone.utc,
)


class QueuedScalarsDatabase:
    def __init__(self, *result_sets):
        self.result_sets = list(result_sets)
        self.statements = []

    def scalars(self, statement):
        self.statements.append(statement)

        if not self.result_sets:
            raise AssertionError(
                "Unexpected database.scalars() call."
            )

        return self.result_sets.pop(0)


def raw_csp_finding(
    *,
    scan_id,
    created_at=NOW,
):
    return SimpleNamespace(
        scan_id=scan_id,
        tool_name="zap",
        external_finding_id="10038",
        title=(
            "Content Security Policy (CSP) "
            "Header Not Set"
        ),
        severity="medium",
        confidence="High",
        cwe_id="CWE-693",
        affected_url="https://example.test/",
        description=(
            "Content Security Policy header is missing."
        ),
        remediation=(
            "Configure a Content Security Policy."
        ),
        evidence=None,
        created_at=created_at,
    )


class FindingsWorkspaceIdentifierTests(
    unittest.TestCase
):
    def test_workspace_finding_id_round_trip_preserves_colons(
        self,
    ):
        value = findings_workspace.workspace_finding_id(
            SCAN_ID,
            "missing-security-header:csp",
        )

        self.assertEqual(
            value,
            (
                "11111111-1111-1111-1111-111111111111:"
                "missing-security-header:csp"
            ),
        )

        self.assertEqual(
            findings_workspace.parse_workspace_finding_id(
                value
            ),
            (
                SCAN_ID,
                "missing-security-header:csp",
            ),
        )

    def test_parse_workspace_finding_id_rejects_invalid_values(
        self,
    ):
        with self.assertRaises(ValueError):
            findings_workspace.parse_workspace_finding_id(
                "not-a-workspace-finding-id"
            )


class FindingsWorkspaceAggregationTests(
    unittest.TestCase
):
    def test_same_issue_in_two_assessments_stays_separate(
        self,
    ):
        function = getattr(
            findings_workspace,
            "build_workspace_rows",
            None,
        )

        self.assertIsNotNone(
            function,
            "build_workspace_rows is missing.",
        )

        if function is None:
            return

        user_id = uuid4()
        target_id = uuid4()

        first_scan = SimpleNamespace(
            id=uuid4(),
            user_id=user_id,
            target_id=target_id,
            status="completed",
            created_at=NOW,
            completed_at=NOW,
            archived_at=None,
        )

        second_scan = SimpleNamespace(
            id=uuid4(),
            user_id=user_id,
            target_id=target_id,
            status="completed",
            created_at=NOW,
            completed_at=NOW,
            archived_at=None,
        )

        target = SimpleNamespace(
            id=target_id,
            user_id=user_id,
            hostname="example.test",
            normalized_url="https://example.test/",
        )

        database = QueuedScalarsDatabase(
            [
                first_scan,
                second_scan,
            ],
            [
                target,
            ],
            [
                raw_csp_finding(
                    scan_id=first_scan.id,
                ),
                raw_csp_finding(
                    scan_id=second_scan.id,
                ),
            ],
        )

        rows = function(
            database,
            user_id,
        )

        matching = [
            row
            for row in rows
            if row["issue_key"]
            == "missing-security-header:csp"
        ]

        self.assertEqual(
            len(matching),
            2,
        )

        self.assertEqual(
            {
                row["scan_id"]
                for row in matching
            },
            {
                first_scan.id,
                second_scan.id,
            },
        )


if __name__ == "__main__":
    unittest.main()


class FindingsWorkspaceFilterTests(
    unittest.TestCase
):
    def test_filters_severity_case_insensitively(self):
        function = getattr(
            findings_workspace,
            "filter_workspace_rows",
            None,
        )

        self.assertIsNotNone(
            function,
            "filter_workspace_rows is missing.",
        )

        if function is None:
            return

        rows = [
            {
                "severity": "High",
                "confidence": "high",
                "classification": "security_issue",
                "target_id": uuid4(),
                "scan_id": uuid4(),
                "title": "High severity issue",
                "description": "Example finding",
                "cwe_id": "CWE-79",
                "target_hostname": "example.test",
                "issue_key": "example:high",
                "sources": [
                    {
                        "tool_name": "zap",
                    }
                ],
            },
            {
                "severity": "low",
                "confidence": "medium",
                "classification": "security_issue",
                "target_id": uuid4(),
                "scan_id": uuid4(),
                "title": "Low severity issue",
                "description": "Example finding",
                "cwe_id": "CWE-200",
                "target_hostname": "example.test",
                "issue_key": "example:low",
                "sources": [
                    {
                        "tool_name": "nikto",
                    }
                ],
            },
        ]

        filtered = function(
            rows,
            severity="HIGH",
        )

        self.assertEqual(
            len(filtered),
            1,
        )

        self.assertEqual(
            filtered[0]["issue_key"],
            "example:high",
        )


def _workspace_filter_rows():
    return [
        {
            "severity": "high",
            "confidence": "High",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "High confidence issue",
            "description": "Example finding",
            "cwe_id": "CWE-79",
            "target_hostname": "example.test",
            "issue_key": "example:high-confidence",
            "sources": [
                {
                    "tool_name": "zap",
                }
            ],
        },
        {
            "severity": "high",
            "confidence": "medium",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Medium confidence issue",
            "description": "Example finding",
            "cwe_id": "CWE-200",
            "target_hostname": "example.test",
            "issue_key": "example:medium-confidence",
            "sources": [
                {
                    "tool_name": "nikto",
                }
            ],
        },
    ]


def _test_filters_confidence_case_insensitively(self):
    filtered = findings_workspace.filter_workspace_rows(
        _workspace_filter_rows(),
        confidence="HIGH",
    )

    self.assertEqual(
        len(filtered),
        1,
    )

    self.assertEqual(
        filtered[0]["issue_key"],
        "example:high-confidence",
    )


FindingsWorkspaceFilterTests.test_filters_confidence_case_insensitively = (
    _test_filters_confidence_case_insensitively
)


def _test_filters_target_id_exactly(self):
    target_a = uuid4()
    target_b = uuid4()

    rows = [
        {
            "severity": "high",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": target_a,
            "scan_id": uuid4(),
            "title": "Target A issue",
            "description": "Example finding",
            "cwe_id": "CWE-79",
            "target_hostname": "a.example.test",
            "issue_key": "example:target-a",
            "sources": [
                {
                    "tool_name": "zap",
                }
            ],
        },
        {
            "severity": "high",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": target_b,
            "scan_id": uuid4(),
            "title": "Target B issue",
            "description": "Example finding",
            "cwe_id": "CWE-200",
            "target_hostname": "b.example.test",
            "issue_key": "example:target-b",
            "sources": [
                {
                    "tool_name": "nikto",
                }
            ],
        },
    ]

    filtered = findings_workspace.filter_workspace_rows(
        rows,
        target_id=target_a,
    )

    self.assertEqual(
        len(filtered),
        1,
    )

    self.assertEqual(
        filtered[0]["issue_key"],
        "example:target-a",
    )


def _test_filters_scan_id_exactly(self):
    scan_a = uuid4()
    scan_b = uuid4()

    rows = [
        {
            "severity": "high",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": scan_a,
            "title": "Assessment A issue",
            "description": "Example finding",
            "cwe_id": "CWE-79",
            "target_hostname": "example.test",
            "issue_key": "example:scan-a",
            "sources": [
                {
                    "tool_name": "zap",
                }
            ],
        },
        {
            "severity": "high",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": scan_b,
            "title": "Assessment B issue",
            "description": "Example finding",
            "cwe_id": "CWE-200",
            "target_hostname": "example.test",
            "issue_key": "example:scan-b",
            "sources": [
                {
                    "tool_name": "nikto",
                }
            ],
        },
    ]

    filtered = findings_workspace.filter_workspace_rows(
        rows,
        scan_id=scan_a,
    )

    self.assertEqual(
        len(filtered),
        1,
    )

    self.assertEqual(
        filtered[0]["issue_key"],
        "example:scan-a",
    )


FindingsWorkspaceFilterTests.test_filters_target_id_exactly = (
    _test_filters_target_id_exactly
)

FindingsWorkspaceFilterTests.test_filters_scan_id_exactly = (
    _test_filters_scan_id_exactly
)


def _test_filters_source_tool_case_insensitively(self):
    rows = [
        {
            "severity": "medium",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Correlated CSP issue",
            "description": "Example finding",
            "cwe_id": "CWE-693",
            "target_hostname": "example.test",
            "issue_key": "missing-security-header:csp",
            "sources": [
                {
                    "tool_name": "zap",
                },
                {
                    "tool_name": "nikto",
                },
            ],
        },
        {
            "severity": "low",
            "confidence": "medium",
            "classification": "attack_surface",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Open HTTP service",
            "description": "Example finding",
            "cwe_id": None,
            "target_hostname": "example.test",
            "issue_key": "nmap:tcp-80",
            "sources": [
                {
                    "tool_name": "nmap",
                }
            ],
        },
    ]

    filtered = findings_workspace.filter_workspace_rows(
        rows,
        tool="NIKTO",
    )

    self.assertEqual(
        len(filtered),
        1,
    )

    self.assertEqual(
        filtered[0]["issue_key"],
        "missing-security-header:csp",
    )


FindingsWorkspaceFilterTests.test_filters_source_tool_case_insensitively = (
    _test_filters_source_tool_case_insensitively
)


def _test_filters_classification_case_insensitively(self):
    rows = [
        {
            "severity": "medium",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Security issue",
            "description": "Example finding",
            "cwe_id": "CWE-693",
            "target_hostname": "example.test",
            "issue_key": "example:security",
            "sources": [
                {
                    "tool_name": "zap",
                }
            ],
        },
        {
            "severity": "low",
            "confidence": "medium",
            "classification": "attack_surface",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Open HTTP service",
            "description": "Example finding",
            "cwe_id": None,
            "target_hostname": "example.test",
            "issue_key": "nmap:tcp-80",
            "sources": [
                {
                    "tool_name": "nmap",
                }
            ],
        },
    ]

    filtered = findings_workspace.filter_workspace_rows(
        rows,
        classification="ATTACK_SURFACE",
    )

    self.assertEqual(
        len(filtered),
        1,
    )

    self.assertEqual(
        filtered[0]["issue_key"],
        "nmap:tcp-80",
    )


FindingsWorkspaceFilterTests.test_filters_classification_case_insensitively = (
    _test_filters_classification_case_insensitively
)


def _test_searches_workspace_text_fields_case_insensitively(self):
    rows = [
        {
            "severity": "medium",
            "confidence": "high",
            "classification": "security_issue",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Content Security Policy Header Missing",
            "description": "Browser policy header is absent.",
            "cwe_id": "CWE-693",
            "target_hostname": "portal.example.test",
            "issue_key": "missing-security-header:csp",
            "sources": [
                {
                    "tool_name": "zap",
                }
            ],
        },
        {
            "severity": "low",
            "confidence": "medium",
            "classification": "attack_surface",
            "target_id": uuid4(),
            "scan_id": uuid4(),
            "title": "Open HTTP Service",
            "description": "TCP port 80 is exposed.",
            "cwe_id": None,
            "target_hostname": "api.example.test",
            "issue_key": "nmap:tcp-80",
            "sources": [
                {
                    "tool_name": "nmap",
                }
            ],
        },
    ]

    searches = {
        "CONTENT SECURITY": "missing-security-header:csp",
        "browser policy": "missing-security-header:csp",
        "cwe-693": "missing-security-header:csp",
        "PORTAL.EXAMPLE.TEST": "missing-security-header:csp",
        "missing-security-header:csp": "missing-security-header:csp",
        "tcp port 80": "nmap:tcp-80",
    }

    for query, expected_issue_key in searches.items():
        with self.subTest(query=query):
            filtered = findings_workspace.filter_workspace_rows(
                rows,
                q=query,
            )

            self.assertEqual(
                len(filtered),
                1,
            )

            self.assertEqual(
                filtered[0]["issue_key"],
                expected_issue_key,
            )


FindingsWorkspaceFilterTests.test_searches_workspace_text_fields_case_insensitively = (
    _test_searches_workspace_text_fields_case_insensitively
)


class FindingsWorkspaceDetailTests(
    unittest.TestCase
):
    def test_builds_detail_with_raw_occurrences(self):
        function = getattr(
            findings_workspace,
            "build_workspace_detail",
            None,
        )

        self.assertIsNotNone(
            function,
            "build_workspace_detail is missing.",
        )

        if function is None:
            return

        user_id = uuid4()
        target_id = uuid4()
        scan_id = uuid4()
        finding_id = uuid4()

        scan = SimpleNamespace(
            id=scan_id,
            user_id=user_id,
            target_id=target_id,
            status="completed",
            created_at=NOW,
            completed_at=NOW,
            archived_at=None,
        )

        target = SimpleNamespace(
            id=target_id,
            user_id=user_id,
            hostname="example.test",
            normalized_url="https://example.test/",
        )

        raw_finding = raw_csp_finding(
            scan_id=scan_id,
        )

        raw_finding.id = finding_id
        raw_finding.affected_port = 443
        raw_finding.cvss_score = None
        raw_finding.status = "open"

        database = QueuedScalarsDatabase(
            [scan],
            [target],
            [raw_finding],
            [raw_finding],
        )

        detail = function(
            database,
            user_id,
            findings_workspace.workspace_finding_id(
                scan_id,
                "missing-security-header:csp",
            ),
        )

        self.assertIsNotNone(detail)

        self.assertEqual(
            detail["issue_key"],
            "missing-security-header:csp",
        )

        self.assertEqual(
            detail["scan_id"],
            scan_id,
        )

        self.assertEqual(
            detail["target_id"],
            target_id,
        )

        self.assertEqual(
            len(detail["occurrences"]),
            1,
        )

        occurrence = detail["occurrences"][0]

        self.assertEqual(
            occurrence["id"],
            finding_id,
        )

        self.assertEqual(
            occurrence["tool_name"],
            "zap",
        )

        self.assertEqual(
            occurrence["external_finding_id"],
            "10038",
        )

        self.assertEqual(
            occurrence["affected_port"],
            443,
        )

        self.assertEqual(
            occurrence["status"],
            "open",
        )


def _test_detail_rejects_invalid_workspace_id(self):
    database = QueuedScalarsDatabase()

    detail = findings_workspace.build_workspace_detail(
        database,
        uuid4(),
        "not-a-workspace-finding-id",
    )

    self.assertIsNone(detail)
    self.assertEqual(
        database.statements,
        [],
    )


def _test_detail_returns_none_for_wrong_issue_key(self):
    user_id = uuid4()
    target_id = uuid4()
    scan_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        user_id=user_id,
        target_id=target_id,
        status="completed",
        created_at=NOW,
        completed_at=NOW,
        archived_at=None,
    )

    target = SimpleNamespace(
        id=target_id,
        user_id=user_id,
        hostname="example.test",
        normalized_url="https://example.test/",
    )

    raw_finding = raw_csp_finding(
        scan_id=scan_id,
    )

    database = QueuedScalarsDatabase(
        [scan],
        [target],
        [raw_finding],
    )

    detail = findings_workspace.build_workspace_detail(
        database,
        user_id,
        findings_workspace.workspace_finding_id(
            scan_id,
            "missing-security-header:hsts",
        ),
    )

    self.assertIsNone(detail)


def _test_detail_does_not_return_another_users_finding(self):
    owner_id = uuid4()
    other_user_id = uuid4()
    target_id = uuid4()
    scan_id = uuid4()

    scan = SimpleNamespace(
        id=scan_id,
        user_id=owner_id,
        target_id=target_id,
        status="completed",
        created_at=NOW,
        completed_at=NOW,
        archived_at=None,
    )

    target = SimpleNamespace(
        id=target_id,
        user_id=owner_id,
        hostname="example.test",
        normalized_url="https://example.test/",
    )

    raw_finding = raw_csp_finding(
        scan_id=scan_id,
    )

    database = QueuedScalarsDatabase(
        [],
    )

    detail = findings_workspace.build_workspace_detail(
        database,
        other_user_id,
        findings_workspace.workspace_finding_id(
            scan_id,
            "missing-security-header:csp",
        ),
    )

    self.assertIsNone(detail)


FindingsWorkspaceDetailTests.test_detail_rejects_invalid_workspace_id = (
    _test_detail_rejects_invalid_workspace_id
)

FindingsWorkspaceDetailTests.test_detail_returns_none_for_wrong_issue_key = (
    _test_detail_returns_none_for_wrong_issue_key
)

FindingsWorkspaceDetailTests.test_detail_does_not_return_another_users_finding = (
    _test_detail_does_not_return_another_users_finding
)


class FindingsWorkspaceSchemaTests(
    unittest.TestCase
):
    def test_workspace_response_schemas_exist(self):
        import importlib
        import importlib.util

        spec = importlib.util.find_spec(
            "app.schemas.findings"
        )

        self.assertIsNotNone(
            spec,
            "app.schemas.findings is missing.",
        )

        if spec is None:
            return

        schemas = importlib.import_module(
            "app.schemas.findings"
        )

        summary = getattr(
            schemas,
            "WorkspaceFindingSummaryResponse",
            None,
        )

        page = getattr(
            schemas,
            "WorkspaceFindingsPageResponse",
            None,
        )

        occurrence = getattr(
            schemas,
            "WorkspaceFindingOccurrenceResponse",
            None,
        )

        detail = getattr(
            schemas,
            "WorkspaceFindingDetailResponse",
            None,
        )

        self.assertIsNotNone(summary)
        self.assertIsNotNone(page)
        self.assertIsNotNone(occurrence)
        self.assertIsNotNone(detail)

        if any(
            item is None
            for item in (
                summary,
                page,
                occurrence,
                detail,
            )
        ):
            return

        self.assertTrue(
            {
                "id",
                "issue_key",
                "classification",
                "title",
                "severity",
                "confidence",
                "cwe_id",
                "description",
                "remediation",
                "occurrence_count",
                "affected_url_count",
                "sample_affected_urls",
                "source_count",
                "sources",
                "requires_manual_validation",
                "target_id",
                "target_hostname",
                "target_url",
                "scan_id",
                "scan_status",
                "scan_created_at",
                "scan_completed_at",
                "last_observed_at",
            }.issubset(
                summary.model_fields
            )
        )

        self.assertEqual(
            set(page.model_fields),
            {
                "total",
                "offset",
                "limit",
                "items",
            },
        )

        self.assertTrue(
            {
                "id",
                "tool_name",
                "external_finding_id",
                "title",
                "severity",
                "confidence",
                "affected_url",
                "affected_port",
                "evidence",
                "remediation",
                "cwe_id",
                "cvss_score",
                "status",
                "created_at",
            }.issubset(
                occurrence.model_fields
            )
        )

        self.assertIn(
            "occurrences",
            detail.model_fields,
        )


from fastapi import HTTPException
from unittest.mock import patch


def _workspace_api_row(
    *,
    issue_key="missing-security-header:csp",
    title="Content Security Policy Header Missing",
):
    scan_id = uuid4()

    return {
        "id": findings_workspace.workspace_finding_id(
            scan_id,
            issue_key,
        ),
        "issue_key": issue_key,
        "classification": "security_issue",
        "title": title,
        "severity": "medium",
        "confidence": "high",
        "cwe_id": "CWE-693",
        "description": "Example description.",
        "remediation": "Add the missing header.",
        "occurrence_count": 1,
        "affected_url_count": 1,
        "sample_affected_urls": [
            "https://example.test/",
        ],
        "source_count": 1,
        "sources": [
            {
                "tool_name": "zap",
                "external_finding_ids": [
                    "10038",
                ],
                "occurrence_count": 1,
            }
        ],
        "requires_manual_validation": False,
        "target_id": uuid4(),
        "target_hostname": "example.test",
        "target_url": "https://example.test/",
        "scan_id": scan_id,
        "scan_status": "completed",
        "scan_created_at": NOW,
        "scan_completed_at": NOW,
        "last_observed_at": NOW,
    }


class FindingsWorkspaceRouterTests(
    unittest.TestCase
):
    def setUp(self):
        self.organization_id = uuid4()

        self.organization_context = (
            SimpleNamespace(
                organization=SimpleNamespace(
                    id=self.organization_id,
                ),
                role="viewer",
            )
        )

        self.context_patch = patch(
            "app.routers.findings."
            "resolve_organization_context",
            return_value=(
                self.organization_context
            ),
        )

        self.context_patch.start()

        self.addCleanup(
            self.context_patch.stop
        )


    def router_module(self):
        import importlib
        import importlib.util

        spec = importlib.util.find_spec(
            "app.routers.findings"
        )

        self.assertIsNotNone(
            spec,
            "app.routers.findings is missing.",
        )

        if spec is None:
            return None

        return importlib.import_module(
            "app.routers.findings"
        )

    def test_router_exposes_list_and_detail_routes(self):
        module = self.router_module()

        if module is None:
            return

        list_route = next(
            (
                route
                for route in module.router.routes
                if route.path == "/api/v1/findings"
                and "GET" in route.methods
            ),
            None,
        )

        detail_route = next(
            (
                route
                for route in module.router.routes
                if route.path
                == "/api/v1/findings/{finding_id:path}"
                and "GET" in route.methods
            ),
            None,
        )

        self.assertIsNotNone(
            list_route,
            "GET /api/v1/findings is missing.",
        )

        self.assertIsNotNone(
            detail_route,
            (
                "GET /api/v1/findings/"
                "{finding_id:path} is missing."
            ),
        )

    def test_list_forwards_filters_and_paginates(self):
        module = self.router_module()

        if module is None:
            return

        function = getattr(
            module,
            "list_findings",
            None,
        )

        self.assertIsNotNone(
            function,
            "list_findings endpoint is missing.",
        )

        if function is None:
            return

        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        target_id = uuid4()
        scan_id = uuid4()

        rows = [
            _workspace_api_row(
                issue_key="example:first",
                title="First",
            ),
            _workspace_api_row(
                issue_key="example:second",
                title="Second",
            ),
            _workspace_api_row(
                issue_key="example:third",
                title="Third",
            ),
        ]

        filtered_rows = rows[1:]

        with (
            patch.object(
                module,
                "build_workspace_rows",
                return_value=rows,
            ) as build_rows,
            patch.object(
                module,
                "filter_workspace_rows",
                return_value=filtered_rows,
            ) as filter_rows,
        ):
            page = function(
                current_user=user,
                database=object(),
                severity="medium",
                confidence="high",
                target_id=target_id,
                scan_id=scan_id,
                tool="zap",
                classification="security_issue",
                q="header",
                offset=1,
                limit=1,
            )

        build_rows.assert_called_once_with(
            unittest.mock.ANY,
            self.organization_id,
        )

        filter_rows.assert_called_once_with(
            rows,
            severity="medium",
            confidence="high",
            target_id=target_id,
            scan_id=scan_id,
            tool="zap",
            classification="security_issue",
            q="header",
        )

        self.assertEqual(
            page.total,
            2,
        )

        self.assertEqual(
            page.offset,
            1,
        )

        self.assertEqual(
            page.limit,
            1,
        )

        self.assertEqual(
            len(page.items),
            1,
        )

        self.assertEqual(
            page.items[0].issue_key,
            "example:third",
        )

    def test_detail_returns_workspace_finding(self):
        module = self.router_module()

        if module is None:
            return

        function = getattr(
            module,
            "get_finding",
            None,
        )

        self.assertIsNotNone(
            function,
            "get_finding endpoint is missing.",
        )

        if function is None:
            return

        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        summary = _workspace_api_row()

        detail = {
            **summary,
            "occurrences": [
                {
                    "id": uuid4(),
                    "tool_name": "zap",
                    "external_finding_id": "10038",
                    "title": "CSP Header Not Set",
                    "severity": "medium",
                    "confidence": "high",
                    "affected_url":
                        "https://example.test/",
                    "affected_port": 443,
                    "evidence": {
                        "header": "missing",
                    },
                    "remediation":
                        "Add a Content-Security-Policy header.",
                    "cwe_id": "CWE-693",
                    "cvss_score": None,
                    "status": "open",
                    "created_at": NOW,
                }
            ],
        }

        with patch.object(
            module,
            "build_workspace_detail",
            return_value=detail,
        ) as build_detail:
            result = function(
                finding_id=summary["id"],
                current_user=user,
                database=object(),
            )

        build_detail.assert_called_once_with(
            unittest.mock.ANY,
            self.organization_id,
            summary["id"],
        )

        self.assertEqual(
            result.id,
            summary["id"],
        )

        self.assertEqual(
            len(result.occurrences),
            1,
        )

        self.assertEqual(
            result.occurrences[0].tool_name,
            "zap",
        )

    def test_detail_returns_404_when_not_found(self):
        module = self.router_module()

        if module is None:
            return

        function = getattr(
            module,
            "get_finding",
            None,
        )

        self.assertIsNotNone(function)

        if function is None:
            return

        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        finding_id = (
            f"{uuid4()}:"
            "missing-security-header:csp"
        )

        with patch.object(
            module,
            "build_workspace_detail",
            return_value=None,
        ):
            with self.assertRaises(
                HTTPException
            ) as context:
                function(
                    finding_id=finding_id,
                    current_user=user,
                    database=object(),
                )

        self.assertEqual(
            context.exception.status_code,
            404,
        )

        self.assertEqual(
            context.exception.detail,
            "Finding not found.",
        )

    def test_main_application_registers_findings_router(self):
        import app.main as main_module

        schema = main_module.app.openapi()

        paths = schema.get(
            "paths",
            {},
        )

        self.assertIn(
            "/api/v1/findings",
            paths,
        )

        self.assertIn(
            "get",
            paths[
                "/api/v1/findings"
            ],
        )

        self.assertIn(
            "/api/v1/findings/{finding_id}",
            paths,
        )

        self.assertIn(
            "get",
            paths[
                "/api/v1/findings/{finding_id}"
            ],
        )


def _test_list_ignores_unknown_classification(self):
    module = self.router_module()

    if module is None:
        return

    function = getattr(
        module,
        "list_findings",
        None,
    )

    self.assertIsNotNone(function)

    if function is None:
        return

    user = SimpleNamespace(
        id=uuid4(),
        role="user",
    )

    rows = [
        _workspace_api_row(),
    ]

    with (
        patch.object(
            module,
            "build_workspace_rows",
            return_value=rows,
        ),
        patch.object(
            module,
            "filter_workspace_rows",
            return_value=rows,
        ) as filter_rows,
    ):
        page = function(
            current_user=user,
            database=object(),
            severity=None,
            confidence=None,
            target_id=None,
            scan_id=None,
            tool=None,
            classification="not-a-real-classification",
            q=None,
            offset=0,
            limit=50,
        )

    filter_rows.assert_called_once_with(
        rows,
        severity=None,
        confidence=None,
        target_id=None,
        scan_id=None,
        tool=None,
        classification=None,
        q=None,
    )

    self.assertEqual(
        page.total,
        1,
    )


FindingsWorkspaceRouterTests.test_list_ignores_unknown_classification = (
    _test_list_ignores_unknown_classification
)


def _test_openapi_enforces_pagination_bounds(self):
    import app.main as main_module

    schema = main_module.app.openapi()

    operation = schema[
        "paths"
    ][
        "/api/v1/findings"
    ][
        "get"
    ]

    parameters = {
        parameter["name"]: parameter
        for parameter in operation["parameters"]
    }

    offset_schema = parameters[
        "offset"
    ][
        "schema"
    ]

    limit_schema = parameters[
        "limit"
    ][
        "schema"
    ]

    self.assertEqual(
        offset_schema["minimum"],
        0,
    )

    self.assertEqual(
        offset_schema["default"],
        0,
    )

    self.assertEqual(
        limit_schema["minimum"],
        1,
    )

    self.assertEqual(
        limit_schema["maximum"],
        100,
    )

    self.assertEqual(
        limit_schema["default"],
        50,
    )


FindingsWorkspaceRouterTests.test_openapi_enforces_pagination_bounds = (
    _test_openapi_enforces_pagination_bounds
)
