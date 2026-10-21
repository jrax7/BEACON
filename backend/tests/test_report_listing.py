import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.routers import reports as report_router
from app.schemas import reports as report_schemas


NOW = datetime(
    2026,
    8,
    20,
    12,
    0,
    tzinfo=timezone.utc,
)


class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class CapturingDatabase:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        return FakeResult(self.rows)


def make_row(
    *,
    user_id,
    organization_id,
    archived_at=None,
):
    target_id = uuid4()
    scan_id = uuid4()
    report_id = uuid4()

    target = Target(
        id=target_id,
        organization_id=organization_id,
        user_id=user_id,
        original_url="https://example.test/",
        normalized_url="https://example.test/",
        hostname="example.test",
        verification_status="verified",
        created_at=NOW,
        updated_at=NOW,
    )

    scan = Scan(
        id=scan_id,
        organization_id=organization_id,
        user_id=user_id,
        target_id=target_id,
        scan_level="basic",
        status="completed",
        progress=100,
        completed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )

    report = Report(
        id=report_id,
        scan_id=scan_id,
        format="pdf",
        file_path="reports/example.pdf",
        checksum_sha256="a" * 64,
        archived_at=archived_at,
        generated_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )

    return report, scan, target


class GlobalReportListingTests(unittest.TestCase):
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

        self.context_patch = patch.object(
            report_router,
            "resolve_organization_context",
            return_value=(
                self.organization_context
            ),
        )

        self.context_patch.start()

        self.addCleanup(
            self.context_patch.stop
        )


    def list_function(self):
        function = getattr(
            report_router,
            "list_reports",
            None,
        )

        self.assertIsNotNone(
            function,
            "Global report listing endpoint is missing.",
        )

        return function

    def test_global_report_response_schema_exists(self):
        schema = getattr(
            report_schemas,
            "ReportListItemResponse",
            None,
        )

        self.assertIsNotNone(
            schema,
            "ReportListItemResponse is missing.",
        )

        if schema is None:
            return

        fields = set(schema.model_fields)

        self.assertTrue(
            {
                "id",
                "scan_id",
                "target_id",
                "target_hostname",
                "target_url",
                "scan_level",
                "scan_status",
                "format",
                "checksum_sha256",
                "archived_at",
                "generated_at",
                "created_at",
                "download_url",
            }.issubset(fields)
        )

    def test_router_exposes_authenticated_global_report_list(self):
        route = next(
            (
                route
                for route in report_router.router.routes
                if route.path == "/api/v1/reports"
                and "GET" in route.methods
            ),
            None,
        )

        self.assertIsNotNone(
            route,
            "GET /api/v1/reports is missing.",
        )

    def test_listing_returns_joined_context_with_one_query(self):
        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        row = make_row(user_id=user.id, organization_id=self.organization_id)
        database = CapturingDatabase([row])

        function = self.list_function()

        if function is None:
            return

        items = function(
            current_user=user,
            database=database,
            archived="active",
        )

        self.assertEqual(
            len(database.statements),
            1,
            "Global report listing must use one joined query.",
        )

        self.assertEqual(len(items), 1)

        item = items[0]
        report, scan, target = row

        self.assertEqual(item.id, report.id)
        self.assertEqual(item.scan_id, scan.id)
        self.assertEqual(item.target_id, target.id)
        self.assertEqual(
            item.target_hostname,
            target.hostname,
        )
        self.assertEqual(
            item.target_url,
            target.normalized_url,
        )
        self.assertEqual(
            item.scan_level,
            scan.scan_level,
        )
        self.assertEqual(
            item.scan_status,
            scan.status,
        )
        self.assertEqual(
            item.download_url,
            f"/api/v1/reports/{report.id}/download",
        )

    def test_listing_query_is_scoped_to_current_user(self):
        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        database = CapturingDatabase(
            [make_row(user_id=user.id, organization_id=self.organization_id)]
        )

        function = self.list_function()

        if function is None:
            return

        function(
            current_user=user,
            database=database,
            archived="all",
        )

        statement = database.statements[0]
        compiled = statement.compile()

        sql = str(compiled).lower()

        self.assertIn(
            "scans.organization_id",
            sql,
        )

        self.assertIn(
            self.organization_id,
            compiled.params.values(),
        )

    def test_listing_applies_report_archive_filters(self):
        user = SimpleNamespace(
            id=uuid4(),
            role="user",
        )

        function = self.list_function()

        if function is None:
            return

        active_database = CapturingDatabase([])
        function(
            current_user=user,
            database=active_database,
            archived="active",
        )

        active_sql = str(
            active_database.statements[0].compile()
        ).lower()

        self.assertIn(
            "reports.archived_at is null",
            active_sql,
        )

        archived_database = CapturingDatabase([])
        function(
            current_user=user,
            database=archived_database,
            archived="archived",
        )

        archived_sql = str(
            archived_database.statements[0].compile()
        ).lower()

        self.assertIn(
            "reports.archived_at is not null",
            archived_sql,
        )

        all_database = CapturingDatabase([])
        function(
            current_user=user,
            database=all_database,
            archived="all",
        )

        all_sql = str(
            all_database.statements[0].compile()
        ).lower()

        self.assertNotIn(
            "reports.archived_at is null",
            all_sql,
        )
        self.assertNotIn(
            "reports.archived_at is not null",
            all_sql,
        )

    def test_demo_user_can_read_owned_report_listing(self):
        user = SimpleNamespace(
            id=uuid4(),
            role="demo",
        )

        row = make_row(user_id=user.id, organization_id=self.organization_id)
        database = CapturingDatabase([row])

        function = self.list_function()

        if function is None:
            return

        items = function(
            current_user=user,
            database=database,
            archived="all",
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].id, row[0].id)


if __name__ == "__main__":
    unittest.main()
