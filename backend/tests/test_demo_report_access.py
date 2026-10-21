import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi import HTTPException

from app.routers import reports as report_router
from app.schemas.reports import (
    ReportBulkActionRequest,
    ReportGenerateRequest,
)


class DemoReportAccessTests(unittest.TestCase):
    def setUp(self):
        self.demo_user = SimpleNamespace(
            id=uuid4(),
            role="demo",
        )

        self.organization_id = uuid4()

        self.organization_context = (
            SimpleNamespace(
                organization=SimpleNamespace(
                    id=self.organization_id,
                ),
                role="analyst",
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

    def assert_forbidden(
        self,
        callback,
    ):
        with self.assertRaises(HTTPException) as context:
            callback()

        self.assertEqual(
            context.exception.status_code,
            403,
        )

    def test_demo_can_request_report_generation(self):
        scan = SimpleNamespace(
            id=uuid4(),
            organization_id=(
                self.organization_id
            ),
            target_id=uuid4(),
            status="completed",
            archived_at=None,
        )

        request = ReportGenerateRequest(
            formats=[
                "html",
                "pdf",
            ]
        )

        database = MagicMock()

        with patch.object(
            report_router,
            "get_owned_scan",
            return_value=scan,
        ):
            with patch.object(
                report_router.generate_scan_report,
                "delay",
                return_value=SimpleNamespace(
                    id="demo-report-task",
                ),
            ) as mock_delay:
                response = (
                    report_router.request_report_generation(
                        scan.id,
                        request,
                        self.demo_user,
                        database,
                    )
                )

        self.assertEqual(
            response.scan_id,
            scan.id,
        )
        self.assertEqual(
            response.task_id,
            "demo-report-task",
        )
        self.assertEqual(
            response.status,
            "queued",
        )

        mock_delay.assert_called_once_with(
            str(scan.id),
            [
                "html",
                "pdf",
            ],
        )

    def test_demo_can_read_owned_report(self):
        report_id = uuid4()
        scan_id = uuid4()
        now = datetime.now(timezone.utc)

        report = SimpleNamespace(
            id=report_id,
            scan_id=scan_id,
            format="html",
            checksum_sha256="a" * 64,
            archived_at=None,
            generated_at=now,
            created_at=now,
        )

        with patch.object(
            report_router,
            "get_owned_report",
            return_value=(
                report,
                MagicMock(),
                MagicMock(),
            ),
        ):
            response = report_router.read_report(
                report_id,
                self.demo_user,
                MagicMock(),
            )

        self.assertEqual(
            response.id,
            report_id,
        )
        self.assertEqual(
            response.scan_id,
            scan_id,
        )
        self.assertEqual(
            response.format,
            "html",
        )

    def test_demo_can_download_owned_report(self):
        report_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        checksum = "b" * 64

        with tempfile.TemporaryDirectory() as directory:
            report_path = (
                Path(directory)
                / "demo-report.html"
            )
            report_path.write_text(
                "<html>demo</html>"
            )

            report = SimpleNamespace(
                id=report_id,
                scan_id=scan_id,
                format="html",
                file_path="reports/demo-report.html",
                checksum_sha256=checksum,
                archived_at=None,
            )

            scan = SimpleNamespace(
                id=scan_id,
                organization_id=(
                    self.organization_id
                ),
            )

            target = SimpleNamespace(
                id=target_id,
                hostname="lab-target",
            )

            database = MagicMock()

            with patch.object(
                report_router,
                "get_owned_report",
                return_value=(
                    report,
                    scan,
                    target,
                ),
            ):
                with patch.object(
                    report_router,
                    "resolve_report_path",
                    return_value=report_path,
                ):
                    with patch.object(
                        report_router,
                        "sha256_file",
                        return_value=checksum,
                    ):
                        response = (
                            report_router.download_report(
                                report_id,
                                self.demo_user,
                                database,
                            )
                        )

        self.assertEqual(
            response.media_type,
            "text/html; charset=utf-8",
        )
        self.assertEqual(
            response.headers[
                "x-beacon-sha256"
            ],
            checksum,
        )

    def test_demo_cannot_bulk_archive_reports(self):
        request = ReportBulkActionRequest(
            report_ids=[uuid4()],
        )

        with patch.object(
            report_router,
            "get_owned_reports",
            side_effect=AssertionError(
                "Demo bulk archive must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.bulk_archive_reports(
                    request,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_bulk_restore_reports(self):
        request = ReportBulkActionRequest(
            report_ids=[uuid4()],
        )

        with patch.object(
            report_router,
            "get_owned_reports",
            side_effect=AssertionError(
                "Demo bulk restore must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.bulk_restore_reports(
                    request,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_bulk_delete_reports(self):
        request = ReportBulkActionRequest(
            report_ids=[uuid4()],
        )

        with patch.object(
            report_router,
            "get_owned_reports",
            side_effect=AssertionError(
                "Demo bulk delete must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.bulk_delete_reports(
                    request,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_archive_report(self):
        report_id = uuid4()

        with patch.object(
            report_router,
            "get_owned_report",
            side_effect=AssertionError(
                "Demo archive must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.archive_report(
                    report_id,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_restore_report(self):
        report_id = uuid4()

        with patch.object(
            report_router,
            "get_owned_report",
            side_effect=AssertionError(
                "Demo restore must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.restore_report(
                    report_id,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_delete_report(self):
        report_id = uuid4()

        with patch.object(
            report_router,
            "get_owned_report",
            side_effect=AssertionError(
                "Demo delete must be blocked "
                "before report lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: report_router.delete_report(
                    report_id,
                    self.demo_user,
                    MagicMock(),
                )
            )


if __name__ == "__main__":
    unittest.main()
