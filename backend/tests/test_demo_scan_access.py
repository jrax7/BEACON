import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.organizations.rbac import OrganizationRole
from app.organizations.service import (
    create_personal_organization,
)
from app.routers import scans as scan_router
from app.schemas.scans import ScanBulkActionRequest, ScanCreate


@compiles(JSONB, "sqlite")
def compile_jsonb_for_sqlite(
    _type,
    _compiler,
    **_kwargs,
):
    """Allow PostgreSQL JSONB columns in SQLite-only tests."""

    return "JSON"


class DemoScanAccessTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={
                "check_same_thread": False,
            },
            poolclass=StaticPool,
        )

        User.__table__.create(self.engine)
        Organization.__table__.create(
            self.engine
        )
        OrganizationMembership.__table__.create(
            self.engine
        )
        Target.__table__.create(self.engine)
        Scan.__table__.create(self.engine)
        AuditLog.__table__.create(self.engine)

        self.database = Session(
            self.engine,
            expire_on_commit=False,
        )

        self.demo_user = User(
            email="demo@beacon.example.com",
            full_name="BEACON Demo",
            password_hash="not-used",
            role="demo",
            is_active=True,
            is_email_verified=False,
        )

        self.normal_user = User(
            email="user@example.com",
            full_name="Normal User",
            password_hash="not-used",
            role="user",
            is_active=True,
            is_email_verified=False,
        )

        self.database.add_all(
            [
                self.demo_user,
                self.normal_user,
            ]
        )
        self.database.flush()

        self.demo_organization, _ = (
            create_personal_organization(
                self.database,
                self.demo_user,
                role=OrganizationRole.ANALYST,
                name="Demo Workspace",
            )
        )

        self.normal_organization, _ = (
            create_personal_organization(
                self.database,
                self.normal_user,
                role=OrganizationRole.ADMIN,
                name="Normal Workspace",
            )
        )


        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(days=30)
        )

        self.demo_lab_target = Target(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            original_url="http://lab-target/",
            normalized_url="http://lab-target/",
            hostname="lab-target",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=datetime.now(timezone.utc),
            verification_expires_at=expires_at,
        )

        self.demo_other_target = Target(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            original_url="https://example.com/",
            normalized_url="https://example.com/",
            hostname="example.com",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=datetime.now(timezone.utc),
            verification_expires_at=expires_at,
        )

        self.normal_target_a = Target(
            organization_id=self.normal_organization.id,
            user_id=self.normal_user.id,
            original_url="https://normal-a.test/",
            normalized_url="https://normal-a.test/",
            hostname="normal-a.test",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=datetime.now(timezone.utc),
            verification_expires_at=expires_at,
        )

        self.normal_target_b = Target(
            organization_id=self.normal_organization.id,
            user_id=self.normal_user.id,
            original_url="https://normal-b.test/",
            normalized_url="https://normal-b.test/",
            hostname="normal-b.test",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
            verified_at=datetime.now(timezone.utc),
            verification_expires_at=expires_at,
        )

        self.database.add_all(
            [
                self.demo_lab_target,
                self.demo_other_target,
                self.normal_target_a,
                self.normal_target_b,
            ]
        )
        self.database.flush()

    def tearDown(self):
        self.database.rollback()
        self.database.close()
        self.engine.dispose()

    def assert_http_status(
        self,
        expected_status,
        callback,
    ):
        with self.assertRaises(HTTPException) as context:
            callback()

        self.assertEqual(
            context.exception.status_code,
            expected_status,
        )

    def test_demo_scan_requires_configured_lab_target(self):
        request = ScanCreate(
            target_id=self.demo_other_target.id,
            scan_level="basic",
        )

        with patch.object(
            scan_router,
            "validate_target_destination",
            return_value=["203.0.113.10"],
        ):
            with patch.object(
                scan_router.run_basic_scan,
                "delay",
                return_value=SimpleNamespace(
                    id="should-not-run",
                ),
            ) as mock_delay:
                self.assert_http_status(
                    404,
                    lambda: scan_router.create_scan(
                        request,
                        self.demo_user,
                        self.database,
                    ),
                )

                mock_delay.assert_not_called()

    def test_demo_scan_level_is_basic_only(self):
        request = SimpleNamespace(
            target_id=self.demo_lab_target.id,
            scan_level="deep",
        )

        with patch.object(
            scan_router,
            "validate_target_destination",
            return_value=["127.0.0.1"],
        ):
            with patch.object(
                scan_router.run_basic_scan,
                "delay",
                return_value=SimpleNamespace(
                    id="should-not-run",
                ),
            ) as mock_delay:
                self.assert_http_status(
                    403,
                    lambda: scan_router.create_scan(
                        request,
                        self.demo_user,
                        self.database,
                    ),
                )

                mock_delay.assert_not_called()

    def test_demo_active_scan_is_account_wide(self):
        active_scan = Scan(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            target_id=self.demo_other_target.id,
            scan_level="basic",
            status="queued",
            progress=0,
        )

        self.database.add(active_scan)
        self.database.flush()

        request = ScanCreate(
            target_id=self.demo_lab_target.id,
            scan_level="basic",
        )

        with patch.object(
            scan_router,
            "validate_target_destination",
            return_value=["127.0.0.1"],
        ):
            with patch.object(
                scan_router.run_basic_scan,
                "delay",
                return_value=SimpleNamespace(
                    id="should-not-run",
                ),
            ) as mock_delay:
                self.assert_http_status(
                    409,
                    lambda: scan_router.create_scan(
                        request,
                        self.demo_user,
                        self.database,
                    ),
                )

                mock_delay.assert_not_called()

    def test_normal_user_concurrency_remains_per_target(self):
        existing_scan = Scan(
            organization_id=self.normal_organization.id,
            user_id=self.normal_user.id,
            target_id=self.normal_target_b.id,
            scan_level="basic",
            status="running",
            progress=50,
        )

        self.database.add(existing_scan)
        self.database.flush()

        request = ScanCreate(
            target_id=self.normal_target_a.id,
            scan_level="basic",
        )

        with patch.object(
            scan_router,
            "validate_target_destination",
            return_value=["203.0.113.20"],
        ):
            with patch.object(
                scan_router.run_basic_scan,
                "delay",
                return_value=SimpleNamespace(
                    id="normal-task",
                ),
            ) as mock_delay:
                created_scan = scan_router.create_scan(
                    request,
                    self.normal_user,
                    self.database,
                )

        self.assertEqual(
            created_scan.target_id,
            self.normal_target_a.id,
        )
        self.assertEqual(
            created_scan.status,
            "queued",
        )
        self.assertEqual(
            created_scan.celery_task_id,
            "normal-task",
        )

        mock_delay.assert_called_once()

    def test_demo_cannot_bulk_archive_scans(self):
        request = ScanBulkActionRequest(
            scan_ids=[uuid4()],
        )

        with patch.object(
            scan_router,
            "get_owned_scans",
            side_effect=AssertionError(
                "Demo bulk archive must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.bulk_archive_scans(
                    request,
                    self.demo_user,
                    MagicMock(),
                ),
            )

    def test_demo_cannot_bulk_restore_scans(self):
        request = ScanBulkActionRequest(
            scan_ids=[uuid4()],
        )

        with patch.object(
            scan_router,
            "get_owned_scans",
            side_effect=AssertionError(
                "Demo bulk restore must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.bulk_restore_scans(
                    request,
                    self.demo_user,
                    MagicMock(),
                ),
            )

    def test_demo_cannot_archive_scan(self):
        scan_id = uuid4()

        with patch.object(
            scan_router,
            "get_owned_scan",
            side_effect=AssertionError(
                "Demo archive must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.archive_scan(
                    scan_id,
                    self.demo_user,
                    MagicMock(),
                ),
            )

    def test_demo_cannot_restore_scan(self):
        scan_id = uuid4()

        with patch.object(
            scan_router,
            "get_owned_scan",
            side_effect=AssertionError(
                "Demo restore must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.restore_scan(
                    scan_id,
                    self.demo_user,
                    MagicMock(),
                ),
            )

    def test_demo_cannot_delete_scan(self):
        scan_id = uuid4()

        with patch.object(
            scan_router,
            "get_owned_scan",
            side_effect=AssertionError(
                "Demo deletion must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.delete_scan(
                    scan_id,
                    self.demo_user,
                    MagicMock(),
                ),
            )

    def test_demo_cannot_bulk_delete_scans(self):
        request = ScanBulkActionRequest(
            scan_ids=[uuid4()],
        )

        with patch.object(
            scan_router,
            "get_owned_scans",
            side_effect=AssertionError(
                "Demo bulk deletion must be blocked "
                "before scan lookup."
            ),
        ):
            self.assert_http_status(
                403,
                lambda: scan_router.bulk_delete_scans(
                    request,
                    self.demo_user,
                    MagicMock(),
                ),
            )


if __name__ == "__main__":
    unittest.main()
