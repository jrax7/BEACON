import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

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
from app.routers import targets as target_router
from app.schemas.targets import TargetCreate


class DemoTargetAccessTests(unittest.TestCase):
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


        self.lab_target = Target(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            original_url="http://lab-target/",
            normalized_url="http://lab-target/",
            hostname="lab-target",
            verification_method="file",
            verification_token_hash=None,
            verification_status="verified",
        )

        self.unexpected_demo_target = Target(
            organization_id=self.demo_organization.id,
            user_id=self.demo_user.id,
            original_url="https://example.com/",
            normalized_url="https://example.com/",
            hostname="example.com",
            verification_method="file",
            verification_token_hash=None,
            verification_status="pending",
        )

        self.normal_target = Target(
            organization_id=self.normal_organization.id,
            user_id=self.normal_user.id,
            original_url="https://example.org/",
            normalized_url="https://example.org/",
            hostname="example.org",
            verification_method="file",
            verification_token_hash=None,
            verification_status="pending",
        )

        self.database.add_all(
            [
                self.lab_target,
                self.unexpected_demo_target,
                self.normal_target,
            ]
        )
        self.database.commit()

    def tearDown(self):
        self.database.close()
        self.engine.dispose()

    def assert_forbidden(self, callback):
        with self.assertRaises(HTTPException) as context:
            callback()

        self.assertEqual(
            context.exception.status_code,
            403,
        )

    def test_demo_list_only_returns_configured_lab_target(self):
        targets = target_router.list_targets(
            self.demo_user,
            self.database,
        )

        self.assertEqual(
            [target.id for target in targets],
            [self.lab_target.id],
        )

    def test_normal_user_target_listing_is_unchanged(self):
        targets = target_router.list_targets(
            self.normal_user,
            self.database,
        )

        self.assertEqual(
            [target.id for target in targets],
            [self.normal_target.id],
        )

    def test_demo_can_read_configured_lab_target(self):
        target = target_router.read_target(
            self.lab_target.id,
            self.demo_user,
            self.database,
        )

        self.assertEqual(
            target.id,
            self.lab_target.id,
        )

    def test_demo_cannot_read_unexpected_owned_target(self):
        with self.assertRaises(HTTPException) as context:
            target_router.read_target(
                self.unexpected_demo_target.id,
                self.demo_user,
                self.database,
            )

        self.assertEqual(
            context.exception.status_code,
            404,
        )

    def test_demo_cannot_create_target(self):
        request = TargetCreate(
            url="https://example.net/",
            verification_method="file",
        )

        with patch.object(
            target_router,
            "validate_target_destination",
            side_effect=AssertionError(
                "Demo create should be blocked before validation."
            ),
        ):
            self.assert_forbidden(
                lambda: target_router.create_target(
                    request,
                    self.demo_user,
                    self.database,
                )
            )

    def test_demo_cannot_delete_target(self):
        with patch.object(
            target_router,
            "get_owned_target",
            side_effect=AssertionError(
                "Demo delete should be blocked before target lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: target_router.delete_target(
                    self.lab_target.id,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_regenerate_verification_token(self):
        with patch.object(
            target_router,
            "get_owned_target",
            side_effect=AssertionError(
                "Demo token regeneration should be blocked "
                "before target lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: target_router.regenerate_verification_token(
                    self.lab_target.id,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_verify_target_by_file(self):
        with patch.object(
            target_router,
            "get_owned_target",
            side_effect=AssertionError(
                "Demo file verification should be blocked "
                "before target lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: target_router.verify_target_file(
                    self.lab_target.id,
                    self.demo_user,
                    MagicMock(),
                )
            )

    def test_demo_cannot_verify_target_by_dns(self):
        with patch.object(
            target_router,
            "get_owned_target",
            side_effect=AssertionError(
                "Demo DNS verification should be blocked "
                "before target lookup."
            ),
        ):
            self.assert_forbidden(
                lambda: target_router.verify_target_dns(
                    self.lab_target.id,
                    self.demo_user,
                    MagicMock(),
                )
            )


if __name__ == "__main__":
    unittest.main()
