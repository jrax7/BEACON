import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.models.organization import Organization
from app.models.organization_membership import (
    OrganizationMembership,
)
from app.models.target import Target
from app.models.user import User
from app.scripts.provision_demo import (
    provision_demo,
    validate_demo_password,
)
from app.security.auth import (
    hash_password,
    verify_password,
)


class DemoProvisioningTests(unittest.TestCase):
    def setUp(self):
        self._demo_target_patch = patch.object(
            settings,
            "demo_target_url",
            "http://lab-target/",
        )
        self._demo_allow_patch = patch(
            "app.scripts.provision_demo.is_allowed_lab_target",
            side_effect=lambda hostname: hostname == "lab-target",
        )

        self._demo_target_patch.start()
        self._demo_allow_patch.start()

        self.addCleanup(
            self._demo_target_patch.stop
        )
        self.addCleanup(
            self._demo_allow_patch.stop
        )

        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={
                "check_same_thread": False,
            },
            poolclass=StaticPool,
        )

        User.__table__.create(self.engine)
        Organization.__table__.create(self.engine)
        OrganizationMembership.__table__.create(
            self.engine
        )
        Target.__table__.create(self.engine)

        self.database = Session(
            self.engine,
            expire_on_commit=False,
        )

    def tearDown(self):
        self.database.close()
        self.engine.dispose()

    def test_password_must_be_at_least_twelve_characters(self):
        with self.assertRaises(ValueError):
            validate_demo_password("short")

    def test_password_must_not_exceed_128_characters(self):
        with self.assertRaises(ValueError):
            validate_demo_password("x" * 129)

    def test_valid_password_is_returned_unchanged(self):
        password = "DemoPassword-2026"

        self.assertEqual(
            validate_demo_password(password),
            password,
        )

    def test_provisions_demo_user_and_verified_lab_target(self):
        user, target, created_user = provision_demo(
            self.database,
            "DemoPassword-2026",
        )

        self.assertTrue(created_user)

        self.assertEqual(
            user.email,
            settings.demo_user_email,
        )
        self.assertEqual(
            user.full_name,
            "BEACON Demo",
        )
        self.assertEqual(
            user.role,
            "demo",
        )
        self.assertTrue(user.is_active)

        self.assertTrue(
            verify_password(
                "DemoPassword-2026",
                user.password_hash,
            )
        )

        self.assertEqual(
            target.user_id,
            user.id,
        )
        self.assertEqual(
            target.hostname,
            "lab-target",
        )
        self.assertEqual(
            target.normalized_url,
            "http://lab-target/",
        )
        self.assertEqual(
            target.verification_method,
            "file",
        )
        self.assertEqual(
            target.verification_status,
            "verified",
        )
        self.assertIsNone(
            target.verification_token_hash,
        )
        self.assertIsNotNone(
            target.verified_at,
        )
        self.assertIsNotNone(
            target.verification_expires_at,
        )
        self.assertGreater(
            target.verification_expires_at,
            target.verified_at,
        )

        user_count = self.database.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.email == settings.demo_user_email,
            )
        )

        target_count = self.database.scalar(
            select(func.count())
            .select_from(Target)
            .where(
                Target.user_id == user.id,
            )
        )

        self.assertEqual(user_count, 1)
        self.assertEqual(target_count, 1)

    def test_reprovisioning_is_idempotent_and_updates_password(self):
        first_user, first_target, first_created = provision_demo(
            self.database,
            "DemoPassword-2026",
        )

        second_user, second_target, second_created = provision_demo(
            self.database,
            "ReplacementPassword-2026",
        )

        self.assertTrue(first_created)
        self.assertFalse(second_created)

        self.assertEqual(
            first_user.id,
            second_user.id,
        )
        self.assertEqual(
            first_target.id,
            second_target.id,
        )

        user_count = self.database.scalar(
            select(func.count())
            .select_from(User)
            .where(
                User.email == settings.demo_user_email,
            )
        )

        target_count = self.database.scalar(
            select(func.count())
            .select_from(Target)
            .where(
                Target.user_id == second_user.id,
            )
        )

        self.assertEqual(user_count, 1)
        self.assertEqual(target_count, 1)

        self.assertTrue(
            verify_password(
                "ReplacementPassword-2026",
                second_user.password_hash,
            )
        )

        self.assertFalse(
            verify_password(
                "DemoPassword-2026",
                second_user.password_hash,
            )
        )

    def test_refuses_to_convert_existing_normal_user(self):
        existing_user = User(
            email=settings.demo_user_email,
            full_name="Existing User",
            password_hash=hash_password(
                "ExistingPassword-2026",
            ),
            role="user",
            is_active=True,
            is_email_verified=False,
        )

        self.database.add(existing_user)
        self.database.commit()

        with self.assertRaisesRegex(
            RuntimeError,
            "non-demo",
        ):
            provision_demo(
                self.database,
                "DemoPassword-2026",
            )

        self.database.refresh(existing_user)

        self.assertEqual(
            existing_user.role,
            "user",
        )

    def test_refuses_demo_account_with_unexpected_extra_target(self):
        user, demo_target, _ = provision_demo(
            self.database,
            "DemoPassword-2026",
        )

        original_password_hash = user.password_hash

        unexpected_target = Target(
            organization_id=demo_target.organization_id,
            user_id=user.id,
            original_url="https://example.com/",
            normalized_url="https://example.com/",
            hostname="example.com",
            verification_method="file",
            verification_token_hash=None,
            verification_status="pending",
        )

        self.database.add(unexpected_target)
        self.database.commit()

        with self.assertRaisesRegex(
            RuntimeError,
            "unexpected targets",
        ):
            provision_demo(
                self.database,
                "ReplacementPassword-2026",
            )

        self.database.refresh(user)

        self.assertEqual(
            user.password_hash,
            original_password_hash,
        )

    def test_refuses_unapproved_demo_target(self):
        with patch.object(
            settings,
            "demo_target_url",
            "http://not-approved/",
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "allowed lab target",
            ):
                provision_demo(
                    self.database,
                    "DemoPassword-2026",
                )

        user_count = self.database.scalar(
            select(func.count())
            .select_from(User)
        )

        target_count = self.database.scalar(
            select(func.count())
            .select_from(Target)
        )

        self.assertEqual(user_count, 0)
        self.assertEqual(target_count, 0)

    def test_phase16b_demo_account_is_email_verified(self):
        user, _, _ = provision_demo(
            self.database,
            "DemoPassword-2026",
        )

        self.assertTrue(
            user.is_email_verified
        )


if __name__ == "__main__":
    unittest.main()
