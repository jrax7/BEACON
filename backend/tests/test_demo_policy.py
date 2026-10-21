import unittest
from types import SimpleNamespace

from fastapi import HTTPException

from app.security.demo import (
    ensure_demo_active_scan_allowed,
    ensure_demo_mutation_allowed,
    ensure_demo_scan_level_allowed,
    ensure_demo_target_allowed,
    is_demo_user,
)


class DemoPolicyTests(unittest.TestCase):
    def setUp(self):
        self.demo_user = SimpleNamespace(
            role="demo",
        )

        self.normal_user = SimpleNamespace(
            role="user",
        )

        self.lab_target = SimpleNamespace(
            hostname="lab-target",
            normalized_url="http://lab-target/",
        )

        self.other_target = SimpleNamespace(
            hostname="example.com",
            normalized_url="https://example.com/",
        )

    def test_identifies_demo_role(self):
        self.assertTrue(
            is_demo_user(self.demo_user)
        )

        self.assertFalse(
            is_demo_user(self.normal_user)
        )

    def test_normal_user_mutation_remains_allowed(self):
        self.assertIsNone(
            ensure_demo_mutation_allowed(
                self.normal_user,
            )
        )

    def test_demo_mutation_is_forbidden(self):
        with self.assertRaises(
            HTTPException
        ) as context:
            ensure_demo_mutation_allowed(
                self.demo_user,
            )

        self.assertEqual(
            context.exception.status_code,
            403,
        )

    def test_demo_target_must_match_configured_lab_target(
        self,
    ):
        self.assertIsNone(
            ensure_demo_target_allowed(
                self.demo_user,
                self.lab_target,
            )
        )

        with self.assertRaises(
            HTTPException
        ) as context:
            ensure_demo_target_allowed(
                self.demo_user,
                self.other_target,
            )

        self.assertEqual(
            context.exception.status_code,
            404,
        )

    def test_normal_user_target_is_not_restricted_by_demo_policy(
        self,
    ):
        self.assertIsNone(
            ensure_demo_target_allowed(
                self.normal_user,
                self.other_target,
            )
        )

    def test_demo_scan_level_is_basic_only(self):
        self.assertIsNone(
            ensure_demo_scan_level_allowed(
                self.demo_user,
                "basic",
            )
        )

        with self.assertRaises(
            HTTPException
        ) as context:
            ensure_demo_scan_level_allowed(
                self.demo_user,
                "deep",
            )

        self.assertEqual(
            context.exception.status_code,
            403,
        )

    def test_normal_user_scan_level_is_not_changed_by_demo_policy(
        self,
    ):
        self.assertIsNone(
            ensure_demo_scan_level_allowed(
                self.normal_user,
                "deep",
            )
        )

    def test_demo_may_scan_when_no_demo_scan_is_active(
        self,
    ):
        self.assertIsNone(
            ensure_demo_active_scan_allowed(
                self.demo_user,
                None,
            )
        )

    def test_demo_second_active_scan_is_rejected(self):
        active_scan = SimpleNamespace(
            id="active",
        )

        with self.assertRaises(
            HTTPException
        ) as context:
            ensure_demo_active_scan_allowed(
                self.demo_user,
                active_scan,
            )

        self.assertEqual(
            context.exception.status_code,
            409,
        )

    def test_normal_user_is_not_affected_by_demo_active_scan_policy(
        self,
    ):
        active_scan = SimpleNamespace(
            id="active",
        )

        self.assertIsNone(
            ensure_demo_active_scan_allowed(
                self.normal_user,
                active_scan,
            )
        )


if __name__ == "__main__":
    unittest.main()
