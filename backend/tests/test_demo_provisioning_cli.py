import unittest
from unittest.mock import MagicMock, patch

from app.scripts import provision_demo


class DemoProvisioningCliTests(unittest.TestCase):
    @patch.object(
        provision_demo.getpass,
        "getpass",
        side_effect=[
            "DemoPassword-2026",
            "DifferentPassword-2026",
        ],
    )
    def test_main_rejects_password_mismatch(
        self,
        _mock_getpass,
    ):
        with patch.object(
            provision_demo,
            "provision_demo",
        ) as mock_provision:
            with self.assertRaisesRegex(
                SystemExit,
                "Passwords do not match",
            ):
                provision_demo.main()

            mock_provision.assert_not_called()

    @patch.object(
        provision_demo.getpass,
        "getpass",
        side_effect=[
            "DemoPassword-2026",
            "DemoPassword-2026",
        ],
    )
    def test_main_provisions_using_session(
        self,
        _mock_getpass,
    ):
        fake_database = MagicMock()
        fake_user = MagicMock()
        fake_target = MagicMock()

        fake_user.email = "demo@beacon.example.com"
        fake_target.hostname = "lab-target"

        session_context = MagicMock()
        session_context.__enter__.return_value = fake_database

        with patch.object(
            provision_demo,
            "SessionLocal",
            return_value=session_context,
        ):
            with patch.object(
                provision_demo,
                "provision_demo",
                return_value=(
                    fake_user,
                    fake_target,
                    True,
                ),
            ) as mock_provision:
                provision_demo.main()

        mock_provision.assert_called_once_with(
            fake_database,
            "DemoPassword-2026",
        )


if __name__ == "__main__":
    unittest.main()
