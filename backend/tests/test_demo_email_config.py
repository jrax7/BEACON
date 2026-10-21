import unittest

from pydantic import EmailStr, TypeAdapter

from app.config import Settings


class DemoEmailConfigTests(unittest.TestCase):
    def test_default_demo_email_is_valid_api_email(self):
        demo_email = Settings.model_fields[
            "demo_user_email"
        ].default

        validated = TypeAdapter(
            EmailStr
        ).validate_python(
            demo_email
        )

        self.assertEqual(
            str(validated),
            demo_email,
        )


if __name__ == "__main__":
    unittest.main()
