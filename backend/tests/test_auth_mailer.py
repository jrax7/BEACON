from __future__ import annotations

import inspect
from smtplib import SMTPException
from types import SimpleNamespace


def _settings():
    return SimpleNamespace(
        public_url="https://beacon.example.com",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="beacon",
        smtp_password="smtp-secret",
        smtp_starttls=True,
        smtp_from_address="no-reply@beacon.example.com",
        smtp_from_name="BEACON",
        smtp_timeout_seconds=10,
    )


def test_verification_url_uses_fragment_not_query() -> None:
    from app.auth.mailer import email_verification_url

    url = email_verification_url(
        "raw-secret-token",
        runtime_settings=_settings(),
    )

    assert (
        url
        == "https://beacon.example.com/"
        "verify-email#token=raw-secret-token"
    )

    assert "?token=" not in url


def test_password_reset_url_uses_fragment_not_query() -> None:
    from app.auth.mailer import password_reset_url

    url = password_reset_url(
        "raw-secret-token",
        runtime_settings=_settings(),
    )

    assert (
        url
        == "https://beacon.example.com/"
        "reset-password#token=raw-secret-token"
    )

    assert "?token=" not in url


class FakeSMTP:
    def __init__(
        self,
        owner,
        attempt,
    ):
        self.owner = owner
        self.attempt = attempt

    def starttls(self):
        self.owner.starttls += 1

    def login(
        self,
        username,
        password,
    ):
        self.owner.logins.append(
            (
                username,
                password,
            )
        )

    def send_message(self, message):
        self.owner.messages.append(message)

        if self.attempt < 3:
            raise SMTPException(
                "temporary delivery failure"
            )

    def quit(self):
        return None


class SMTPFactory:
    def __init__(self):
        self.calls = 0
        self.starttls = 0
        self.logins = []
        self.messages = []

    def __call__(
        self,
        host,
        port,
        *,
        timeout,
    ):
        self.calls += 1

        assert host == "smtp.example.com"
        assert port == 587
        assert timeout == 10

        return FakeSMTP(
            self,
            self.calls,
        )


def test_smtp_delivery_retries_in_process_at_30_and_120_seconds() -> None:
    from app.auth.mailer import send_auth_email_message

    factory = SMTPFactory()
    sleeps = []

    send_auth_email_message(
        to_address="recipient@example.com",
        purpose="verify_email",
        link=(
            "https://beacon.example.com/"
            "verify-email#token=raw"
        ),
        runtime_settings=_settings(),
        smtp_factory=factory,
        sleeper=sleeps.append,
    )

    assert factory.calls == 3
    assert sleeps == [
        30,
        120,
    ]

    assert factory.starttls == 3


def test_mail_task_payload_contract_contains_no_raw_token() -> None:
    from app.auth.mail_tasks import send_auth_lifecycle_email

    signature = inspect.signature(
        send_auth_lifecycle_email
    )

    assert list(
        signature.parameters
    ) == [
        "user_id",
        "purpose",
    ]


def test_branded_auth_email_has_plain_text_and_html_parts() -> None:
    from app.auth.mailer import _message_for

    message = _message_for(
        to_address="recipient@example.com",
        purpose="reset_password",
        link=(
            "https://beacon.example.com/"
            "reset-password#token=raw-secret-token"
        ),
        runtime_settings=_settings(),
        context={
            "recipient_name": "Beacon Operator",
        },
    )

    assert message.is_multipart()
    assert message.get_content_type() == "multipart/alternative"
    assert message["Subject"] == "Reset your password • BEACON"
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["X-BEACON-Message-Type"] == "reset_password"

    plain = message.get_body(
        preferencelist=("plain",)
    )
    html = message.get_body(
        preferencelist=("html",)
    )

    assert plain is not None
    assert html is not None
    assert "Hi Beacon Operator," in plain.get_content()
    assert "Reset password" in plain.get_content()
    assert "BEACON Security Assessment Platform" in plain.get_content()

    html_body = html.get_content()
    assert "BEACON" in html_body
    assert "Security note" in html_body
    assert "Reset password" in html_body
    assert "#token=raw-secret-token" in html_body
    assert "<script" not in html_body
    assert "<img" not in html_body
    assert "max-width:680px" in html_body
    assert "border-top:2px solid #d52e46" in html_body
    assert "padding:14px 24px" in html_body


def test_invitation_email_includes_workspace_context() -> None:
    from app.auth.mailer import _message_for

    message = _message_for(
        to_address="member@example.com",
        purpose="organization_invitation",
        link=(
            "https://beacon.example.com/"
            "invite?token=invite-token"
        ),
        runtime_settings=_settings(),
        context={
            "organization_name": "Security Operations",
            "workspace_role": "analyst",
            "inviter_name": "Workspace Admin",
        },
    )

    assert (
        message["Subject"]
        == "Invitation to Security Operations • BEACON"
    )

    plain = message.get_body(
        preferencelist=("plain",)
    )
    html = message.get_body(
        preferencelist=("html",)
    )

    assert plain is not None
    assert html is not None

    for expected in (
        "Security Operations",
        "Analyst",
        "member@example.com",
        "Workspace Admin",
    ):
        assert expected in plain.get_content()
        assert expected in html.get_content()
