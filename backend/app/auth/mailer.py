from __future__ import annotations

import smtplib
from email.message import EmailMessage
from html import escape
from time import sleep
from urllib.parse import quote

from app.config import settings


class MailDeliveryError(RuntimeError):
    """Sanitized terminal authentication-email failure."""


def _public_origin(
    runtime_settings,
) -> str:
    return (
        runtime_settings
        .public_url
        .rstrip("/")
    )


def email_verification_url(
    raw_token: str,
    *,
    runtime_settings=settings,
) -> str:
    return (
        f"{_public_origin(runtime_settings)}"
        "/verify-email"
        f"#token={raw_token}"
    )


def password_reset_url(
    raw_token: str,
    *,
    runtime_settings=settings,
) -> str:
    return (
        f"{_public_origin(runtime_settings)}"
        "/reset-password"
        f"#token={raw_token}"
    )


def organization_invitation_url(
    raw_token: str,
    *,
    runtime_settings=settings,
) -> str:
    return (
        f"{_public_origin(runtime_settings)}"
        "/invite?token="
        f"{quote(raw_token, safe='')}"
    )


def _single_line(
    value: object,
    *,
    fallback: str = "",
    limit: int = 160,
) -> str:
    normalized = " ".join(
        str(value or "").split()
    ).strip()

    if not normalized:
        return fallback

    return normalized[:limit]


def _email_copy(
    *,
    purpose: str,
    to_address: str,
    context: dict[str, str],
) -> dict[str, object]:
    recipient_name = _single_line(
        context.get("recipient_name"),
        fallback="there",
        limit=80,
    )

    if purpose == "verify_email":
        return {
            "subject": "Verify your email • BEACON",
            "eyebrow": "ACCOUNT SECURITY",
            "title": "Verify your email address",
            "greeting": f"Hi {recipient_name},",
            "intro": (
                "Confirm this email address to activate your BEACON account "
                "and continue into your security workspace."
            ),
            "action": "Verify email address",
            "expiry": "This verification link expires in 24 hours.",
            "security": (
                "If you did not create a BEACON account, you can safely "
                "ignore this message."
            ),
            "details": (),
        }

    if purpose == "reset_password":
        return {
            "subject": "Reset your password • BEACON",
            "eyebrow": "ACCOUNT RECOVERY",
            "title": "Reset your BEACON password",
            "greeting": f"Hi {recipient_name},",
            "intro": (
                "We received a request to reset the password for your "
                "BEACON account. Use the secure link below to choose a new one."
            ),
            "action": "Reset password",
            "expiry": "This password-reset link expires in 30 minutes.",
            "security": (
                "If you did not request a password reset, no action is needed. "
                "Your current password will remain unchanged."
            ),
            "details": (),
        }

    if purpose == "organization_invitation":
        workspace = _single_line(
            context.get("organization_name"),
            fallback="BEACON workspace",
            limit=100,
        )
        role = _single_line(
            context.get("workspace_role"),
            fallback="member",
            limit=40,
        )
        inviter = _single_line(
            context.get("inviter_name"),
            fallback="A BEACON workspace administrator",
            limit=100,
        )

        return {
            "subject": f"Invitation to {workspace} • BEACON",
            "eyebrow": "WORKSPACE INVITATION",
            "title": "You’re invited to BEACON",
            "greeting": "You have a new workspace invitation.",
            "intro": (
                f"{inviter} invited you to join {workspace}. "
                "Use the invitation below with the account that owns this email address."
            ),
            "action": "Review invitation",
            "expiry": "This invitation expires in 72 hours.",
            "security": (
                f"This invitation is intended only for {to_address}. "
                "If you were not expecting it, you can ignore this message."
            ),
            "details": (
                ("Workspace", workspace),
                ("Role", role.title()),
                ("Invited account", to_address),
            ),
        }

    raise ValueError(
        "Unsupported authentication email purpose."
    )


def _render_text_email(
    *,
    copy: dict[str, object],
    link: str,
) -> str:
    lines = [
        str(copy["title"]),
        "",
        str(copy["greeting"]),
        "",
        str(copy["intro"]),
    ]

    details = copy["details"]

    if details:
        lines.extend(["", "Details"])
        lines.extend(
            f"{label}: {value}"
            for label, value in details
        )

    lines.extend([
        "",
        f"{copy['action']}: {link}",
        "",
        str(copy["expiry"]),
        str(copy["security"]),
        "",
        "BEACON Security Assessment Platform",
        "Automated security notification — please do not reply.",
    ])

    return "\n".join(lines)


def _render_detail_rows(
    details: tuple[tuple[str, str], ...],
) -> str:
    if not details:
        return ""

    rows = "".join(
        "<tr>"
        "<td style=\"padding:10px 12px;color:#8f7f85;font-size:11px;"
        "font-family:Arial,sans-serif;text-transform:uppercase;letter-spacing:.08em;"
        "border-bottom:1px solid #2b171d;\">"
        f"{escape(label)}"
        "</td>"
        "<td style=\"padding:10px 12px;color:#f4ecef;font-size:13px;"
        "font-family:Arial,sans-serif;text-align:right;border-bottom:1px solid #2b171d;\">"
        f"{escape(value)}"
        "</td>"
        "</tr>"
        for label, value in details
    )

    return (
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" "
        "style=\"margin:22px 0 0;border:1px solid #2b171d;border-radius:10px;"
        "border-collapse:separate;overflow:hidden;background:#0c0709;\">"
        f"{rows}"
        "</table>"
    )


def _render_html_email(
    *,
    copy: dict[str, object],
    link: str,
) -> str:
    safe_link = escape(link, quote=True)
    details_html = _render_detail_rows(
        copy["details"],
    )

    return f"""<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#080406;color:#f4ecef;">
    <div style="display:none;max-height:0;overflow:hidden;color:transparent;opacity:0;">
      {escape(str(copy['intro']))}
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#080406;">
      <tr>
        <td align="center" style="padding:28px 18px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;border:1px solid #321a22;border-top:2px solid #d52e46;border-radius:16px;background:#130a0e;overflow:hidden;">
            <tr>
              <td style="padding:26px 30px;border-bottom:1px solid #2b171d;background:#10080b;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="vertical-align:middle;">
                      <table role="presentation" cellpadding="0" cellspacing="0">
                        <tr>
                          <td style="width:42px;height:42px;text-align:center;vertical-align:middle;border:1px solid #a51f33;border-radius:11px;background:#250d14;color:#ef4159;font-family:Arial,sans-serif;font-weight:800;font-size:17px;">B</td>
                          <td style="padding-left:12px;vertical-align:middle;">
                            <div style="color:#ffffff;font-family:Arial,sans-serif;font-size:15px;font-weight:800;letter-spacing:.12em;">BEACON</div>
                            <div style="margin-top:3px;color:#8f7f85;font-family:Arial,sans-serif;font-size:11px;">Security Assessment Platform</div>
                          </td>
                        </tr>
                      </table>
                    </td>
                    <td align="right" style="color:#d52e46;font-family:Arial,sans-serif;font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;">
                      {escape(str(copy['eyebrow']))}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:36px 30px 26px;">
                <h1 style="margin:0;color:#fff;font-family:Arial,sans-serif;font-size:30px;line-height:1.2;letter-spacing:-.02em;">{escape(str(copy['title']))}</h1>
                <p style="margin:18px 0 0;color:#f4ecef;font-family:Arial,sans-serif;font-size:15px;line-height:1.7;">{escape(str(copy['greeting']))}</p>
                <p style="margin:10px 0 0;color:#b6a7ad;font-family:Arial,sans-serif;font-size:14px;line-height:1.75;">{escape(str(copy['intro']))}</p>
                {details_html}
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:28px 0 0;">
                  <tr>
                    <td style="border-radius:9px;background:#d52e46;">
                      <a href="{safe_link}" style="display:inline-block;padding:14px 24px;color:#fff;font-family:Arial,sans-serif;font-size:14px;font-weight:800;text-decoration:none;">{escape(str(copy['action']))} &nbsp;→</a>
                    </td>
                  </tr>
                </table>
                <div style="margin:24px 0 0;padding:16px 18px;border:1px solid #332027;border-radius:10px;background:#0d080a;">
                  <div style="color:#ef4159;font-family:Arial,sans-serif;font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;">Security note</div>
                  <p style="margin:8px 0 0;color:#9e8f95;font-family:Arial,sans-serif;font-size:12px;line-height:1.65;">{escape(str(copy['expiry']))}<br>{escape(str(copy['security']))}</p>
                </div>
                <p style="margin:18px 0 0;color:#74666b;font-family:Arial,sans-serif;font-size:11px;line-height:1.6;">If the button does not open, copy and paste this link into your browser:<br><a href="{safe_link}" style="color:#c6a9b2;text-decoration:underline;word-break:break-all;">{safe_link}</a></p>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 30px;border-top:1px solid #2b171d;background:#0d0709;color:#66585d;font-family:Arial,sans-serif;font-size:10px;line-height:1.6;">
                Automated security notification from BEACON. Please do not reply to this message.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"""


def _message_for(
    *,
    to_address: str,
    purpose: str,
    link: str,
    runtime_settings,
    context: dict[str, str] | None = None,
) -> EmailMessage:
    message = EmailMessage()

    from_name = _single_line(
        runtime_settings.smtp_from_name,
        limit=80,
    )
    from_address = _single_line(
        runtime_settings.smtp_from_address,
        limit=320,
    )

    message["From"] = (
        f"{from_name} <{from_address}>"
        if from_name
        else from_address
    )
    message["To"] = to_address
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    message["X-BEACON-Message-Type"] = purpose

    copy = _email_copy(
        purpose=purpose,
        to_address=to_address,
        context=context or {},
    )

    message["Subject"] = str(copy["subject"])
    message.set_content(
        _render_text_email(
            copy=copy,
            link=link,
        )
    )
    message.add_alternative(
        _render_html_email(
            copy=copy,
            link=link,
        ),
        subtype="html",
    )

    return message


def send_auth_email_message(
    *,
    to_address: str,
    purpose: str,
    link: str,
    runtime_settings=settings,
    context: dict[str, str] | None = None,
    smtp_factory=smtplib.SMTP,
    sleeper=sleep,
) -> None:
    """Deliver one auth email with bounded in-process retries."""

    message = _message_for(
        to_address=to_address,
        purpose=purpose,
        link=link,
        runtime_settings=runtime_settings,
        context=context,
    )

    delays = (
        0,
        30,
        120,
    )

    for attempt, delay in enumerate(
        delays,
        start=1,
    ):
        if delay:
            sleeper(delay)

        smtp = None

        try:
            smtp = smtp_factory(
                runtime_settings.smtp_host,
                runtime_settings.smtp_port,
                timeout=(
                    runtime_settings
                    .smtp_timeout_seconds
                ),
            )

            if runtime_settings.smtp_starttls:
                smtp.starttls()

            if runtime_settings.smtp_username:
                smtp.login(
                    runtime_settings.smtp_username,
                    runtime_settings.smtp_password,
                )

            smtp.send_message(message)
            return
        except (
            OSError,
            smtplib.SMTPException,
        ):
            if attempt == len(delays):
                raise MailDeliveryError(
                    "Authentication email delivery failed."
                ) from None
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass
