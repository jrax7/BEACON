from datetime import datetime
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)


class UserCreate(BaseModel):
    """Information required to register a new user."""

    email: EmailStr
    full_name: str = Field(
        min_length=2,
        max_length=150,
    )
    password: str = Field(
        min_length=12,
        max_length=128,
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str) -> str:
        normalized = " ".join(value.strip().split())

        if len(normalized) < 2:
            raise ValueError("Full name must contain at least 2 characters.")

        return normalized


class UserResponse(BaseModel):
    """Safe user information returned by the API."""

    id: UUID
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    is_email_verified: bool
    created_at: datetime

    organization_id: UUID | None = None
    organization_name: str | None = None
    organization_role: str | None = None

    model_config = ConfigDict(
        from_attributes=True,
    )


class TokenResponse(BaseModel):
    """JWT access token returned after successful authentication."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MessageResponse(BaseModel):
    """General API message."""

    message: str


class BrowserLoginRequest(BaseModel):
    """JSON credentials for browser session login."""

    email: EmailStr
    password: str = Field(
        min_length=12,
        max_length=128,
    )

    @field_validator("email")
    @classmethod
    def normalize_login_email(
        cls,
        value: EmailStr,
    ) -> str:
        return str(value).strip().lower()


class PasswordChangeRequest(BaseModel):
    """Authenticated password rotation."""

    current_password: str = Field(
        min_length=12,
        max_length=128,
    )
    new_password: str = Field(
        min_length=12,
        max_length=128,
    )


class RegistrationRequest(UserCreate):
    """Public registration request."""

    turnstile_token: str = Field(
        default="",
        max_length=4096,
    )

    invitation_token: str | None = Field(
        default=None,
        min_length=20,
        max_length=1024,
    )


class EmailVerificationRequest(BaseModel):
    """One-time email verification token."""

    token: str = Field(
        min_length=20,
        max_length=1024,
    )


class ResendVerificationRequest(BaseModel):
    """Request another verification email."""

    email: EmailStr
    turnstile_token: str = Field(
        default="",
        max_length=4096,
    )

    @field_validator("email")
    @classmethod
    def normalize_resend_email(
        cls,
        value: EmailStr,
    ) -> str:
        return str(
            value
        ).strip().lower()


class ForgotPasswordRequest(BaseModel):
    """Non-enumerating password recovery request."""

    email: EmailStr
    turnstile_token: str = Field(
        default="",
        max_length=4096,
    )

    @field_validator("email")
    @classmethod
    def normalize_forgot_email(
        cls,
        value: EmailStr,
    ) -> str:
        return str(
            value
        ).strip().lower()


class PasswordResetRequest(BaseModel):
    """One-time password reset."""

    token: str = Field(
        min_length=20,
        max_length=1024,
    )

    new_password: str = Field(
        min_length=12,
        max_length=128,
    )
