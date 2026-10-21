from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


VerificationMethod = Literal["file", "dns"]


class TargetCreate(BaseModel):
    """Input required to register a target."""

    url: str = Field(
        min_length=8,
        max_length=2048,
    )

    verification_method: VerificationMethod = "file"


class TargetResponse(BaseModel):
    """Safe target information returned by the API."""

    id: UUID
    original_url: str
    normalized_url: str
    hostname: str
    verification_method: str | None
    verification_status: str
    verified_at: datetime | None
    verification_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class TargetCreateResponse(TargetResponse):
    """Target response that includes the one-time verification value."""

    verification_value: str
    verification_location: str
    instructions: str


class VerificationTokenResponse(BaseModel):
    """A newly generated ownership-verification value."""

    target_id: UUID
    verification_method: VerificationMethod
    verification_value: str
    verification_location: str
    instructions: str


class TargetVerificationResponse(BaseModel):
    """Result of an ownership-verification attempt."""

    target_id: UUID
    hostname: str
    verification_method: VerificationMethod
    verification_status: str
    checked_location: str
    verified_at: datetime
    verification_expires_at: datetime
    message: str
