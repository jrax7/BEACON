from datetime import datetime
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

from app.organizations.rbac import (
    OrganizationRole,
)


class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    role: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class ActiveOrganizationRequest(BaseModel):
    organization_id: UUID


class OrganizationUpdateRequest(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=150,
    )

    @field_validator("name")
    @classmethod
    def normalize_name(
        cls,
        value: str,
    ) -> str:
        normalized = " ".join(
            value.strip().split()
        )

        if not normalized:
            raise ValueError(
                "Organization name is required."
            )

        return normalized


class MemberResponse(BaseModel):
    membership_id: UUID
    user_id: UUID
    email: EmailStr
    full_name: str
    role: str
    created_at: datetime


class MemberRoleUpdateRequest(BaseModel):
    role: OrganizationRole


class InvitationAcceptRequest(BaseModel):
    token: str = Field(
        min_length=1,
        max_length=2048,
    )


class InvitationCreateRequest(BaseModel):
    email: EmailStr
    role: OrganizationRole = (
        OrganizationRole.VIEWER
    )

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: EmailStr,
    ) -> str:
        return str(
            value
        ).strip().lower()


class InvitationResponse(BaseModel):
    id: UUID
    email: EmailStr
    role: str
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class InvitationResolveResponse(BaseModel):
    invitation_id: UUID
    organization_id: UUID
    organization_name: str
    email: EmailStr
    role: str
    expires_at: datetime
