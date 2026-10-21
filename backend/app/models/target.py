from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A website or hostname registered for scanning."""

    __tablename__ = "targets"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "hostname",
            name="uq_targets_organization_hostname",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    # Creator/provenance identity.
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    original_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    normalized_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
    )

    verification_method: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    verification_token_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    verification_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
