from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class InfrastructureAuthorization(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Recorded authorization for Deep infrastructure assessment."""

    __tablename__ = "infrastructure_authorizations"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    confirmed_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    authorization_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    authorization_text_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    authorized_ips: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )

    authorized_cidrs: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )

    resolved_target_ips: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )

    broad_port_scan_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    network_active_checks_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    third_party_infrastructure_attested_excluded: Mapped[bool] = (
        mapped_column(
            Boolean,
            nullable=False,
        )
    )
