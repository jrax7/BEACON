from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin


class FindingRetest(
    UUIDPrimaryKeyMixin,
    Base,
):
    """A vulnerability retest linked to a validating assessment."""

    __tablename__ = "finding_retests"

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    requested_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="REQUESTED",
        server_default="REQUESTED",
        index=True,
    )

    scan_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
