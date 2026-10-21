from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class FindingOccurrence(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """One observation of a canonical finding in one assessment."""

    __tablename__ = "finding_occurrences"

    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "scan_id",
            name=(
                "uq_finding_occurrences_"
                "finding_scan"
            ),
        ),
    )

    finding_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="observed",
        server_default="observed",
        index=True,
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
