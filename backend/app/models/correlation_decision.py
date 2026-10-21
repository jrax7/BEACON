from uuid import UUID

from sqlalchemy import (
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class CorrelationDecision(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Auditable merge/separate decision between two detections."""

    __tablename__ = "correlation_decisions"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    detection_a_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "detections.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    detection_b_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "detections.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    strategy_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    decision: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    candidate_identity: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    confidence: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    details: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )
