from uuid import UUID

from sqlalchemy import (
    ForeignKey,
    Integer,
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


class Detection(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """One source-specific scanner detection before correlation."""

    __tablename__ = "detections"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    tool_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "scan_tool_runs.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    raw_evidence_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "scanner_evidence.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    finding_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    engine: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    engine_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    rule_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    rule_version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )

    confidence: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    asset_identity: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    affected_service: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    affected_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    affected_location: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    affected_parameter: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cve_ids: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    cwe_ids: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    evidence_strength: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    source_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )
