from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class RawScannerEvidence(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Immutable scanner evidence captured before normalization."""

    __tablename__ = "scanner_evidence"

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

    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    payload: Mapped[dict | list | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    request_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    response_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    command_metadata: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    artifact_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    artifact_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
