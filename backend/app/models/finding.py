from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A normalized security finding produced by one or more tools."""

    __tablename__ = "findings"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # Engine v2 canonical metadata remains nullable so historical
    # findings stay valid without invented backfill values.
    target_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "targets.id",
            ondelete="SET NULL",
        ),
        nullable=True,
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

    tool_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    external_finding_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
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

    affected_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    affected_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    remediation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cwe_id: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    cvss_score: Mapped[Decimal | None] = mapped_column(
        Numeric(3, 1),
        nullable=True,
    )

    fingerprint: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    asset_identity: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    canonical_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    cve_ids: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    cwe_ids: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    affected_service: Mapped[str | None] = mapped_column(
        String(255),
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

    impact: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    first_seen: Mapped[object | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[object | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    source_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    occurrence_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    lifecycle_state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="NEW",
        server_default="NEW",
        index=True,
    )

    observation_state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="NEW",
        server_default="NEW",
        index=True,
    )

    assignee_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    remediation_owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    disposition: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        index=True,
    )

    disposition_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    disposition_set_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    disposition_set_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    duplicate_of_finding_id: Mapped[UUID | None] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="open",
        server_default="open",
        index=True,
    )
