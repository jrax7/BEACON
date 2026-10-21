from uuid import UUID

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssessmentScanPlan(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Immutable Engine v2 execution snapshot for one assessment."""

    __tablename__ = "assessment_scan_plans"

    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    profile: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    profile_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    assessment_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    authorized_scope: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    resolved_addresses: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )

    engine_policy_versions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    crawl_policy: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    rate_budget: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    timeout_budget: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    nuclei_template_snapshot_id: Mapped[UUID | None] = (
        mapped_column(
            Uuid,
            ForeignKey(
                "nuclei_template_snapshots.id",
                ondelete="RESTRICT",
            ),
            nullable=True,
        )
    )

    zap_policy_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
