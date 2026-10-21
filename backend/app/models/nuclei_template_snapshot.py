from sqlalchemy import Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class NucleiTemplateSnapshot(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Immutable approved Nuclei template-set snapshot."""

    __tablename__ = "nuclei_template_snapshots"

    policy_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    nuclei_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    template_source: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    template_source_revision: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    snapshot_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )

    approved_groups: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
    )

    template_manifest: Mapped[list[dict]] = mapped_column(
        JSONB,
        nullable=False,
    )

    template_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
