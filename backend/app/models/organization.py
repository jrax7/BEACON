from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class Organization(
    UUIDPrimaryKeyMixin,
    TimestampMixin,
    Base,
):
    """Top-level BEACON tenant and authorization boundary."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    slug: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
        unique=True,
        index=True,
    )
