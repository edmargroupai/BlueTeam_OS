from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class QualitySnapshot(Base):
    __tablename__ = "quality_snapshots"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    band: Mapped[str] = mapped_column(String(32), nullable=False)
    domains: Mapped[dict] = mapped_column(JSON, nullable=False)
    checks: Mapped[list] = mapped_column(JSON, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
