from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability: Mapped[float] = mapped_column(Float, default=0.0)
    asset_id: Mapped[str] = mapped_column(String(120), nullable=False)
    asset_criticality: Mapped[float] = mapped_column(Float, default=50.0)
    threat_activity: Mapped[float] = mapped_column(Float, default=0.0)
    priority: Mapped[float] = mapped_column(Float, default=0.0)
    band: Mapped[str] = mapped_column(String(16), default="low")
    sla_days: Mapped[int] = mapped_column(Integer, default=90)
    scanner: Mapped[str] = mapped_column(String(80), default="import")
    status: Mapped[str] = mapped_column(String(32), default="open")
    formula: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
