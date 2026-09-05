from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IndicatorOfCompromise(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("tenant_id", "indicator_type", "value", name="uq_ioc_tenant_type_value"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    ttl_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=168)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    malware: Mapped[str | None] = mapped_column(String(120), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(120), nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    sightings: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SavedHunt(Base):
    __tablename__ = "saved_hunts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    hunt_type: Mapped[str] = mapped_column(String(40), nullable=False)
    query: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
