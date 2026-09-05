from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_event_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_type: Mapped[str] = mapped_column(String(80), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    action: Mapped[str | None] = mapped_column(String(80), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(200), index=True, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    reason: Mapped[str] = mapped_column(String(200), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("tenant_id", "fingerprint", name="uq_finding_fingerprint"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(240), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    acquisition_method: Mapped[str] = mapped_column(String(80), nullable=False)
    original_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collector_identity: Mapped[str] = mapped_column(String(80), nullable=False)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    object_uri: Mapped[str | None] = mapped_column(String(400), nullable=True)
    parser_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    transformation_history: Mapped[list] = mapped_column(JSON, default=list)
    confidence_level: Mapped[int] = mapped_column(default=1)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    sealed: Mapped[bool] = mapped_column(default=True)
