from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    """Append-only. Application code must never update or delete rows."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    tenant_id: Mapped[str | None] = mapped_column(String(40), index=True, nullable=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(80), nullable=False)
    request_id: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approval_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    before_state: Mapped[dict] = mapped_column(JSON, default=dict)
    after_state: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
