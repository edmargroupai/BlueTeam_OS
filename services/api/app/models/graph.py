from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class EntityRecord(Base):
    __tablename__ = "graph_entities"
    __table_args__ = (UniqueConstraint("tenant_id", "entity_type", "key", name="uq_graph_entity"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    key: Mapped[str] = mapped_column(String(240), nullable=False)
    display_name: Mapped[str] = mapped_column(String(240), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_components: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)


class RelationshipRecord(Base):
    __tablename__ = "graph_relationships"
    __table_args__ = (UniqueConstraint("tenant_id", "src_id", "relation", "dst_id", name="uq_graph_rel"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    src_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    dst_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    relation: Mapped[str] = mapped_column(String(32), nullable=False)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    manufactured: Mapped[bool] = mapped_column(default=False)
