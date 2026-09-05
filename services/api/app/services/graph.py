from __future__ import annotations

from blueteam_graph.engine import build_graph
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.graph import EntityRecord, RelationshipRecord
from app.models.telemetry import FindingRecord


def project_graph(db: Session, tenant_id: str, events: list[CanonicalEvent]) -> dict:
    findings = [
        Finding.model_validate(row.payload)
        for row in db.execute(select(FindingRecord).where(FindingRecord.tenant_id == tenant_id)).scalars().all()
    ]
    stored = {
        row.id: row.criticality
        for row in db.execute(select(EntityRecord).where(EntityRecord.tenant_id == tenant_id)).scalars().all()
    }
    graph = build_graph(events, findings, criticality=stored)
    _replace(db, tenant_id, graph)
    return {
        "entities": len(graph.entities),
        "relationships": len(graph.relationships),
        "manufactured_edges": graph.manufactured_edges,
    }


def _replace(db: Session, tenant_id: str, graph) -> None:
    for row in db.execute(select(EntityRecord).where(EntityRecord.tenant_id == tenant_id)).scalars().all():
        db.delete(row)
    for row in db.execute(select(RelationshipRecord).where(RelationshipRecord.tenant_id == tenant_id)).scalars().all():
        db.delete(row)
    db.flush()
    for entity in graph.entities:
        db.add(
            EntityRecord(
                id=entity.id,
                tenant_id=entity.tenant_id,
                entity_type=entity.entity_type,
                key=entity.key,
                display_name=entity.display_name,
                criticality=entity.criticality,
                risk_score=entity.risk_score,
                risk_components=[item.model_dump() for item in entity.risk_components],
                event_ids=entity.event_ids,
                finding_ids=entity.finding_ids,
                first_seen=entity.first_seen,
                last_seen=entity.last_seen,
                attributes=entity.attributes,
            )
        )
    for rel in graph.relationships:
        db.add(
            RelationshipRecord(
                id=rel.id,
                tenant_id=rel.tenant_id,
                src_id=rel.src_id,
                dst_id=rel.dst_id,
                relation=rel.relation,
                event_ids=rel.event_ids,
                manufactured=False,
            )
        )
    db.flush()


def list_entities(db: Session, tenant_id: str) -> list[EntityRecord]:
    return list(
        db.execute(
            select(EntityRecord)
            .where(EntityRecord.tenant_id == tenant_id)
            .order_by(EntityRecord.risk_score.desc())
        ).scalars().all()
    )


def list_relationships(db: Session, tenant_id: str) -> list[RelationshipRecord]:
    return list(
        db.execute(select(RelationshipRecord).where(RelationshipRecord.tenant_id == tenant_id)).scalars().all()
    )


def get_entity(db: Session, tenant_id: str, entity_id: str) -> EntityRecord | None:
    return db.execute(
        select(EntityRecord).where(EntityRecord.tenant_id == tenant_id, EntityRecord.id == entity_id)
    ).scalar_one_or_none()


def set_criticality(db: Session, tenant_id: str, entity_id: str, criticality: str) -> EntityRecord | None:
    row = get_entity(db, tenant_id, entity_id)
    if row is None:
        return None
    allowed = {"unknown", "low", "medium", "high", "crown_jewel"}
    if criticality not in allowed:
        raise ValueError("unsupported criticality")
    row.criticality = criticality
    db.flush()
    return row


def serialize_entity(row: EntityRecord) -> dict:
    return {
        "id": row.id,
        "entity_type": row.entity_type,
        "key": row.key,
        "display_name": row.display_name,
        "criticality": row.criticality,
        "risk_score": row.risk_score,
        "risk_components": row.risk_components,
        "event_ids": row.event_ids,
        "finding_ids": row.finding_ids,
        "first_seen": row.first_seen.isoformat(),
        "last_seen": row.last_seen.isoformat(),
    }


def serialize_rel(row: RelationshipRecord) -> dict:
    return {
        "id": row.id,
        "src_id": row.src_id,
        "dst_id": row.dst_id,
        "relation": row.relation,
        "event_ids": row.event_ids,
        "manufactured": row.manufactured,
    }
