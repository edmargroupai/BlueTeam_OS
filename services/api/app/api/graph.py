from __future__ import annotations

from blueteam_common.errors import BlueTeamError
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.graph import (
    get_entity,
    list_entities,
    list_relationships,
    project_graph,
    serialize_entity,
    serialize_rel,
    set_criticality,
)
from app.services.ingestion import load_window

router = APIRouter(prefix="/graph", tags=["graph"])


class CriticalityBody(BaseModel):
    criticality: str


@router.get("")
def graph(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    entities = list_entities(db, actor.tenant_id)
    rels = list_relationships(db, actor.tenant_id)
    return {
        "tenant_id": actor.tenant_id,
        "manufactured_edges": False,
        "entities": [serialize_entity(item) for item in entities],
        "relationships": [serialize_rel(item) for item in rels],
    }


@router.get("/entities")
def entities(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    return {"items": [serialize_entity(item) for item in list_entities(db, actor.tenant_id)]}


@router.get("/entities/{entity_id}")
def entity_detail(
    entity_id: str,
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    row = get_entity(db, actor.tenant_id, entity_id)
    if row is None:
        raise BlueTeamError("NOT_FOUND", "Entity not found", 404)
    neighbors = [
        serialize_rel(item)
        for item in list_relationships(db, actor.tenant_id)
        if item.src_id == entity_id or item.dst_id == entity_id
    ]
    return {**serialize_entity(row), "neighbors": neighbors}


@router.post("/rebuild")
def rebuild(
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
) -> dict:
    stats = project_graph(db, actor.tenant_id, load_window(db, actor.tenant_id))
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="graph.rebuild",
        target_type="entity_graph",
        after_state=stats,
        result="success",
    )
    return stats


@router.patch("/entities/{entity_id}")
def update_criticality(
    entity_id: str,
    body: CriticalityBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        row = set_criticality(db, actor.tenant_id, entity_id, body.criticality)
    except ValueError as exc:
        raise BlueTeamError("GRAPH_INVALID", str(exc), 422) from exc
    if row is None:
        raise BlueTeamError("NOT_FOUND", "Entity not found", 404)
    project_graph(db, actor.tenant_id, load_window(db, actor.tenant_id))
    updated = get_entity(db, actor.tenant_id, entity_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="graph.criticality",
        target_type="entity",
        target_id=entity_id,
        after_state={"criticality": body.criticality},
        result="success",
    )
    assert updated is not None
    return serialize_entity(updated)
