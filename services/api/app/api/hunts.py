from __future__ import annotations

from blueteam_blueql.engine import BlueQLError, execute, explain, parse
from blueteam_common.errors import BlueTeamError
from blueteam_sql.engine import execute_hunt, list_hunts
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.hunting import (
    authentication_history,
    entity_lookup,
    export_events,
    ioc_lookup,
    list_saved_hunts,
    network_session_search,
    process_tree_view,
    save_hunt,
    structured_search,
)
from app.services.ingestion import load_window

router = APIRouter(prefix="/hunts", tags=["hunts"])


class BlueQLRequest(BaseModel):
    query: str = Field(min_length=3, max_length=2000)
    dry_run: bool = True


class SQLHuntRequest(BaseModel):
    query_id: str
    params: dict[str, int | str] = Field(default_factory=dict)


class StructuredHuntRequest(BaseModel):
    start: str | None = None
    end: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    domain: str | None = None
    process_name: str | None = None
    source_type: str | None = None
    category: str | None = None
    ioc: str | None = None
    limit: int = 200


class SaveHuntBody(BaseModel):
    name: str
    hunt_type: str
    query: dict
    description: str = ""


class ExportBody(BaseModel):
    format: str = "json"
    items: list[dict] = Field(default_factory=list)


@router.post("/blueql")
def run_blueql(
    body: BlueQLRequest,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    try:
        ast = parse(body.query)
    except BlueQLError as exc:
        raise BlueTeamError("BLUEQL_INVALID", str(exc), 422) from exc
    explained = explain(ast)
    if body.dry_run:
        write_audit(
            db,
            tenant_id=actor.tenant_id,
            actor_type="user",
            actor_id=actor.user_id,
            request_id=request_id,
            action="hunt.blueql.validate",
            target_type="hunt",
            after_state={"query": body.query},
        )
        return {"dry_run": True, "explain": explained, "matches": []}
    events = load_window(db, actor.tenant_id)
    matches = execute(body.query, events)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.blueql.execute",
        target_type="hunt",
        after_state={"query": body.query, "count": len(matches)},
    )
    return {
        "dry_run": False,
        "explain": explained,
        "matches": [event.id for event in matches],
        "count": len(matches),
    }


@router.get("/sql")
def sql_catalogue(_: TenantActor = Depends(Permission("hunts:execute"))) -> dict:
    return {"items": list_hunts()}


@router.post("/sql")
def run_sql(
    body: SQLHuntRequest,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    events = load_window(db, actor.tenant_id)
    settings = get_settings()
    try:
        result = execute_hunt(
            body.query_id,
            events,
            body.params,
            clickhouse_url=settings.clickhouse_url,
            tenant_id=actor.tenant_id,
        )
    except ValueError as exc:
        raise BlueTeamError("SQL_HUNT_INVALID", str(exc), 422) from exc
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.sql.execute",
        target_type="hunt",
        after_state={"query_id": body.query_id},
    )
    return result


@router.post("/structured")
def run_structured(
    body: StructuredHuntRequest,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    result = structured_search(db, actor.tenant_id, **body.model_dump())
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.structured",
        target_type="hunt",
        after_state={"filters": body.model_dump(exclude_none=True), "count": result["count"]},
    )
    return result


@router.get("/auth-history")
def auth_history(
    user: str | None = None,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    result = authentication_history(db, actor.tenant_id, user=user)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.auth_history",
        target_type="hunt",
        after_state={"user": user, "count": result["count"]},
    )
    return result


@router.get("/network-sessions")
def network_sessions(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
) -> dict:
    return network_session_search(db, actor.tenant_id, src_ip=src_ip, dst_ip=dst_ip)


@router.get("/process-tree")
def process_tree(
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
) -> dict:
    return process_tree_view(db, actor.tenant_id)


@router.get("/entity")
def entity(
    q: str,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    result = entity_lookup(db, actor.tenant_id, q)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.entity_lookup",
        target_type="entity",
        after_state={"q": q, "count": result["count"]},
    )
    return result


@router.get("/ioc")
def ioc(
    value: str,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    result = ioc_lookup(db, actor.tenant_id, value)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.ioc_lookup",
        target_type="ioc",
        after_state={"value": value},
    )
    return result


@router.get("/saved")
def saved(
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_saved_hunts(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "name": row.name,
                "description": row.description,
                "hunt_type": row.hunt_type,
                "query": row.query,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }


@router.post("/saved")
def create_saved(
    body: SaveHuntBody,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = save_hunt(
        db,
        actor.tenant_id,
        name=body.name,
        hunt_type=body.hunt_type,
        query=body.query,
        actor_id=actor.user_id,
        description=body.description,
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.save",
        target_type="saved_hunt",
        target_id=row.id,
    )
    return {"id": row.id, "name": row.name, "hunt_type": row.hunt_type}


@router.post("/export")
def export(
    body: ExportBody,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    result = export_events(body.items, fmt=body.format)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="hunt.export",
        target_type="hunt",
        after_state={"format": body.format, "count": result["count"]},
    )
    return result
