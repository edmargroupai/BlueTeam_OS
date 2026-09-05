from __future__ import annotations

from blueteam_blueql.engine import BlueQLError, execute, explain, parse
from blueteam_common.errors import BlueTeamError
from blueteam_sql.engine import execute_hunt, list_hunts
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.ingestion import load_window

router = APIRouter(prefix="/hunts", tags=["hunts"])


class BlueQLRequest(BaseModel):
    query: str = Field(min_length=3, max_length=2000)
    dry_run: bool = True


class SQLHuntRequest(BaseModel):
    query_id: str
    params: dict[str, int | str] = Field(default_factory=dict)


@router.post("/blueql")
def run_blueql(
    body: BlueQLRequest,
    actor: TenantActor = Depends(Permission("hunts:execute")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        ast = parse(body.query)
    except BlueQLError as exc:
        raise BlueTeamError("BLUEQL_INVALID", str(exc), 422) from exc
    explained = explain(ast)
    if body.dry_run:
        return {"dry_run": True, "explain": explained, "matches": []}
    events = load_window(db, actor.tenant_id)
    matches = execute(body.query, events)
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
    return result
