from __future__ import annotations

from blueteam_correlation.engine import correlate
from blueteam_endpoint.process_tree import build_process_tree
from blueteam_network.normalize import sessions_from_events
from blueteam_schemas.findings import Finding
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.detection import list_findings
from app.services.ingestion import load_window

router = APIRouter(prefix="/investigate", tags=["investigate"])


@router.get("/sessions")
def sessions(actor: TenantActor = Depends(Permission("events:read")), db: Session = Depends(get_db)) -> dict:
    events = load_window(db, actor.tenant_id)
    items = [item.model_dump(mode="json") for item in sessions_from_events(events)]
    return {"items": items, "count": len(items), "manufactured": False}


@router.get("/process-tree")
def process_tree(actor: TenantActor = Depends(Permission("events:read")), db: Session = Depends(get_db)) -> dict:
    events = load_window(db, actor.tenant_id)
    tree = build_process_tree(events)
    return tree


@router.get("/storylines")
def storylines(actor: TenantActor = Depends(Permission("detections:read")), db: Session = Depends(get_db)) -> dict:
    from app.services.incidents import list_storylines, persist_storylines_and_incidents

    persist_storylines_and_incidents(db, actor.tenant_id)
    stored = list_storylines(db, actor.tenant_id)
    if stored:
        return {"items": [row.payload for row in stored], "count": len(stored), "persisted": True}
    events = load_window(db, actor.tenant_id)
    findings = [Finding.model_validate(row.payload) for row in list_findings(db, actor.tenant_id)]
    items = [item.model_dump(mode="json") for item in correlate(events, findings)]
    return {"items": items, "count": len(items), "persisted": False}
