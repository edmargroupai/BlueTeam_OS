from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.incidents import list_incidents, list_storylines, persist_storylines_and_incidents

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def get_incidents(
    actor: TenantActor = Depends(Permission("incidents:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_incidents(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "title": row.title,
                "status": row.status,
                "storyline_ids": row.storyline_ids,
                "event_ids": row.event_ids,
                "evidence_ids": row.evidence_ids,
                "mitre_techniques": row.mitre_techniques,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
        "lifecycle": "grouping-only",
        "note": "Assignment, containment, and lessons are Phase 10. These objects are correlation groups only.",
    }


@router.get("/storylines")
def get_storylines(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_storylines(db, actor.tenant_id)
    return {"items": [row.payload for row in rows], "count": len(rows)}


@router.post("/rebuild")
def rebuild(
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
) -> dict:
    return persist_storylines_and_incidents(db, actor.tenant_id)
