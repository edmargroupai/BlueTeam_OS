from __future__ import annotations

from blueteam_telemetry import evaluate_telemetry_health
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.ingestion import list_dead_letters, load_window

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/health")
def telemetry_health(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    events = load_window(db, actor.tenant_id)
    dead = list_dead_letters(db, actor.tenant_id)
    body = evaluate_telemetry_health(
        events=events,
        dead_letter_count=len(dead),
        dead_letter_reasons=[item.reason for item in dead],
    )
    return {"tenant_id": actor.tenant_id, **body}
