from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.ingestion import ingest_payloads, list_dead_letters, list_events

router = APIRouter(prefix="/events", tags=["events"])


class IngestRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class SyslogRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)


class WebhookRequest(BaseModel):
    source: str = "webhook"
    adapter: str | None = None
    events: list[dict[str, Any]] | None = None
    payload: dict[str, Any] | None = None


@router.post("/ingest")
def ingest(
    body: IngestRequest,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
) -> dict:
    result = ingest_payloads(db, actor.tenant_id, body.events, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="events.ingest",
        target_type="security_event",
        after_state={"accepted": len(result["accepted"]), "rejected": len(result["rejected"])},
        result="success",
    )
    return result


@router.post("/syslog")
def ingest_syslog(
    body: SyslogRequest,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
) -> dict:
    payloads = [{"adapter": "syslog", "syslog_raw": line} for line in body.lines]
    result = ingest_payloads(db, actor.tenant_id, payloads, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="events.ingest.syslog",
        target_type="security_event",
        after_state={"accepted": len(result["accepted"]), "rejected": len(result["rejected"])},
        result="success",
    )
    return result


@router.post("/webhook")
def ingest_webhook(
    body: WebhookRequest,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
) -> dict:
    from blueteam_ingest.webhook import normalize_webhook

    raw = body.payload or {"events": body.events or []}
    if body.adapter:
        raw = {**raw, "adapter": body.adapter}
    payloads = normalize_webhook(raw, actor.tenant_id, source=body.source)
    result = ingest_payloads(db, actor.tenant_id, payloads, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="events.ingest.webhook",
        target_type="security_event",
        after_state={"accepted": len(result["accepted"]), "rejected": len(result["rejected"])},
        result="success",
    )
    return result


@router.get("")
def get_events(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_events(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "timestamp": row.timestamp.isoformat(),
                "source": row.source,
                "category": row.category,
                "event_type": row.event_type,
                "outcome": row.outcome,
                "src_ip": row.src_ip,
                "user_name": row.user_name,
                "raw_hash": row.raw_hash,
            }
            for row in rows
        ]
    }


@router.get("/dead-letter")
def dead_letter(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_dead_letters(db, actor.tenant_id)
    return {
        "items": [
            {"id": row.id, "reason": row.reason, "created_at": row.created_at.isoformat()} for row in rows
        ]
    }
