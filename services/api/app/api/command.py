from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.detection import catalogue, list_alerts, list_findings
from app.services.graph import list_entities, serialize_entity
from app.services.incidents import list_incidents
from app.services.ingestion import list_dead_letters, list_events
from app.services.quality import compute_and_store

router = APIRouter(prefix="/command", tags=["command"])


@router.get("/overview")
def overview(
    actor: TenantActor = Depends(Permission("alerts:read")),
    db: Session = Depends(get_db),
) -> dict:
    alerts = list_alerts(db, actor.tenant_id)
    findings = list_findings(db, actor.tenant_id)
    events = list_events(db, actor.tenant_id)
    dlq = list_dead_letters(db, actor.tenant_id)
    quality = compute_and_store(db, actor.tenant_id)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    return {
        "tenant_id": actor.tenant_id,
        "open_alerts": sum(1 for item in alerts if item.status == "open"),
        "findings": len(findings),
        "events": len(events),
        "dead_letter": len(dlq),
        "incidents": len(list_incidents(db, actor.tenant_id)),
        "detections": len(catalogue()),
        "severity": severity_counts,
        "quality": {
            "total": quality.total,
            "band": quality.band,
            "model_version": quality.model_version,
        },
        "ai_required": False,
        "top_risk_entities": [
            serialize_entity(item)
            for item in list_entities(db, actor.tenant_id)
            if item.risk_score > 0
        ][:8],
        "top_alerts": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "created_at": item.created_at.isoformat(),
            }
            for item in alerts[:8]
        ],
    }
