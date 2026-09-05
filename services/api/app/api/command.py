from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import Permission
from app.models.ops import RuleRevision
from app.services.auth import TenantActor
from app.services.detection import catalogue, list_alerts, list_findings
from app.services.graph import list_entities, serialize_entity
from app.services.incidents import list_incidents, serialize_incident
from app.services.ingestion import list_dead_letters, list_events
from app.services.quality import compute_and_store
from blueteam_dataplane.probes import probe_all

router = APIRouter(prefix="/command", tags=["command"])


@router.get("/overview")
def overview(
    actor: TenantActor = Depends(Permission("alerts:read")),
    db: Session = Depends(get_db),
) -> dict:
    settings = get_settings()
    alerts = list_alerts(db, actor.tenant_id)
    findings = list_findings(db, actor.tenant_id)
    events = list_events(db, actor.tenant_id)
    dlq = list_dead_letters(db, actor.tenant_id)
    incidents = list_incidents(db, actor.tenant_id)
    quality = compute_and_store(db, actor.tenant_id)
    plane = probe_all(settings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    technique_counts: Counter[str] = Counter()
    for finding in findings:
        for tech in finding.mitre_techniques or []:
            technique_counts[str(tech)] += 1
        payload = finding.payload or {}
        for tech in payload.get("mitre_techniques") or []:
            technique_counts[str(tech)] += 1
    for incident in incidents:
        for tech in incident.mitre_techniques or []:
            technique_counts[str(tech)] += 1

    revisions = list(db.execute(select(RuleRevision)).scalars().all())
    by_status: Counter[str] = Counter(row.status for row in revisions)
    catalog = catalogue()

    open_incidents = [item for item in incidents if item.status not in {"closed", "recovered"}]
    automation_queue = [
        {
            "id": item.id,
            "title": item.title,
            "status": item.status,
            "queue": "incident_response",
            "updated_at": item.updated_at.isoformat(),
        }
        for item in open_incidents
        if item.status in {"new", "triaging", "investigating", "contained"}
    ][:12]

    return {
        "tenant_id": actor.tenant_id,
        "open_alerts": sum(1 for item in alerts if item.status == "open"),
        "findings": len(findings),
        "events": len(events),
        "dead_letter": len(dlq),
        "incidents": len(incidents),
        "detections": len(catalog),
        "severity": severity_counts,
        "quality": {
            "total": quality.total,
            "band": quality.band,
            "model_version": quality.model_version,
        },
        "ai_required": False,
        "telemetry_health": {
            "events": len(events),
            "dead_letter": len(dlq),
            "dead_letter_ratio": (len(dlq) / max(len(events) + len(dlq), 1)),
            "data_plane": plane["probes"],
            "all_configured_connected": plane["all_configured_connected"],
        },
        "detection_health": {
            "catalogue_rules": len(catalog),
            "revisions": len(revisions),
            "by_status": dict(by_status),
            "findings": len(findings),
            "open_alerts": sum(1 for item in alerts if item.status == "open"),
        },
        "attack_overview": {
            "techniques_observed": len(technique_counts),
            "top_techniques": [
                {"technique": tech, "count": count} for tech, count in technique_counts.most_common(8)
            ],
        },
        "automation_queue": automation_queue,
        "top_risk_entities": [
            serialize_entity(item)
            for item in list_entities(db, actor.tenant_id)
            if item.risk_score > 0
        ][:8],
        "top_incidents": [serialize_incident(item) for item in open_incidents[:8]],
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
