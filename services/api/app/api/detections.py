from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from pydantic import BaseModel, Field

from app.services.detection import catalogue, list_findings, run_scheduled
from app.services.rules import list_history, promote, set_status, sync_catalog_revisions
from app.services.suppression import create_exception, create_suppression, list_exceptions, list_suppressions

router = APIRouter(prefix="/detections", tags=["detections"])


class SuppressionBody(BaseModel):
    rule_id: str
    entity_key: str
    entity_value: str
    reason: str = Field(min_length=3)


class StatusBody(BaseModel):
    status: str


@router.get("")
def list_rules(_: TenantActor = Depends(Permission("detections:read"))) -> dict:
    return {"items": catalogue()}


@router.get("/findings")
def findings(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_findings(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "rule_id": row.rule_id,
                "rule_version": row.rule_version,
                "title": row.title,
                "severity": row.severity,
                "confidence": row.confidence,
                "explanation": row.explanation,
                "mitre_techniques": row.mitre_techniques,
                "event_ids": row.event_ids,
                "evidence_ids": row.evidence_ids,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }


@router.post("/scheduled/run")
def scheduled_run(
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
) -> dict:
    created = run_scheduled(db, actor.tenant_id, actor_id=actor.user_id)
    return {"findings_created": created, "execution": "scheduled"}


@router.get("/suppressions")
def get_suppressions(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    return {
        "suppressions": [
            {
                "id": row.id,
                "rule_id": row.rule_id,
                "entity_key": row.entity_key,
                "entity_value": row.entity_value,
                "reason": row.reason,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            }
            for row in list_suppressions(db, actor.tenant_id)
        ],
        "exceptions": [
            {
                "id": row.id,
                "rule_id": row.rule_id,
                "entity_key": row.entity_key,
                "entity_value": row.entity_value,
                "reason": row.reason,
            }
            for row in list_exceptions(db, actor.tenant_id)
        ],
    }


@router.post("/suppressions")
def add_suppression(
    body: SuppressionBody,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
) -> dict:
    row = create_suppression(
        db,
        tenant_id=actor.tenant_id,
        rule_id=body.rule_id,
        entity_key=body.entity_key,
        entity_value=body.entity_value,
        reason=body.reason,
        actor_id=actor.user_id,
    )
    return {"id": row.id, "rule_id": row.rule_id}


@router.post("/exceptions")
def add_exception(
    body: SuppressionBody,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
) -> dict:
    row = create_exception(
        db,
        tenant_id=actor.tenant_id,
        rule_id=body.rule_id,
        entity_key=body.entity_key,
        entity_value=body.entity_value,
        reason=body.reason,
        actor_id=actor.user_id,
    )
    return {"id": row.id, "rule_id": row.rule_id}


@router.get("/rules/{rule_id}/history")
def rule_history(
    rule_id: str,
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    sync_catalog_revisions(db)
    rows = list_history(db, rule_id)
    return {
        "rule_id": rule_id,
        "items": [
            {
                "id": row.id,
                "version": row.version,
                "status": row.status,
                "checksum": row.checksum,
                "created_at": row.created_at.isoformat(),
                "created_by": row.created_by,
            }
            for row in rows
        ],
    }


@router.post("/rules/{rule_id}/promote")
def promote_rule(
    rule_id: str,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
) -> dict:
    sync_catalog_revisions(db)
    row = promote(db, rule_id, actor_id=actor.user_id)
    return {"rule_id": row.rule_id, "version": row.version, "status": row.status}


@router.post("/rules/{rule_id}/status")
def change_status(
    rule_id: str,
    body: StatusBody,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
) -> dict:
    sync_catalog_revisions(db)
    row = set_status(db, rule_id, body.status, actor_id=actor.user_id)
    return {"rule_id": row.rule_id, "version": row.version, "status": row.status}
