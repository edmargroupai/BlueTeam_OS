from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.intel import (
    deactivate_ioc,
    expire_stale,
    get_ioc,
    list_iocs,
    serialize_ioc,
    upsert_ioc,
)

router = APIRouter(prefix="/intel", tags=["intel"])


class IocBody(BaseModel):
    indicator_type: str
    value: str
    source: str
    confidence: float = 0.7
    ttl_hours: int = 168
    malware: str | None = None
    actor: str | None = None
    campaign: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)


@router.get("/iocs")
def get_iocs(
    include_expired: bool = False,
    actor: TenantActor = Depends(Permission("intel:read")),
    db: Session = Depends(get_db),
) -> dict:
    expire_stale(db, actor.tenant_id)
    rows = list_iocs(db, actor.tenant_id, include_expired=include_expired)
    return {"items": [serialize_ioc(row) for row in rows], "count": len(rows)}


@router.post("/iocs")
def create_ioc(
    body: IocBody,
    actor: TenantActor = Depends(Permission("intel:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = upsert_ioc(
        db,
        actor.tenant_id,
        indicator_type=body.indicator_type,
        value=body.value,
        source=body.source,
        confidence=body.confidence,
        ttl_hours=body.ttl_hours,
        actor_id=actor.user_id,
        malware=body.malware,
        actor=body.actor,
        campaign=body.campaign,
        mitre_techniques=body.mitre_techniques,
        tags=body.tags,
        provenance=body.provenance,
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="intel.ioc_upsert",
        target_type="ioc",
        target_id=row.id,
        after_state={"type": row.indicator_type, "value": row.value, "source": row.source},
    )
    return serialize_ioc(row)


@router.get("/iocs/{ioc_id}")
def read_ioc(
    ioc_id: str,
    actor: TenantActor = Depends(Permission("intel:read")),
    db: Session = Depends(get_db),
) -> dict:
    return serialize_ioc(get_ioc(db, actor.tenant_id, ioc_id))


@router.post("/iocs/{ioc_id}/deactivate")
def deactivate(
    ioc_id: str,
    actor: TenantActor = Depends(Permission("intel:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = deactivate_ioc(db, get_ioc(db, actor.tenant_id, ioc_id), actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="intel.ioc_deactivate",
        target_type="ioc",
        target_id=row.id,
    )
    return serialize_ioc(row)


@router.post("/expire")
def expire(
    actor: TenantActor = Depends(Permission("intel:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    count = expire_stale(db, actor.tenant_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="intel.expire",
        target_type="ioc",
        after_state={"expired": count},
    )
    return {"expired": count}
