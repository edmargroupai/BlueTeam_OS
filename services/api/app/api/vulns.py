from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.vulns import import_vulns, list_vulns

router = APIRouter(prefix="/vulns", tags=["vulns"])


class ImportBody(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)


@router.get("")
def get_vulns(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    items = list_vulns(db, actor.tenant_id)
    return {"items": items, "count": len(items)}


@router.post("/import")
def post_import(
    body: ImportBody,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    items = import_vulns(db, actor.tenant_id, body.findings)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="vulns.import",
        target_type="vulnerability",
        after_state={"count": len(items)},
    )
    return {"items": items, "count": len(items)}
