from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.audit import list_audit, verify_audit_chain
from app.services.auth import TenantActor

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def get_audit(
    actor: TenantActor = Depends(Permission("audit:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_audit(db, actor.tenant_id, include_platform=actor.is_platform_admin)
    return {
        "items": [
            {
                "id": row.id,
                "sequence": row.sequence,
                "tenant_id": row.tenant_id,
                "actor_type": row.actor_type,
                "actor_id": row.actor_id,
                "action": row.action,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "result": row.result,
                "timestamp": row.timestamp.isoformat(),
                "record_hash": row.record_hash,
            }
            for row in rows
        ]
    }


@router.get("/integrity")
def audit_integrity(
    actor: TenantActor = Depends(Permission("audit:read")),
    db: Session = Depends(get_db),
) -> dict:
    ok, reason = verify_audit_chain(db)
    return {"intact": ok, "reason": reason}
