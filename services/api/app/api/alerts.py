from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.detection import list_alerts

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def get_alerts(
    actor: TenantActor = Depends(Permission("alerts:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_alerts(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "finding_id": row.finding_id,
                "title": row.title,
                "severity": row.severity,
                "status": row.status,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
    }
