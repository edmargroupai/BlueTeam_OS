from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.quality import compute_and_store

router = APIRouter(prefix="/quality", tags=["quality"])


@router.get("/index")
def quality_index(
    actor: TenantActor = Depends(Permission("quality:read")),
    db: Session = Depends(get_db),
) -> dict:
    snapshot = compute_and_store(db, actor.tenant_id)
    return {
        "id": snapshot.id,
        "model_version": snapshot.model_version,
        "total": snapshot.total,
        "maximum": 1000,
        "band": snapshot.band,
        "domains": snapshot.domains,
        "checks": snapshot.checks,
        "computed_at": snapshot.computed_at.isoformat(),
        "editable": False,
    }
