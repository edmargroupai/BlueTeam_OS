from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.blue_range import execute_all, execute_one

router = APIRouter(prefix="/blue-range", tags=["blue-range"])


@router.post("/run")
def run_all(
    actor: TenantActor = Depends(Permission("blue_range:execute")),
    db: Session = Depends(get_db),
) -> dict:
    results = execute_all()
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="blue_range.run",
        target_type="blue_range",
        after_state={"scenarios": len(results), "passed": sum(1 for item in results if item["passed"])},
        result="success",
    )
    return {"items": results}


@router.post("/run/{scenario_id}")
def run_one(
    scenario_id: str,
    actor: TenantActor = Depends(Permission("blue_range:execute")),
    db: Session = Depends(get_db),
) -> dict:
    try:
        result = execute_one(scenario_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scenario not found") from exc
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="blue_range.run_one",
        target_type="blue_range",
        target_id=scenario_id,
        result="success" if result["passed"] else "error",
    )
    return result
