from __future__ import annotations

from blueteam_broker.broker import ExecutionBroker
from blueteam_common.ids import new_id
from blueteam_schemas.actions import ActionRequest
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.audit import write_audit
from app.services.auth import TenantActor

router = APIRouter(prefix="/broker", tags=["broker"])
_BROKER = ExecutionBroker()


class BrokerSubmit(BaseModel):
    action_type: str
    reason: str
    dry_run: bool = True
    params: dict = Field(default_factory=dict)
    target: dict = Field(default_factory=dict)


@router.post("/actions")
def submit_action(
    body: BrokerSubmit,
    actor: TenantActor = Depends(Permission("broker:execute")),
    db: Session = Depends(get_db),
) -> dict:
    request = ActionRequest(
        action_id=new_id("act"),
        action_type=body.action_type,
        tenant_id=actor.tenant_id,
        target=body.target,
        params=body.params,
        reason=body.reason,
        requested_by=actor.user_id,
        dry_run=body.dry_run,
        actor_roles=actor.role_keys,
        permissions=sorted(actor.permissions | ({"admin:platform"} if actor.is_platform_admin else set())),
    )
    result = _BROKER.submit(request)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type=actor.actor_type,
        actor_id=actor.user_id,
        request_id=actor.request_id,
        action="broker.submit",
        target_type="action",
        target_id=result.action_id,
        policy_decision=result.policy_decision,
        reason=body.reason,
        result="denied" if result.status in {"denied", "failed"} else "success",
        after_state={"action_type": body.action_type, "status": result.status, "dry_run": body.dry_run},
    )
    return result.model_dump(mode="json")
