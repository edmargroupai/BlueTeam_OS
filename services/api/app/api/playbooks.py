from __future__ import annotations

from blueteam_playbook import CATALOGUE, PlaybookEngine, get_playbook
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor

router = APIRouter(prefix="/playbooks", tags=["playbooks"])
_ENGINE = PlaybookEngine()


class RunBody(BaseModel):
    playbook_id: str
    dry_run: bool = True
    idempotency_key: str | None = None


class ApproveBody(BaseModel):
    step_ids: list[str] = Field(default_factory=list)


@router.get("")
def list_playbooks(_: TenantActor = Depends(Permission("broker:execute"))) -> dict:
    items = [
        {
            "playbook_id": item.playbook_id,
            "name": item.name,
            "description": item.description,
            "steps": [
                {
                    "id": step.id,
                    "action_type": step.action_type,
                    "tier": step.tier,
                    "depends_on": step.depends_on,
                    "retries": step.retries,
                    "rollback_action": step.rollback_action,
                }
                for step in item.steps
            ],
        }
        for item in CATALOGUE.values()
    ]
    return {"items": items, "count": len(items)}


@router.post("/run")
def run_playbook(
    body: RunBody,
    actor: TenantActor = Depends(Permission("broker:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    playbook = get_playbook(body.playbook_id)
    run = _ENGINE.run(
        playbook,
        tenant_id=actor.tenant_id,
        dry_run=body.dry_run,
        idempotency_key=body.idempotency_key,
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="playbook.run",
        target_type="playbook",
        target_id=run.run_id,
        after_state=run.as_dict(),
        result="success" if run.status in {"completed", "awaiting_approval"} else "denied",
    )
    return run.as_dict()


@router.get("/runs/{run_id}")
def get_run(
    run_id: str,
    _: TenantActor = Depends(Permission("broker:execute")),
) -> dict:
    run = _ENGINE.get(run_id)
    if run is None:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("NOT_FOUND", f"Playbook run {run_id} not found", 404)
    return run.as_dict()


@router.post("/runs/{run_id}/approve")
def approve_run(
    run_id: str,
    body: ApproveBody,
    actor: TenantActor = Depends(Permission("response:tier2")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    prior = _ENGINE.get(run_id)
    if prior is None:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("NOT_FOUND", f"Playbook run {run_id} not found", 404)
    playbook = get_playbook(prior.playbook_id)
    run = _ENGINE.approve(run_id, body.step_ids or prior.approval_required, playbook)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="playbook.approve",
        target_type="playbook",
        target_id=run.run_id,
        approval_status="approved",
        after_state=run.as_dict(),
    )
    return run.as_dict()
