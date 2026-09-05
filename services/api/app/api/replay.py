from __future__ import annotations

from pathlib import Path

from blueteam_replay import ReplayLab
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.detection import get_registry

router = APIRouter(prefix="/replay", tags=["replay"])
REPO = Path(__file__).resolve().parents[4]
SCENARIO_ROOT = REPO / "blue_range" / "scenarios"
LAB = ReplayLab(SCENARIO_ROOT)


class DatasetBody(BaseModel):
    name: str
    relative_path: str = "."


class JobBody(BaseModel):
    dataset_id: str
    mode: str = "current"


@router.post("/datasets")
def register_dataset(
    body: DatasetBody,
    actor: TenantActor = Depends(Permission("blue_range:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    dataset = LAB.register_dataset(name=body.name, relative_path=body.relative_path)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="replay.dataset.register",
        target_type="replay_dataset",
        target_id=dataset.dataset_id,
        after_state=dataset.as_dict(),
    )
    return dataset.as_dict()


@router.get("/datasets")
def list_datasets(_: TenantActor = Depends(Permission("detections:read"))) -> dict:
    items = [item.as_dict() for item in LAB.datasets.values()]
    return {"items": items, "count": len(items)}


@router.post("/jobs")
def run_job(
    body: JobBody,
    actor: TenantActor = Depends(Permission("blue_range:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    job = LAB.run(body.dataset_id, current=get_registry(), mode=body.mode)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="replay.job.run",
        target_type="replay_job",
        target_id=job.job_id,
        after_state={"passed": job.passed, "mode": job.mode},
        result="success" if job.passed else "denied",
    )
    return job.as_dict()


@router.get("/jobs")
def list_jobs(_: TenantActor = Depends(Permission("detections:read"))) -> dict:
    items = [item.as_dict() for item in LAB.jobs.values()]
    return {"items": items, "count": len(items)}


@router.get("/jobs/{job_id}")
def get_job(job_id: str, _: TenantActor = Depends(Permission("detections:read"))) -> dict:
    job = LAB.jobs.get(job_id)
    if job is None:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("NOT_FOUND", f"Replay job {job_id} not found", 404)
    return job.as_dict()


def regression_gate(rule_id: str) -> bool:
    return LAB.rule_regression_passed(rule_id)
