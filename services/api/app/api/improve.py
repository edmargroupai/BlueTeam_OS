from __future__ import annotations

from blueteam_attack import compute_coverage
from blueteam_improve import ImprovementEngine, analyse_findings
from blueteam_telemetry import evaluate_telemetry_health
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.replay import LAB as REPLAY_LAB
from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.detection import get_registry, list_findings
from app.services.ingestion import load_window
from app.services.rules import list_history, sync_catalog_revisions

router = APIRouter(prefix="/improve", tags=["improve"])
ENGINE = ImprovementEngine()


class CandidateBody(BaseModel):
    rule_id: str
    rationale: str
    ai_suggested: bool = False
    metrics: dict = Field(default_factory=dict)


@router.get("/analytics")
def analytics(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    sync_catalog_revisions(db)
    findings = [{"rule_id": row.rule_id} for row in list_findings(db, actor.tenant_id)]
    revisions = []
    for rule in get_registry().all_rules():
        for rev in list_history(db, rule.meta.rule_id):
            revisions.append({"rule_id": rev.rule_id, "name": rev.name, "status": rev.status})
    perf = analyse_findings(findings, revisions)
    detection_maps = [
        (rule.meta.rule_id, list(rule.meta.mitre_techniques), list(rule.meta.data_sources), rule.meta.status)
        for rule in get_registry().all_rules()
    ]
    coverage = compute_coverage(
        detection_maps=detection_maps,
        telemetry_source_types=sorted({event.source_type for event in load_window(db, actor.tenant_id)}),
        finding_technique_counts={},
    )
    attack_gaps = [item for item in coverage["techniques"] if item["gap_severity"] in {"critical", "high"}][:20]
    telem = evaluate_telemetry_health(events=load_window(db, actor.tenant_id), dead_letter_count=0)
    return {
        "performance": perf,
        "attack_gaps": attack_gaps,
        "telemetry_gaps": [
            w for w in telem["warnings"] if w["kind"] in {"silent_sensor", "missing_expected_data_source"}
        ],
        "promotion_policy": {"ai_may_auto_promote": False},
    }


@router.post("/candidates")
def create_candidate(
    body: CandidateBody,
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = ENGINE.create(
        rule_id=body.rule_id,
        rationale=body.rationale,
        metrics=body.metrics,
        ai_suggested=body.ai_suggested,
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="improve.candidate.create",
        target_type="improvement",
        target_id=row.candidate_id,
        after_state=row.as_dict(),
    )
    return row.as_dict()


@router.get("/candidates")
def list_candidates(_: TenantActor = Depends(Permission("detections:read"))) -> dict:
    items = [item.as_dict() for item in ENGINE.candidates.values()]
    return {"items": items, "count": len(items)}


@router.post("/candidates/{candidate_id}/replay")
def replay_candidate(
    candidate_id: str,
    actor: TenantActor = Depends(Permission("blue_range:execute")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = ENGINE.candidates.get(candidate_id)
    if row is None:
        from blueteam_common.errors import BlueTeamError

        raise BlueTeamError("NOT_FOUND", "Candidate not found", 404)
    if not REPLAY_LAB.datasets:
        dataset = REPLAY_LAB.register_dataset(name="auto-improve", relative_path=".")
    else:
        dataset = next(iter(REPLAY_LAB.datasets.values()))
    job = REPLAY_LAB.run(dataset.dataset_id, current=get_registry(), mode="current")
    updated = ENGINE.set_status(candidate_id, "replayed" if job.passed else "rejected", replay_job_id=job.job_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="improve.candidate.replay",
        target_type="improvement",
        target_id=candidate_id,
        after_state={"passed": job.passed, "job_id": job.job_id},
    )
    return {"candidate": updated.as_dict(), "job": job.as_dict()}
