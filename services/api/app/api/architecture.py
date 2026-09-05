from __future__ import annotations

from blueteam_architecture import ArchitectureStore, default_lab_architecture, detection_gaps
from blueteam_attack import compute_coverage
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.detection import get_registry

router = APIRouter(prefix="/architecture", tags=["architecture"])
STORE = ArchitectureStore()


@router.get("")
def get_architecture(
    actor: TenantActor = Depends(Permission("detections:read")),
) -> dict:
    graph = STORE.latest(actor.tenant_id)
    if graph is None:
        graph = STORE.save(default_lab_architecture(actor.tenant_id))
    return graph.as_dict()


@router.post("/seed")
def seed_architecture(
    actor: TenantActor = Depends(Permission("detections:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    graph = STORE.save(default_lab_architecture(actor.tenant_id))
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="architecture.seed",
        target_type="architecture",
        target_id=graph.graph_id,
        after_state={"version": graph.version},
    )
    return graph.as_dict()


@router.get("/gaps")
def architecture_gaps(
    actor: TenantActor = Depends(Permission("detections:read")),
) -> dict:
    graph = STORE.latest(actor.tenant_id) or STORE.save(default_lab_architecture(actor.tenant_id))
    detection_maps = [
        (rule.meta.rule_id, list(rule.meta.mitre_techniques), list(rule.meta.data_sources), rule.meta.status)
        for rule in get_registry().all_rules()
    ]
    coverage = compute_coverage(
        detection_maps=detection_maps,
        telemetry_source_types=[],
        finding_technique_counts={},
    )
    covered = [item["technique_id"] for item in coverage["techniques"] if item["detections"]]
    gaps = detection_gaps(graph, covered)
    return {"graph_id": graph.graph_id, "version": graph.version, "gaps": gaps, "count": len(gaps)}


@router.get("/versions")
def architecture_versions(actor: TenantActor = Depends(Permission("detections:read"))) -> dict:
    items = [item.as_dict() for item in STORE.history(actor.tenant_id)]
    return {"items": items, "count": len(items)}
