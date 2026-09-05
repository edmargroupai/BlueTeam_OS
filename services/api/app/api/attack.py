from __future__ import annotations

from collections import Counter

from blueteam_attack import catalogue, compute_coverage, technique_detail
from blueteam_common.errors import BlueTeamError
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.detection import get_registry, list_findings
from app.services.ingestion import load_window

router = APIRouter(prefix="/attack", tags=["attack"])


def _build_coverage(db: Session, tenant_id: str) -> dict:
    detection_maps = []
    validated: set[str] = set()
    for rule in get_registry().all_rules():
        meta = rule.meta
        detection_maps.append(
            (
                meta.rule_id,
                list(meta.mitre_techniques),
                list(meta.data_sources),
                meta.status,
            )
        )
        if meta.status in {"tested", "promoted"}:
            validated.add(meta.rule_id)
    events = load_window(db, tenant_id)
    source_types = sorted({event.source_type for event in events} | {event.category for event in events})
    finding_counts: Counter[str] = Counter()
    for finding in list_findings(db, tenant_id):
        for tech in finding.mitre_techniques or []:
            finding_counts[str(tech)] += 1
        for tech in (finding.payload or {}).get("mitre_techniques") or []:
            finding_counts[str(tech)] += 1
    return compute_coverage(
        detection_maps=detection_maps,
        telemetry_source_types=source_types,
        finding_technique_counts=dict(finding_counts),
        validated_rule_ids=validated,
    )


@router.get("/catalogue")
def get_catalogue(_: TenantActor = Depends(Permission("detections:read"))) -> dict:
    return {"items": catalogue()}


@router.get("/coverage")
def coverage(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    body = _build_coverage(db, actor.tenant_id)
    return {"tenant_id": actor.tenant_id, **body}


@router.get("/techniques/{technique_id}")
def get_technique(
    technique_id: str,
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    body = _build_coverage(db, actor.tenant_id)
    detail = technique_detail(body, technique_id)
    if detail is None:
        raise BlueTeamError("NOT_FOUND", f"Technique {technique_id} not in coverage set", 404)
    return detail
