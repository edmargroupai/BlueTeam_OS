from __future__ import annotations

from pathlib import Path

from blueteam_range.loader import load_scenarios
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.quality import build_checks

router = APIRouter(prefix="/readiness", tags=["readiness"])
REPO = Path(__file__).resolve().parents[4]


@router.get("/gate")
def production_readiness_gate(
    actor: TenantActor = Depends(Permission("quality:read")),
    db: Session = Depends(get_db),
) -> dict:
    checks = build_checks(db, actor.tenant_id)
    required = [
        "identity.blue_range",
        "network.blue_range",
        "endpoint.blue_range",
        "replay.regression_gate",
        "improve.candidates",
        "ai.offline_default",
        "dfir.manifest_export",
        "architecture.seeded",
    ]
    by_id = {item.check_id: item for item in checks}
    results = []
    for check_id in required:
        item = by_id.get(check_id)
        results.append(
            {
                "check_id": check_id,
                "present": item is not None,
                "passed": bool(item and item.passed and item.evidence_ids),
                "evidence_ids": list(item.evidence_ids) if item else [],
            }
        )
    scenario_root = REPO / "blue_range" / "scenarios"
    scenarios = load_scenarios(scenario_root) if scenario_root.exists() else []
    present_required = [item for item in results if item["present"]]
    passed = bool(present_required) and all(item["passed"] for item in present_required) and len(scenarios) >= 6
    return {
        "tenant_id": actor.tenant_id,
        "gate": "production_readiness" if passed else "not_ready",
        "passed": passed,
        "scenario_count": len(scenarios),
        "required_checks": results,
        "note": (
            "GSE-calibre band still requires evidence-backed quality total >= 925; "
            "this gate is necessary but not sufficient."
        ),
    }
