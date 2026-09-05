from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from blueteam_schemas.evidence import IncidentClaim
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.evidence import list_evidence, validate_claim

router = APIRouter(prefix="/ai", tags=["ai"])

ROOT = Path(__file__).resolve().parents[4]
_SPEC = importlib.util.spec_from_file_location(
    "blueteam_ai_gateway",
    ROOT / "services" / "ai-gateway" / "app" / "gateway.py",
)
assert _SPEC and _SPEC.loader
_gateway = importlib.util.module_from_spec(_SPEC)
sys.modules["blueteam_ai_gateway"] = _gateway
_SPEC.loader.exec_module(_gateway)


class AnalystBody(BaseModel):
    task: str = "incident_summary"
    incident_id: str | None = None
    alert_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    question: str = ""


def _offline_summary(*, evidence_ids: list[str], task: str, question: str) -> dict:
    return {
        "task": task,
        "mode": "deterministic_offline",
        "summary": (
            f"Offline analyst response for {task}. "
            f"Grounded only on evidence refs {evidence_ids or ['none']}. "
            "No model was invoked."
        ),
        "suggested_queries": [
            {"dsl": "blueql", "query": "events where severity in ['high','critical'] | limit 50"},
            {"dsl": "structured", "query": {"category": "authentication", "outcome": "failure"}},
        ],
        "unknowns": ["Live model summarisation unavailable while AI gateway is offline"],
        "question": question,
        "fabricated": False,
    }


@router.post("/analyst")
def ai_analyst(
    body: AnalystBody,
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    settings = get_settings()
    known = {row.id for row in list_evidence(db, actor.tenant_id)}
    if body.evidence_ids:
        claim = IncidentClaim(
            id="clm_ai",
            tenant_id=actor.tenant_id,
            claim_text=body.question or body.task,
            confidence=0.4,
            supporting_evidence_ids=body.evidence_ids,
            inference_type=4,
            model_or_rule_version="ai-analyst-offline-1",
        )
        validate_claim(db, actor.tenant_id, claim)
    decision = _gateway.route(
        _gateway.AIRequest(
            tenant_id=actor.tenant_id,
            feature="soc-analyst",
            task_type="summarise",
            context_refs=body.evidence_ids,
            requested_capability=body.task,
            max_cost=0.5,
            max_tokens=800,
            sensitivity="low",
            structured_output_schema={"required": ["summary", "fabricated"]},
            prompt=body.question,
        ),
        ai_enabled=settings.ai_enabled,
    )
    payload = _offline_summary(evidence_ids=body.evidence_ids, task=body.task, question=body.question)
    errors = _gateway.validate_structured(payload, {"required": ["summary", "fabricated"]})
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="ai.analyst",
        target_type="ai",
        target_id=body.task,
        after_state={"decision": decision.decision, "evidence_ids": body.evidence_ids, "schema_errors": errors},
    )
    return {
        "decision": decision.decision,
        "reason": decision.reason,
        "provider": decision.provider,
        "known_evidence": sorted(known)[:20],
        "result": payload,
        "schema_errors": errors,
        "ledger": _gateway.ledger(),
    }


@router.get("/gateway")
def gateway_status(_: TenantActor = Depends(Permission("quality:read"))) -> dict:
    settings = get_settings()
    return {"ai_enabled": settings.ai_enabled, "ledger": _gateway.ledger()}
