from __future__ import annotations

from blueteam_schemas.evidence import IncidentClaim
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission
from app.services.auth import TenantActor
from app.services.evidence import (
    evidence_manifest_hash,
    list_evidence,
    validate_claim,
    verify_evidence,
)

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("")
def get_evidence(
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_evidence(db, actor.tenant_id)
    return {
        "items": [
            {
                "id": row.id,
                "source": row.source,
                "integrity_hash": row.integrity_hash,
                "confidence_level": row.confidence_level,
                "sealed": row.sealed,
                "ingested_at": row.ingested_at.isoformat(),
            }
            for row in rows
        ],
        "manifest_hash": evidence_manifest_hash(db, actor.tenant_id),
    }


@router.get("/{evidence_id}/verify")
def verify(
    evidence_id: str,
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    return verify_evidence(db, actor.tenant_id, evidence_id)


class ClaimRequest(BaseModel):
    claim_text: str
    confidence: float
    supporting_evidence_ids: list[str] = Field(min_length=1)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    inference_type: int = 2
    model_or_rule_version: str


@router.post("/claims/validate")
def validate_ai_or_analyst_claim(
    body: ClaimRequest,
    actor: TenantActor = Depends(Permission("evidence:read")),
    db: Session = Depends(get_db),
) -> dict:
    claim = IncidentClaim(
        id="clm_preview",
        tenant_id=actor.tenant_id,
        claim_text=body.claim_text,
        confidence=body.confidence,
        supporting_evidence_ids=body.supporting_evidence_ids,
        contradicting_evidence_ids=body.contradicting_evidence_ids,
        inference_type=body.inference_type,  # type: ignore[arg-type]
        model_or_rule_version=body.model_or_rule_version,
    )
    validate_claim(db, actor.tenant_id, claim)
    return {"valid": True}
