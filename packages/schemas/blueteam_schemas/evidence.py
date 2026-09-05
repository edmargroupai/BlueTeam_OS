"""Evidence provenance. Primary telemetry outranks AI interpretation."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ConfidenceLevel(IntEnum):
    PRIMARY_TELEMETRY = 1
    DETERMINISTIC_DERIVED = 2
    STATISTICAL_INFERENCE = 3
    AI_INTERPRETATION = 4
    ANALYST_ASSESSMENT = 5


class ChainOfCustodyEvent(BaseModel):
    id: str
    tenant_id: str
    evidence_id: str
    actor_type: str
    actor_id: str
    action: Literal["acquired", "ingested", "hashed", "parsed", "exported", "reviewed", "sealed"]
    timestamp: datetime
    notes: str | None = None
    previous_hash: str | None = None
    record_hash: str


class EvidenceObject(BaseModel):
    id: str
    tenant_id: str
    incident_id: str | None = None
    source: str
    acquisition_method: str
    original_timestamp: datetime
    ingested_at: datetime
    collector_identity: str
    integrity_hash: str
    object_uri: str | None = None
    parser_version: str
    transformation_history: list[str] = Field(default_factory=list)
    confidence_level: ConfidenceLevel = ConfidenceLevel.PRIMARY_TELEMETRY
    payload_ref: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    sealed: bool = False


class IncidentClaim(BaseModel):
    id: str
    tenant_id: str
    incident_id: str | None = None
    claim_text: str
    confidence: float
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    inference_type: ConfidenceLevel
    model_or_rule_version: str
    unknowns: list[str] = Field(default_factory=list)
    analyst_disposition: str | None = None

    def validate_evidence_refs(self, known_ids: set[str]) -> None:
        missing = [eid for eid in self.supporting_evidence_ids if eid not in known_ids]
        if missing:
            raise ValueError(f"unsupported evidence references: {missing}")
        missing_c = [eid for eid in self.contradicting_evidence_ids if eid not in known_ids]
        if missing_c:
            raise ValueError(f"unsupported contradicting evidence references: {missing_c}")
