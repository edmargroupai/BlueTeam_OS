from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]


class FindingEvidence(BaseModel):
    evidence_id: str
    event_id: str | None = None
    role: Literal["trigger", "supporting", "context"] = "supporting"


class Finding(BaseModel):
    id: str
    tenant_id: str
    rule_id: str
    rule_version: str
    title: str
    description: str
    severity: Severity
    confidence: float
    fingerprint: str
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    evidence: list[FindingEvidence] = Field(default_factory=list)
    explanation: str
    created_at: datetime
    attributes: dict[str, str] = Field(default_factory=dict)
