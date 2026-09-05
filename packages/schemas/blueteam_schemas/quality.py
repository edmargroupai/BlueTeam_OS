"""Evidence-backed quality scoring. UI cannot write these values."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

QUALITY_DOMAINS: dict[str, int] = {
    "network_defence": 100,
    "endpoint_defence": 100,
    "incident_response": 100,
    "dfir": 80,
    "detection_engineering": 100,
    "threat_hunting": 80,
    "identity_security": 80,
    "cloud_security": 70,
    "defensive_architecture": 70,
    "threat_intelligence": 50,
    "response_automation": 60,
    "continuous_monitoring": 50,
}

MaturityBand = Literal[
    "prototype",
    "basic_soc",
    "professional",
    "advanced",
    "expert",
    "gse_calibre",
    "elite",
]


def maturity_band(score: int) -> MaturityBand:
    if score >= 975:
        return "elite"
    if score >= 925:
        return "gse_calibre"
    if score >= 850:
        return "expert"
    if score >= 750:
        return "advanced"
    if score >= 650:
        return "professional"
    if score >= 500:
        return "basic_soc"
    return "prototype"


class QualityCheckResult(BaseModel):
    check_id: str
    domain: str
    title: str
    max_points: int
    awarded_points: int
    passed: bool
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str

    @property
    def missing_evidence(self) -> bool:
        return not self.evidence_ids


class QualityIndex(BaseModel):
    model_version: str
    computed_at: datetime
    total: int
    maximum: int = 1000
    band: MaturityBand
    domains: dict[str, int]
    checks: list[QualityCheckResult]
    unsigned: bool = False
