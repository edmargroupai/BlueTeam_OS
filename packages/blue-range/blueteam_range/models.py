from __future__ import annotations

from datetime import datetime
from typing import Any

from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding
from pydantic import BaseModel, Field


class ExpectedDetection(BaseModel):
    rule_id: str
    min_count: int = 1
    mitre_techniques: list[str] = Field(default_factory=list)


class RangeScenario(BaseModel):
    id: str
    family: str
    name: str
    description: str
    attack_techniques: list[str]
    max_detection_latency_seconds: float = 5.0
    allowed_false_positive_envelope: int = 0
    events: list[CanonicalEvent]
    expected_event_count: int
    expected_detections: list[ExpectedDetection]
    expected_mitre: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class DetectionAssertion(BaseModel):
    rule_id: str
    expected_min: int
    observed: int
    passed: bool


class RangeResult(BaseModel):
    scenario_id: str
    passed: bool
    started_at: datetime
    finished_at: datetime
    latency_seconds: float
    event_count: int
    findings: list[Finding]
    assertions: list[DetectionAssertion]
    unexpected_rule_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
