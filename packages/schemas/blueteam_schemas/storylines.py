from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class StorylineStage(BaseModel):
    name: str
    rule_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None


class Storyline(BaseModel):
    storyline_id: str
    tenant_id: str
    title: str
    entities: dict[str, list[str]] = Field(default_factory=dict)
    stages: list[StorylineStage] = Field(default_factory=list)
    confidence: float
    evidence_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    start: datetime
    end: datetime
    attributes: dict[str, Any] = Field(default_factory=dict)
