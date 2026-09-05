"""Entity graph contracts. Relationships require source event IDs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EntityType = Literal["user", "host", "ip", "domain", "process", "cloud_resource"]
Criticality = Literal["unknown", "low", "medium", "high", "crown_jewel"]
RelationType = Literal[
    "used_from",
    "on_host",
    "ran",
    "child_of",
    "connected_to",
    "queried",
    "owns",
]


class RiskComponent(BaseModel):
    source: str
    kind: Literal["detection", "intel", "criticality"]
    points: float
    explanation: str


class GraphEntity(BaseModel):
    id: str
    tenant_id: str
    entity_type: EntityType
    key: str
    display_name: str
    criticality: Criticality = "unknown"
    risk_score: float = 0.0
    risk_components: list[RiskComponent] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphRelationship(BaseModel):
    id: str
    tenant_id: str
    src_id: str
    dst_id: str
    relation: RelationType
    event_ids: list[str] = Field(default_factory=list)
    manufactured: bool = False


class EntityGraph(BaseModel):
    tenant_id: str
    entities: list[GraphEntity]
    relationships: list[GraphRelationship]
    manufactured_edges: bool = False
