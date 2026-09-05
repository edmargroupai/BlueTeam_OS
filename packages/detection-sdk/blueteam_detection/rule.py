from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from blueteam_detection.context import DetectionContext


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    description: str
    version: str
    severity: str
    confidence: float
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    author: str = "blueteam-os"
    status: str = "tested"
    execution: str = "realtime"


class DetectionRule(Protocol):
    meta: RuleMeta

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        """Pure evaluation. Must not perform network I/O."""
        ...
