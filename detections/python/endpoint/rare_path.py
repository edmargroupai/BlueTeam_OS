from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.rare_executable_path",
    name="Rare executable path",
    description="Executable launched from a world-writable or user-temp path.",
    version="1.0.0",
    severity="medium",
    confidence=70,
    mitre_tactics=["defense-evasion"],
    mitre_techniques=["T1036"],
    data_sources=["endpoint"],
)

RARE = ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/", "\\users\\public\\")


class RareExecutablePathRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "process" or not event.process:
            return []
        path = (event.process.path or "").lower()
        if not path or not any(token in path for token in RARE):
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{path}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=f"Process launched from rare path {path}.",
            )
        ]
