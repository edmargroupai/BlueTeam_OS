from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.suspicious_script_interpreter",
    name="Suspicious script interpreter",
    description="Script host or interpreter launched from user content paths.",
    version="1.0.0",
    severity="medium",
    confidence=74,
    mitre_tactics=["execution"],
    mitre_techniques=["T1059"],
    data_sources=["endpoint", "process"],
)

INTERPRETERS = {"wscript.exe", "cscript.exe", "mshta.exe", "python.exe", "wmic.exe"}
USER_PATHS = ("\\users\\", "/home/", "\\appdata\\", "\\temp\\")


class SuspiciousScriptInterpreterRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "process" or not event.process:
            return []
        name = (event.process.name or "").lower()
        path = (event.process.path or event.process.command_line or "").lower()
        if name not in INTERPRETERS:
            return []
        if not any(token in path for token in USER_PATHS):
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{name}:{event.id}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=f"{name} executed from a user/content path.",
            )
        ]
