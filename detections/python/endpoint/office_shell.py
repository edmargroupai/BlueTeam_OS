from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.office_spawns_shell",
    name="Office spawns a shell",
    description="Office process launches powershell, cmd, or wscript.",
    version="1.0.0",
    severity="high",
    confidence=88,
    mitre_tactics=["execution"],
    mitre_techniques=["T1059.001", "T1204.002"],
    data_sources=["endpoint", "process"],
)

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}


class OfficeSpawnsShellRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "process" or not event.process or not event.parent_process:
            return []
        child = (event.process.name or "").lower()
        parent = (event.parent_process.name or "").lower()
        if parent not in OFFICE or child not in SHELLS:
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{parent}:{child}:{event.id}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=f"{parent} spawned {child}.",
            )
        ]
