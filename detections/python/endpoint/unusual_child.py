from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.unusual_child_process",
    name="Unusual child process",
    description="Trusted parent launches an unexpected LOLBin or payload-like child.",
    version="1.0.0",
    severity="medium",
    confidence=72,
    mitre_tactics=["execution"],
    mitre_techniques=["T1204"],
    data_sources=["endpoint"],
)

PARENTS = {"explorer.exe", "services.exe"}
CHILDREN = {"powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "payload.exe"}


class UnusualChildProcessRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "process" or not event.process or not event.parent_process:
            return []
        parent = (event.parent_process.name or "").lower()
        child = (event.process.name or "").lower()
        if parent not in PARENTS or child not in CHILDREN:
            return []
        if parent == "explorer.exe" and child in {"powershell.exe", "cmd.exe"}:
            # Explorer launching a shell is common; require a payload-like path.
            path = (event.process.path or "").lower()
            if "\\temp\\" not in path and "\\users\\" not in path and child != "payload.exe":
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
                explanation=f"Unusual child {child} from {parent}.",
            )
        ]
