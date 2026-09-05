from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.encoded_powershell",
    name="Encoded PowerShell",
    description="PowerShell launched with encoded command switches.",
    version="1.0.0",
    severity="high",
    confidence=86,
    mitre_tactics=["defense-evasion", "execution"],
    mitre_techniques=["T1027", "T1059.001"],
    data_sources=["endpoint", "process"],
)

MARKERS = (" -enc ", " -encodedcommand ", " -e ", "frombase64string")


class EncodedPowershellRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "process" or not event.process:
            return []
        name = (event.process.name or "").lower()
        cmd = (event.process.command_line or "").lower()
        if name not in {"powershell.exe", "pwsh.exe"} or not any(marker in f" {cmd} " for marker in MARKERS):
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.id}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation="PowerShell command line contains an encoded-command marker.",
            )
        ]
