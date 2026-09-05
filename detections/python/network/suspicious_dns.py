from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.suspicious_dns",
    name="Suspicious DNS",
    description="Unusually long DNS query labels consistent with tunneling or DGA-like names.",
    version="1.0.0",
    severity="medium",
    confidence=70,
    mitre_tactics=["command-and-control", "exfiltration"],
    mitre_techniques=["T1071.004"],
    data_sources=["dns"],
)


class SuspiciousDnsRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "dns" or not event.domain:
            return []
        labels = event.domain.split(".")
        long_label = max((len(part) for part in labels), default=0)
        if long_label < 40 and "tunnel" not in event.domain.lower():
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.domain}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=f"DNS query {event.domain} has a {long_label}-character label.",
            )
        ]
