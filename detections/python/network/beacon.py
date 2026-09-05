from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.repetitive_beacon",
    name="Repetitive beacon",
    description="Regular outbound connections from one host to one destination.",
    version="1.0.0",
    severity="high",
    confidence=82,
    mitre_tactics=["command-and-control"],
    mitre_techniques=["T1071"],
    data_sources=["network"],
)


class RepetitiveBeaconRule:
    meta = META
    min_repeats = 4
    window_seconds = 600

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "network" or not event.src_ip or not event.dst_ip:
            return []
        related = [
            item
            for item in context.events_in_window(event, self.window_seconds, src_ip=event.src_ip)
            if item.dst_ip == event.dst_ip and item.category == "network"
        ]
        if len(related) < self.min_repeats:
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.src_ip}:{event.dst_ip}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=f"{len(related)} outbound connections from {event.src_ip} to {event.dst_ip}.",
            )
        ]
