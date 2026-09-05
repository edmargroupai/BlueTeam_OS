from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.rare_destination",
    name="Rare destination",
    description="First observed outbound destination from a host in the recent window.",
    version="1.0.0",
    severity="low",
    confidence=65,
    mitre_tactics=["command-and-control"],
    mitre_techniques=["T1071"],
    data_sources=["network"],
)


class RareDestinationRule:
    meta = META
    window_seconds = 3600

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "network" or not event.src_ip or not event.dst_ip:
            return []
        peers = [
            item
            for item in context.events_in_window(event, self.window_seconds, src_ip=event.src_ip)
            if item.category == "network" and item.dst_ip
        ]
        dest_counts: dict[str, int] = {}
        for item in peers:
            dest_counts[item.dst_ip] = dest_counts.get(item.dst_ip, 0) + 1
        if dest_counts.get(event.dst_ip, 0) != 1:
            return []
        if max(dest_counts.values(), default=0) < 3 or len(dest_counts) < 2:
            return []
        related = peers
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.src_ip}:{event.dst_ip}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=f"{event.src_ip} reached rare destination {event.dst_ip}.",
            )
        ]
