from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.horizontal_scan",
    name="Horizontal network scan",
    description="One source contacts many distinct destinations on a shared port.",
    version="1.0.0",
    severity="medium",
    confidence=80,
    mitre_tactics=["discovery"],
    mitre_techniques=["T1046"],
    data_sources=["network", "zeek", "suricata"],
)


class HorizontalScanRule:
    meta = META
    min_destinations = 8
    window_seconds = 120

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category not in {"network", "alert"} or not event.src_ip or not event.dst_ip:
            return []
        related = [
            item
            for item in context.events_in_window(event, self.window_seconds, src_ip=event.src_ip)
            if item.category in {"network", "alert"} and item.dst_ip and item.dst_port == event.dst_port
        ]
        destinations = {item.dst_ip for item in related}
        if len(destinations) < self.min_destinations:
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.src_ip}:{event.dst_port}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=(
                    f"{event.src_ip} contacted {len(destinations)} distinct hosts on port "
                    f"{event.dst_port} within {self.window_seconds}s."
                ),
            )
        ]
