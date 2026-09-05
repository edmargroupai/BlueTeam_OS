from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.vertical_scan",
    name="Vertical port scan",
    description="One source probes many ports on a single destination.",
    version="1.0.0",
    severity="medium",
    confidence=80,
    mitre_tactics=["discovery"],
    mitre_techniques=["T1046"],
    data_sources=["network", "zeek", "suricata"],
)


class VerticalScanRule:
    meta = META
    min_ports = 8
    window_seconds = 120

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category not in {"network", "alert"} or not event.src_ip or not event.dst_ip:
            return []
        related = [
            item
            for item in context.events_in_window(event, self.window_seconds, src_ip=event.src_ip)
            if item.dst_ip == event.dst_ip and item.dst_port
        ]
        ports = {item.dst_port for item in related}
        if len(ports) < self.min_ports:
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
                explanation=f"{event.src_ip} probed {len(ports)} ports on {event.dst_ip}.",
            )
        ]
