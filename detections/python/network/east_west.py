from __future__ import annotations

from ipaddress import ip_address

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="network.unusual_east_west",
    name="Unusual east-west traffic",
    description="Internal-to-internal SMB/RDP/WinRM after or alongside other suspicious activity.",
    version="1.0.0",
    severity="high",
    confidence=75,
    mitre_tactics=["lateral-movement"],
    mitre_techniques=["T1021.002", "T1021.001"],
    data_sources=["network"],
)

ADMIN_PORTS = {445, 3389, 5985, 5986}


class UnusualEastWestRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "network" or not event.src_ip or not event.dst_ip or not event.dst_port:
            return []
        if event.dst_port not in ADMIN_PORTS:
            return []
        try:
            if not ip_address(event.src_ip).is_private or not ip_address(event.dst_ip).is_private:
                return []
        except ValueError:
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.src_ip}:{event.dst_ip}:{event.dst_port}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=(
                    f"East-west {event.protocol or 'tcp'}/{event.dst_port} "
                    f"from {event.src_ip} to {event.dst_ip}."
                ),
            )
        ]
