from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events

META = RuleMeta(
    rule_id="endpoint.process_network_chain",
    name="Process to network chain",
    description="A newly created process on a host is followed by an outbound connection.",
    version="1.0.0",
    severity="high",
    confidence=80,
    mitre_tactics=["command-and-control"],
    mitre_techniques=["T1071"],
    data_sources=["endpoint", "network"],
)

INTERESTING = {"powershell.exe", "pwsh.exe", "cmd.exe", "payload.exe", "wscript.exe"}


class ProcessNetworkChainRule:
    meta = META
    window_seconds = 180

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "network" or not event.dst_ip or not event.host:
            return []
        host = event.host.name or event.host.id
        if not host:
            return []
        processes = [
            item
            for item in context.events_in_window(event, self.window_seconds)
            if item.category == "process"
            and item.process
            and (item.process.name or "").lower() in INTERESTING
            and item.host
            and (item.host.name or item.host.id) == host
        ]
        if not processes:
            return []
        related = processes + [event]
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{host}:{event.dst_ip}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=f"Host {host} ran {processes[-1].process.name} then connected to {event.dst_ip}.",
            )
        ]
