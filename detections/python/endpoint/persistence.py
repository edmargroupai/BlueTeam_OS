from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.shared import finding_from_events


def _persist(event: CanonicalEvent, meta: RuleMeta, context: DetectionContext, explanation: str) -> list[Finding]:
    fingerprint = f"{meta.rule_id}:{event.tenant_id}:{event.id}"
    if context.already_open(fingerprint):
        return []
    return [finding_from_events(meta, event, [event], fingerprint=fingerprint, explanation=explanation)]


class ServicePersistenceRule:
    meta = RuleMeta(
        rule_id="endpoint.service_persistence",
        name="Service persistence",
        description="New or modified service creation from endpoint telemetry.",
        version="1.0.0",
        severity="medium",
        confidence=78,
        mitre_tactics=["persistence"],
        mitre_techniques=["T1543.003"],
        data_sources=["endpoint"],
    )

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.event_type != "service" and event.category != "persistence":
            return []
        if event.action not in {"service", "service_start", "service_create"} and event.event_type != "service":
            return []
        if event.event_type != "service":
            return []
        return _persist(event, self.meta, context, "Service persistence event observed.")


class ScheduledTaskPersistenceRule:
    meta = RuleMeta(
        rule_id="endpoint.scheduled_task_persistence",
        name="Scheduled-task persistence",
        description="Scheduled task creation or modification.",
        version="1.0.0",
        severity="medium",
        confidence=78,
        mitre_tactics=["persistence"],
        mitre_techniques=["T1053.005"],
        data_sources=["endpoint"],
    )

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.event_type != "scheduled_task":
            return []
        return _persist(event, self.meta, context, "Scheduled-task persistence event observed.")


class RegistryPersistenceRule:
    meta = RuleMeta(
        rule_id="endpoint.registry_persistence",
        name="Registry persistence",
        description="Run-key or similar registry persistence write.",
        version="1.0.0",
        severity="medium",
        confidence=80,
        mitre_tactics=["persistence"],
        mitre_techniques=["T1547.001"],
        data_sources=["endpoint"],
    )

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category != "registry":
            return []
        path = ((event.file.path if event.file else None) or str(event.raw_event.get("TargetObject") or "")).lower()
        if "\\currentversion\\run" not in path and "runonce" not in path:
            return []
        return _persist(event, self.meta, context, f"Registry persistence write: {path}")
