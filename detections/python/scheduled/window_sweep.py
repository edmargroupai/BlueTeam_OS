"""Scheduled detection: sweep the stored window, not the inbound event stream."""

from __future__ import annotations

from datetime import timedelta

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding
from detections.python.shared import finding_from_events


class ScheduledAuthFailureSweep:
    meta = RuleMeta(
        rule_id="scheduled.auth_failure_sweep",
        name="Scheduled authentication failure sweep",
        description="Window sweep for repeated authentication failures. Runs only on the scheduled runner.",
        version="1.0.0",
        severity="medium",
        confidence=70,
        mitre_tactics=["credential-access"],
        mitre_techniques=["T1110"],
        data_sources=["authentication"],
        status="tested",
        execution="scheduled",
    )

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not context.scheduled:
            return []
        if event.category != "authentication" or event.outcome != "failure":
            return []
        related = context.window.query(
            tenant_id=event.tenant_id,
            since=event.timestamp - timedelta(hours=24),
            until=event.timestamp,
            category="authentication",
            outcome="failure",
            src_ip=event.src_ip,
        )
        if len(related) < 8:
            return []
        users = {item.user.name for item in related if item.user and item.user.name}
        fingerprint = f"scheduled.auth_failure_sweep|{event.tenant_id}|{event.src_ip}"
        if context.already_open(fingerprint):
            return []
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=f"Scheduled sweep observed {len(related)} authentication failures from {event.src_ip} across {len(users)} users.",
            )
        ]
