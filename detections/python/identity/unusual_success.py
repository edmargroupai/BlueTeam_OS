from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_failure, is_auth_success

META = RuleMeta(
    rule_id="identity.unusual_success",
    name="Unusual successful login",
    description="Successful authentication after recent failures for the same account.",
    version="1.0.0",
    severity="high",
    confidence=78,
    mitre_tactics=["credential-access", "initial-access"],
    mitre_techniques=["T1078", "T1110"],
    data_sources=["authentication", "identity"],
)


class UnusualSuccessRule:
    meta = META
    prior_failures = 3
    window_seconds = 1800

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_success(event) or not event.user or not event.user.name:
            return []
        failures = [
            item
            for item in context.events_in_window(
                event,
                self.window_seconds,
                category="authentication",
                outcome="failure",
                user_name=event.user.name,
            )
            if is_auth_failure(item)
        ]
        if len(failures) < self.prior_failures:
            return []
        fingerprint = (
            f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:"
            f"{event.timestamp.replace(second=0, microsecond=0).isoformat()}"
        )
        if context.already_open(fingerprint):
            return []
        related = [*failures, event]
        explanation = (
            f"Account {event.user.name} succeeded after {len(failures)} failures "
            f"in {self.window_seconds}s from {event.src_ip}."
        )
        return [
            finding_from_events(
                self.meta,
                event,
                related,
                fingerprint=fingerprint,
                explanation=explanation,
            )
        ]
