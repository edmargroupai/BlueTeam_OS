from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_failure

META = RuleMeta(
    rule_id="identity.repeated_failures",
    name="Repeated failed login",
    description="Repeated authentication failures for one account (lower intensity than brute force).",
    version="1.0.0",
    severity="medium",
    confidence=75,
    mitre_tactics=["credential-access"],
    mitre_techniques=["T1110"],
    data_sources=["authentication", "identity"],
)


class RepeatedFailuresRule:
    meta = META
    min_failures = 5
    window_seconds = 900

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_failure(event) or not event.user or not event.user.name:
            return []
        related = context.events_in_window(
            event,
            self.window_seconds,
            category="authentication",
            outcome="failure",
            user_name=event.user.name,
        )
        if len(related) < self.min_failures:
            return []
        bucket = event.timestamp.replace(minute=0, second=0, microsecond=0)
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:{bucket.isoformat()}"
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"Account {event.user.name} had {len(related)} failed logins "
            f"within {self.window_seconds}s."
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
