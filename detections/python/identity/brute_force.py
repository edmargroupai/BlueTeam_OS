from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_failure

META = RuleMeta(
    rule_id="identity.brute_force",
    name="Authentication brute force",
    description=(
        "Repeated authentication failures against one account inside a short window "
        "(T1110.001)."
    ),
    version="1.0.0",
    severity="high",
    confidence=80,
    mitre_tactics=["credential-access"],
    mitre_techniques=["T1110.001"],
    data_sources=["authentication", "identity"],
)


class BruteForceRule:
    meta = META
    min_failures = 8
    window_seconds = 600

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
        users_in_window = {item.user.name for item in related if item.user and item.user.name}
        # Spray is many users / one IP. Brute force is one user / many attempts.
        if len(users_in_window) > 2:
            return []
        bucket = event.timestamp.replace(minute=event.timestamp.minute // 10 * 10, second=0, microsecond=0)
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:{bucket.isoformat()}"
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"Account {event.user.name} recorded {len(related)} failed authentications "
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
