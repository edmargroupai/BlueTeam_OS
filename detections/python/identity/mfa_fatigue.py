from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events

META = RuleMeta(
    rule_id="identity.mfa_fatigue",
    name="MFA fatigue",
    description="Burst of MFA challenges or denials against one account (T1621 abstraction).",
    version="1.0.0",
    severity="high",
    confidence=80,
    mitre_tactics=["credential-access"],
    mitre_techniques=["T1621"],
    data_sources=["authentication", "identity"],
)

MFA_ACTIONS = {"mfa_challenge", "mfa_deny", "mfa_push", "mfa_reject"}


def _is_mfa(event: CanonicalEvent) -> bool:
    if event.category != "authentication":
        return False
    action = (event.action or "").lower()
    event_type = (event.event_type or "").lower()
    return action in MFA_ACTIONS or event_type in MFA_ACTIONS or bool(event.attributes.get("mfa"))


class MfaFatigueRule:
    meta = META
    min_challenges = 5
    window_seconds = 600

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not _is_mfa(event) or not event.user or not event.user.name:
            return []
        related = [
            item
            for item in context.events_in_window(
                event,
                self.window_seconds,
                category="authentication",
                user_name=event.user.name,
            )
            if _is_mfa(item)
        ]
        if len(related) < self.min_challenges:
            return []
        bucket = event.timestamp.replace(minute=event.timestamp.minute // 10 * 10, second=0, microsecond=0)
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:{bucket.isoformat()}"
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"Account {event.user.name} received {len(related)} MFA challenge/deny events "
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
