from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_failure

META = RuleMeta(
    rule_id="identity.password_spray",
    name="Password spraying",
    description=(
        "Many distinct usernames failing authentication from one source IP "
        "inside a short window. Classic password-spray pattern (T1110.003)."
    ),
    version="1.0.0",
    severity="high",
    confidence=85,
    mitre_tactics=["credential-access"],
    mitre_techniques=["T1110.003"],
    data_sources=["authentication", "identity"],
)


class PasswordSprayRule:
    meta = META
    distinct_users = 5
    window_seconds = 600

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_failure(event) or not event.src_ip:
            return []
        related = context.events_in_window(
            event,
            self.window_seconds,
            category="authentication",
            outcome="failure",
            src_ip=event.src_ip,
        )
        users = {item.user.name for item in related if item.user and item.user.name}
        if len(users) < self.distinct_users:
            return []
        bucket = event.timestamp.replace(second=0, microsecond=0).isoformat()
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.src_ip}:{bucket}"
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"{len(users)} distinct accounts failed authentication from {event.src_ip} "
            f"within {self.window_seconds}s. Accounts: {', '.join(sorted(users))}."
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
