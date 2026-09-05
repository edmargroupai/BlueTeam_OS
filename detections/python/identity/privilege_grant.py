from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events

META = RuleMeta(
    rule_id="identity.privilege_grant",
    name="Privileged group or role grant",
    description="A principal was added to an administrative group or granted a privileged role.",
    version="1.0.0",
    severity="high",
    confidence=90,
    mitre_tactics=["privilege-escalation", "persistence"],
    mitre_techniques=["T1098", "T1078"],
    data_sources=["identity", "directory"],
)

PRIVILEGED_MARKERS = (
    "domain admins",
    "enterprise admins",
    "administrators",
    "global admin",
    "privileged role administrator",
    "organization management",
    "sudo",
    "root",
)


class PrivilegeGrantRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if event.category not in {"identity", "directory"}:
            return []
        if event.action not in {"add_to_group", "grant_role", "add_member", "elevate"}:
            return []
        target = str(event.attributes.get("group") or event.attributes.get("role") or "").lower()
        if not any(marker in target for marker in PRIVILEGED_MARKERS):
            return []
        fingerprint = f"{self.meta.rule_id}:{event.tenant_id}:{event.id}"
        if context.already_open(fingerprint):
            return []
        actor = event.user.name if event.user and event.user.name else "unknown"
        explanation = (
            f"{actor} granted privileged membership '{target}' "
            f"(action={event.action}, outcome={event.outcome or 'unknown'})."
        )
        return [
            finding_from_events(
                self.meta,
                event,
                [event],
                fingerprint=fingerprint,
                explanation=explanation,
            )
        ]
