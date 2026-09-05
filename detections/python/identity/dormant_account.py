from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_success

META = RuleMeta(
    rule_id="identity.dormant_account",
    name="Dormant account activity",
    description="Successful login for an account marked dormant or long-idle in directory enrichment.",
    version="1.0.0",
    severity="medium",
    confidence=72,
    mitre_tactics=["persistence", "initial-access"],
    mitre_techniques=["T1078"],
    data_sources=["authentication", "identity"],
)


def _is_dormant(event: CanonicalEvent) -> bool:
    directory = event.attributes.get("directory") or {}
    if isinstance(directory, dict):
        if str(directory.get("dormant", "")).lower() in {"true", "1", "yes"}:
            return True
        try:
            if int(directory.get("last_login_days") or 0) >= 90:
                return True
        except (TypeError, ValueError):
            pass
    return str(event.attributes.get("dormant", "")).lower() in {"true", "1", "yes"}


class DormantAccountRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_success(event) or not event.user or not event.user.name:
            return []
        if not _is_dormant(event):
            return []
        fingerprint = (
            f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:"
            f"{event.timestamp.date().isoformat()}"
        )
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"Dormant/long-idle account {event.user.name} authenticated successfully "
            f"from {event.src_ip}."
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
