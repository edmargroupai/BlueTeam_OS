from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_success

META = RuleMeta(
    rule_id="identity.service_account_misuse",
    name="Service account misuse",
    description="Interactive or unusual authentication by a service account.",
    version="1.0.0",
    severity="high",
    confidence=82,
    mitre_tactics=["persistence", "privilege-escalation"],
    mitre_techniques=["T1078.001"],
    data_sources=["authentication", "identity"],
)

INTERACTIVE = {"interactive", "2", "10", "11", "remoteinteractive", "unlocked"}


def _is_service(event: CanonicalEvent) -> bool:
    name = (event.user.name if event.user else "") or ""
    if name.lower().startswith("svc-") or name.lower().startswith("svc_"):
        return True
    directory = event.attributes.get("directory") or {}
    if isinstance(directory, dict) and str(directory.get("type", "")).lower() == "service":
        return True
    return str(event.attributes.get("account_type", "")).lower() == "service"


def _is_interactive(event: CanonicalEvent) -> bool:
    logon = str(event.attributes.get("logon_type") or event.attributes.get("LogonType") or "").lower()
    if logon in INTERACTIVE:
        return True
    action = (event.action or "").lower()
    return action in {"interactive_login", "rdp", "console"}


class ServiceAccountMisuseRule:
    meta = META

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_success(event) or not event.user or not event.user.name:
            return []
        if not _is_service(event):
            return []
        if not _is_interactive(event):
            return []
        fingerprint = (
            f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:"
            f"{event.timestamp.replace(minute=0, second=0, microsecond=0).isoformat()}"
        )
        if context.already_open(fingerprint):
            return []
        explanation = (
            f"Service account {event.user.name} performed interactive authentication "
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
