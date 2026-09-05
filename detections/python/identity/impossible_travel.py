from __future__ import annotations

from blueteam_detection.context import DetectionContext
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding

from detections.python.identity._common import finding_from_events, is_auth_success

META = RuleMeta(
    rule_id="identity.impossible_travel",
    name="Impossible travel abstraction",
    description=(
        "Two successful authentications for one account from different GeoIP countries "
        "inside a short window. Uses fixture/enrichment country codes only — not live travel math."
    ),
    version="1.0.0",
    severity="high",
    confidence=70,
    mitre_tactics=["initial-access"],
    mitre_techniques=["T1078"],
    data_sources=["authentication", "identity"],
)


def _country(event: CanonicalEvent) -> str | None:
    geo = event.attributes.get("geoip") or {}
    if isinstance(geo, dict):
        country = geo.get("country")
        if country and country not in {"unknown", "private"}:
            return str(country)
    return None


class ImpossibleTravelRule:
    meta = META
    window_seconds = 7200

    def evaluate(self, event: CanonicalEvent, context: DetectionContext) -> list[Finding]:
        if not is_auth_success(event) or not event.user or not event.user.name:
            return []
        current = _country(event)
        if not current:
            return []
        prior = [
            item
            for item in context.events_in_window(
                event,
                self.window_seconds,
                category="authentication",
                outcome="success",
                user_name=event.user.name,
            )
            if item.id != event.id and is_auth_success(item)
        ]
        for item in prior:
            other = _country(item)
            if other and other != current:
                fingerprint = (
                    f"{self.meta.rule_id}:{event.tenant_id}:{event.user.name}:"
                    f"{other}->{current}:{event.timestamp.date().isoformat()}"
                )
                if context.already_open(fingerprint):
                    return []
                explanation = (
                    f"Account {event.user.name} authenticated from {other} then {current} "
                    f"within {self.window_seconds}s (GeoIP fixture abstraction)."
                )
                return [
                    finding_from_events(
                        self.meta,
                        event,
                        [item, event],
                        fingerprint=fingerprint,
                        explanation=explanation,
                    )
                ]
        return []
