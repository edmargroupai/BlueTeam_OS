from __future__ import annotations

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_detection.rule import RuleMeta
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding, FindingEvidence


def is_auth_failure(event: CanonicalEvent) -> bool:
    return (
        event.category == "authentication"
        and event.event_type in {"login", "authentication", "logon"}
        and event.outcome == "failure"
    )


def is_auth_success(event: CanonicalEvent) -> bool:
    return (
        event.category == "authentication"
        and event.event_type in {"login", "authentication", "logon"}
        and event.outcome == "success"
    )


def finding_from_events(
    meta: RuleMeta,
    trigger: CanonicalEvent,
    related: list[CanonicalEvent],
    *,
    fingerprint: str,
    explanation: str,
    title: str | None = None,
) -> Finding:
    event_ids = [event.id for event in related]
    if trigger.id not in event_ids:
        event_ids.insert(0, trigger.id)
    evidence = [
        FindingEvidence(
            evidence_id=f"evi_pending_{event.id}",
            event_id=event.id,
            role="trigger" if event.id == trigger.id else "supporting",
        )
        for event in related
    ]
    return Finding(
        id=new_id("fnd"),
        tenant_id=trigger.tenant_id,
        rule_id=meta.rule_id,
        rule_version=meta.version,
        title=title or meta.name,
        description=meta.description,
        severity=meta.severity,  # type: ignore[arg-type]
        confidence=meta.confidence,
        fingerprint=fingerprint,
        mitre_tactics=list(meta.mitre_tactics),
        mitre_techniques=list(meta.mitre_techniques),
        event_ids=event_ids,
        evidence=evidence,
        explanation=explanation,
        created_at=utcnow(),
        attributes={"src_ip": trigger.src_ip or "", "user": (trigger.user.name if trigger.user else "")},
    )
