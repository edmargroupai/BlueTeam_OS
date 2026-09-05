from __future__ import annotations

from blueteam_detection.context import DetectionContext, EventWindow
from blueteam_schemas.events import CanonicalEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.telemetry import Alert, FindingRecord
from app.services.evidence import register_event_evidence
from detections.python.catalog import build_default_registry

_REGISTRY = None


def get_registry():
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = build_default_registry()
    return _REGISTRY


def evaluate_and_store(db: Session, tenant_id: str, event: CanonicalEvent, *, actor_id: str) -> int:
    from app.services.ingestion import load_window

    events = load_window(db, tenant_id)
    open_fps = set(
        db.execute(
            select(FindingRecord.fingerprint).where(FindingRecord.tenant_id == tenant_id)
        ).scalars().all()
    )
    context = DetectionContext(EventWindow(events), open_fingerprints=open_fps)
    return evaluate_and_store_findings(db, tenant_id, event, context, actor_id=actor_id)


def list_findings(db: Session, tenant_id: str) -> list[FindingRecord]:
    return list(
        db.execute(
            select(FindingRecord)
            .where(FindingRecord.tenant_id == tenant_id)
            .order_by(FindingRecord.created_at.desc())
        ).scalars().all()
    )


def list_alerts(db: Session, tenant_id: str) -> list[Alert]:
    return list(
        db.execute(select(Alert).where(Alert.tenant_id == tenant_id).order_by(Alert.created_at.desc())).scalars().all()
    )


def run_scheduled(db: Session, tenant_id: str, *, actor_id: str) -> int:
    from app.services.ingestion import load_window

    events = load_window(db, tenant_id)
    if not events:
        return 0
    open_fps = set(
        db.execute(select(FindingRecord.fingerprint).where(FindingRecord.tenant_id == tenant_id)).scalars().all()
    )
    context = DetectionContext(EventWindow(events), open_fingerprints=open_fps, scheduled=True)
    created = 0
    for event in events:
        created += evaluate_and_store_findings(db, tenant_id, event, context, actor_id=actor_id)
    return created


def evaluate_and_store_findings(
    db: Session, tenant_id: str, event: CanonicalEvent, context: DetectionContext, *, actor_id: str
) -> int:
    from app.services.suppression import is_suppressed

    findings = get_registry().evaluate(event, context)
    created = 0
    for finding in findings:
        if is_suppressed(db, tenant_id, finding):
            continue
        if db.execute(
            select(FindingRecord).where(
                FindingRecord.tenant_id == tenant_id,
                FindingRecord.fingerprint == finding.fingerprint,
            )
        ).scalar_one_or_none():
            continue
        evidence_ids: list[str] = []
        for event_id in finding.event_ids:
            evidence_ids.append(
                register_event_evidence(
                    db,
                    tenant_id=tenant_id,
                    event_id=event_id,
                    collector_identity=actor_id,
                )
            )
        record = FindingRecord(
            id=finding.id,
            tenant_id=tenant_id,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            fingerprint=finding.fingerprint,
            explanation=finding.explanation,
            mitre_techniques=finding.mitre_techniques,
            event_ids=finding.event_ids,
            evidence_ids=evidence_ids,
            payload=finding.model_dump(mode="json"),
            created_at=finding.created_at,
        )
        db.add(record)
        db.add(
            Alert(
                id=finding.id.replace("fnd_", "alt_", 1) if finding.id.startswith("fnd_") else finding.id,
                tenant_id=tenant_id,
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                status="open",
                created_at=finding.created_at,
            )
        )
        created += 1
        context.open_fingerprints.add(finding.fingerprint)
    db.flush()
    return created


def catalogue() -> list[dict]:
    return [
        {
            "rule_id": rule.meta.rule_id,
            "name": rule.meta.name,
            "version": rule.meta.version,
            "severity": rule.meta.severity,
            "mitre_techniques": rule.meta.mitre_techniques,
            "status": rule.meta.status,
            "execution": getattr(rule.meta, "execution", "realtime"),
            "description": rule.meta.description,
        }
        for rule in get_registry().all_rules()
    ]
