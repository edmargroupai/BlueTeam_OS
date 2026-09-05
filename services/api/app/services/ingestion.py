from __future__ import annotations

from blueteam_common.hashing import canonical_json, sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.telemetry import DeadLetterEvent, SecurityEvent
from app.services.detection import evaluate_and_store
from blueteam_ingest.router import normalize_payload


def ingest_payloads(
    db: Session,
    tenant_id: str,
    payloads: list[dict],
    *,
    actor_id: str,
) -> dict:
    accepted: list[str] = []
    duplicates: list[str] = []
    rejected: list[dict] = []
    findings_created = 0

    for payload in payloads:
        try:
            event = normalize_payload(payload, tenant_id)
            from blueteam_enrich.engine import enrich_event

            event, _enrichment = enrich_event(event)
        except (ValidationError, ValueError) as exc:
            _dead_letter(db, tenant_id, payload, str(exc))
            rejected.append({"reason": str(exc)})
            continue

        existing = None
        if event.idempotency_key:
            existing = db.execute(
                select(SecurityEvent).where(
                    SecurityEvent.tenant_id == tenant_id,
                    SecurityEvent.idempotency_key == event.idempotency_key,
                )
            ).scalar_one_or_none()
        if existing is None:
            existing = db.get(SecurityEvent, event.id)
            if existing and existing.tenant_id != tenant_id:
                _dead_letter(db, tenant_id, payload, "event id collision across tenants")
                rejected.append({"reason": "event id collision", "id": event.id})
                continue
        if existing is not None:
            duplicates.append(existing.id)
            continue

        raw_hash = event.raw_hash or sha256_hex(canonical_json(event.raw_event or payload))
        from app.services.dataplane import best_effort_project

        best_effort_project(event, payload)
        stored = SecurityEvent(
            id=event.id,
            tenant_id=tenant_id,
            timestamp=event.timestamp,
            ingested_at=event.ingested_at,
            source=event.source,
            source_type=event.source_type,
            event_type=event.event_type,
            category=event.category,
            action=event.action,
            outcome=event.outcome,
            src_ip=event.src_ip,
            user_name=event.user.name if event.user else None,
            idempotency_key=event.idempotency_key,
            raw_hash=raw_hash,
            payload=event.model_dump(mode="json"),
        )
        db.add(stored)
        db.flush()
        accepted.append(event.id)
        findings_created += evaluate_and_store(db, tenant_id, event, actor_id=actor_id)

    if accepted:
        from app.services.graph import project_graph
        from app.services.incidents import persist_storylines_and_incidents

        project_graph(db, tenant_id, load_window(db, tenant_id))
        persist_storylines_and_incidents(db, tenant_id)

    return {
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "findings_created": findings_created,
    }


def _dead_letter(db: Session, tenant_id: str | None, payload: dict, reason: str) -> None:
    db.add(
        DeadLetterEvent(
            id=new_id("dlq"),
            tenant_id=tenant_id,
            reason=reason[:200],
            raw_payload=payload,
            created_at=utcnow(),
        )
    )


def load_window(db: Session, tenant_id: str) -> list[CanonicalEvent]:
    rows = db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.timestamp.asc())
    ).scalars().all()
    return [CanonicalEvent.model_validate(row.payload) for row in rows]


def list_events(db: Session, tenant_id: str) -> list[SecurityEvent]:
    return list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.tenant_id == tenant_id)
            .order_by(SecurityEvent.timestamp.desc())
        ).scalars().all()
    )


def list_dead_letters(db: Session, tenant_id: str) -> list[DeadLetterEvent]:
    return list(
        db.execute(
            select(DeadLetterEvent)
            .where(DeadLetterEvent.tenant_id == tenant_id)
            .order_by(DeadLetterEvent.created_at.desc())
        ).scalars().all()
    )
