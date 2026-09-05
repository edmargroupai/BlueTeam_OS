from __future__ import annotations

from blueteam_common.errors import BlueTeamError
from blueteam_common.hashing import canonical_json, sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.evidence import ConfidenceLevel, IncidentClaim
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.telemetry import Evidence, SecurityEvent


def register_event_evidence(
    db: Session,
    *,
    tenant_id: str,
    event_id: str,
    collector_identity: str,
) -> str:
    existing = db.execute(
        select(Evidence).where(Evidence.tenant_id == tenant_id, Evidence.source == f"event:{event_id}")
    ).scalar_one_or_none()
    if existing:
        return existing.id
    event = db.execute(
        select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.id == event_id)
    ).scalar_one_or_none()
    if event is None:
        raise BlueTeamError("EVIDENCE_SOURCE_MISSING", f"event {event_id} not found in tenant", 404)
    evidence = Evidence(
        id=new_id("evi"),
        tenant_id=tenant_id,
        source=f"event:{event_id}",
        acquisition_method="ingestion",
        original_timestamp=event.timestamp,
        ingested_at=utcnow(),
        collector_identity=collector_identity,
        integrity_hash=event.raw_hash,
        object_uri=None,
        parser_version="canonical-1.0.0",
        transformation_history=["normalize.generic"],
        confidence_level=int(ConfidenceLevel.PRIMARY_TELEMETRY),
        payload={"event_id": event_id, "raw_hash": event.raw_hash},
        sealed=True,
    )
    db.add(evidence)
    db.flush()
    return evidence.id


def list_evidence(db: Session, tenant_id: str) -> list[Evidence]:
    return list(
        db.execute(select(Evidence).where(Evidence.tenant_id == tenant_id).order_by(Evidence.ingested_at.desc()))
        .scalars()
        .all()
    )


def verify_evidence(db: Session, tenant_id: str, evidence_id: str) -> dict:
    row = db.execute(
        select(Evidence).where(Evidence.tenant_id == tenant_id, Evidence.id == evidence_id)
    ).scalar_one_or_none()
    if row is None:
        raise BlueTeamError("NOT_FOUND", "Evidence not found", 404)
    if row.source.startswith("event:"):
        event_id = row.source.split(":", 1)[1]
        event = db.execute(
            select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.id == event_id)
        ).scalar_one_or_none()
        if event is None or event.raw_hash != row.integrity_hash:
            return {"id": evidence_id, "intact": False, "reason": "hash mismatch or missing source"}
    return {"id": evidence_id, "intact": True, "integrity_hash": row.integrity_hash}


def validate_claim(db: Session, tenant_id: str, claim: IncidentClaim) -> None:
    known = set(
        db.execute(select(Evidence.id).where(Evidence.tenant_id == tenant_id)).scalars().all()
    )
    try:
        claim.validate_evidence_refs(known)
    except ValueError as exc:
        raise BlueTeamError("INVALID_EVIDENCE_REF", str(exc), 422) from exc


def evidence_manifest_hash(db: Session, tenant_id: str) -> str:
    rows = list_evidence(db, tenant_id)
    return sha256_hex(
        canonical_json([{"id": row.id, "integrity_hash": row.integrity_hash} for row in rows])
    )
