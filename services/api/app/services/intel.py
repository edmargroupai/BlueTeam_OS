from __future__ import annotations

from datetime import UTC, datetime, timedelta

from blueteam_common.errors import BlueTeamError
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intel import IndicatorOfCompromise

IOC_TYPES = {"ip", "domain", "hash", "url", "email"}


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def serialize_ioc(row: IndicatorOfCompromise) -> dict:
    now = utcnow()
    expired = as_utc(row.expires_at) <= now
    return {
        "id": row.id,
        "indicator_type": row.indicator_type,
        "value": row.value,
        "source": row.source,
        "confidence": row.confidence,
        "ttl_hours": row.ttl_hours,
        "expires_at": as_utc(row.expires_at).isoformat(),
        "expired": expired,
        "active": row.active and not expired,
        "malware": row.malware,
        "actor": row.actor,
        "campaign": row.campaign,
        "mitre_techniques": row.mitre_techniques or [],
        "tags": row.tags or [],
        "sightings": row.sightings,
        "last_seen_at": as_utc(row.last_seen_at).isoformat() if row.last_seen_at else None,
        "provenance": row.provenance or {},
        "created_at": as_utc(row.created_at).isoformat(),
        "created_by": row.created_by,
        "updated_at": as_utc(row.updated_at).isoformat(),
    }


def list_iocs(db: Session, tenant_id: str, *, include_expired: bool = False) -> list[IndicatorOfCompromise]:
    rows = list(
        db.execute(
            select(IndicatorOfCompromise)
            .where(IndicatorOfCompromise.tenant_id == tenant_id)
            .order_by(IndicatorOfCompromise.updated_at.desc())
        ).scalars().all()
    )
    if include_expired:
        return rows
    now = utcnow()
    return [row for row in rows if row.active and as_utc(row.expires_at) > now]


def get_ioc(db: Session, tenant_id: str, ioc_id: str) -> IndicatorOfCompromise:
    row = db.execute(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.tenant_id == tenant_id,
            IndicatorOfCompromise.id == ioc_id,
        )
    ).scalar_one_or_none()
    if row is None:
        raise BlueTeamError("NOT_FOUND", "IOC not found", 404)
    return row


def upsert_ioc(
    db: Session,
    tenant_id: str,
    *,
    indicator_type: str,
    value: str,
    source: str,
    confidence: float,
    ttl_hours: int,
    actor_id: str,
    malware: str | None = None,
    actor: str | None = None,
    campaign: str | None = None,
    mitre_techniques: list[str] | None = None,
    tags: list[str] | None = None,
    provenance: dict | None = None,
) -> IndicatorOfCompromise:
    indicator_type = indicator_type.lower().strip()
    value = value.strip().lower() if indicator_type in {"domain", "email"} else value.strip()
    if indicator_type not in IOC_TYPES:
        raise BlueTeamError("INVALID_IOC_TYPE", f"Unsupported type {indicator_type}", 422)
    if not value or not source.strip():
        raise BlueTeamError("INVALID_IOC", "value and source required", 422)
    if confidence < 0 or confidence > 1:
        raise BlueTeamError("INVALID_CONFIDENCE", "confidence must be 0..1", 422)
    ttl_hours = max(1, min(ttl_hours, 24 * 365))
    now = utcnow()
    existing = db.execute(
        select(IndicatorOfCompromise).where(
            IndicatorOfCompromise.tenant_id == tenant_id,
            IndicatorOfCompromise.indicator_type == indicator_type,
            IndicatorOfCompromise.value == value,
        )
    ).scalar_one_or_none()
    if existing:
        existing.source = source.strip()
        existing.confidence = confidence
        existing.ttl_hours = ttl_hours
        existing.expires_at = now + timedelta(hours=ttl_hours)
        existing.malware = malware
        existing.actor = actor
        existing.campaign = campaign
        existing.mitre_techniques = mitre_techniques or []
        existing.tags = tags or []
        if provenance:
            existing.provenance = {**(existing.provenance or {}), **provenance}
        existing.active = True
        existing.updated_at = now
        db.flush()
        return existing
    row = IndicatorOfCompromise(
        id=new_id("ioc"),
        tenant_id=tenant_id,
        indicator_type=indicator_type,
        value=value,
        source=source.strip(),
        confidence=confidence,
        ttl_hours=ttl_hours,
        expires_at=now + timedelta(hours=ttl_hours),
        malware=malware,
        actor=actor,
        campaign=campaign,
        mitre_techniques=mitre_techniques or [],
        tags=tags or [],
        sightings=0,
        provenance=provenance or {"first_seen_source": source.strip()},
        active=True,
        created_at=now,
        created_by=actor_id,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def deactivate_ioc(db: Session, row: IndicatorOfCompromise, *, actor_id: str) -> IndicatorOfCompromise:
    row.active = False
    row.updated_at = utcnow()
    provenance = dict(row.provenance or {})
    provenance["deactivated_by"] = actor_id
    provenance["deactivated_at"] = utcnow().isoformat()
    row.provenance = provenance
    db.flush()
    return row


def active_intel_map(db: Session, tenant_id: str) -> dict[str, dict[str, str]]:
    """Shape expected by blueteam_enrich.engine.enrich_event(intel=...)."""
    mapping: dict[str, dict[str, str]] = {}
    for row in list_iocs(db, tenant_id, include_expired=False):
        mapping[row.value] = {
            "rule_id": f"intel.{row.indicator_type}",
            "type": row.indicator_type,
            "confidence": f"{row.confidence:.2f}",
            "source": row.source,
            "ioc_id": row.id,
            "malware": row.malware or "",
            "actor": row.actor or "",
            "campaign": row.campaign or "",
        }
    return mapping


def record_sightings(db: Session, tenant_id: str, event: CanonicalEvent) -> list[str]:
    """Increment sightings for matching active IOCs. Returns matched IOC ids."""
    candidates = {
        event.src_ip,
        event.dst_ip,
        event.domain,
        event.hash,
        event.url,
        event.user.email if event.user else None,
    }
    matched_ids: list[str] = []
    now = utcnow()
    for candidate in candidates:
        if not candidate:
            continue
        value = candidate.strip()
        rows = db.execute(
            select(IndicatorOfCompromise).where(
                IndicatorOfCompromise.tenant_id == tenant_id,
                IndicatorOfCompromise.value.in_({value, value.lower()}),
                IndicatorOfCompromise.active.is_(True),
            )
        ).scalars().all()
        for row in rows:
            if as_utc(row.expires_at) <= now:
                continue
            row.sightings = int(row.sightings or 0) + 1
            row.last_seen_at = now
            row.updated_at = now
            matched_ids.append(row.id)
    if matched_ids:
        db.flush()
    return matched_ids


def expire_stale(db: Session, tenant_id: str) -> int:
    now = utcnow()
    rows = list(
        db.execute(
            select(IndicatorOfCompromise).where(
                IndicatorOfCompromise.tenant_id == tenant_id,
                IndicatorOfCompromise.active.is_(True),
            )
        ).scalars().all()
    )
    expired_rows = [row for row in rows if as_utc(row.expires_at) <= now]
    for row in expired_rows:
        row.active = False
        provenance = dict(row.provenance or {})
        provenance["expired_at"] = now.isoformat()
        row.provenance = provenance
        row.updated_at = now
    if expired_rows:
        db.flush()
    return len(expired_rows)
