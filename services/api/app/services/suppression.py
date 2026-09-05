from __future__ import annotations

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.findings import Finding
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ops import DetectionException, Suppression


def is_suppressed(db: Session, tenant_id: str, finding: Finding) -> bool:
    now = utcnow()
    rows = db.execute(
        select(Suppression).where(
            Suppression.tenant_id == tenant_id,
            Suppression.rule_id == finding.rule_id,
        )
    ).scalars().all()
    for row in rows:
        if row.expires_at and row.expires_at < now:
            continue
        value = finding.attributes.get(row.entity_key) or ""
        if value and value == row.entity_value:
            return True
    exceptions = db.execute(
        select(DetectionException).where(
            DetectionException.tenant_id == tenant_id,
            DetectionException.rule_id == finding.rule_id,
        )
    ).scalars().all()
    for row in exceptions:
        value = finding.attributes.get(row.entity_key) or ""
        if value and value == row.entity_value:
            return True
    return False


def create_suppression(
    db: Session,
    *,
    tenant_id: str,
    rule_id: str,
    entity_key: str,
    entity_value: str,
    reason: str,
    actor_id: str,
    expires_at=None,
) -> Suppression:
    row = Suppression(
        id=new_id("sup"),
        tenant_id=tenant_id,
        rule_id=rule_id,
        entity_key=entity_key,
        entity_value=entity_value,
        reason=reason,
        created_by=actor_id,
        expires_at=expires_at,
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def create_exception(
    db: Session,
    *,
    tenant_id: str,
    rule_id: str,
    entity_key: str,
    entity_value: str,
    reason: str,
    actor_id: str,
) -> DetectionException:
    row = DetectionException(
        id=new_id("exc"),
        tenant_id=tenant_id,
        rule_id=rule_id,
        entity_key=entity_key,
        entity_value=entity_value,
        reason=reason,
        created_by=actor_id,
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def list_suppressions(db: Session, tenant_id: str) -> list[Suppression]:
    return list(db.execute(select(Suppression).where(Suppression.tenant_id == tenant_id)).scalars().all())


def list_exceptions(db: Session, tenant_id: str) -> list[DetectionException]:
    return list(db.execute(select(DetectionException).where(DetectionException.tenant_id == tenant_id)).scalars().all())
