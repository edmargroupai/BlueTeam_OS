from __future__ import annotations

from blueteam_common.hashing import chained_hash
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog

GENESIS_HASH = "0" * 64


def _next_sequence(db: Session) -> int:
    current = db.execute(select(func.max(AuditLog.sequence))).scalar_one_or_none()
    return 1 if current is None else current + 1


def _latest_hash(db: Session) -> str:
    row = db.execute(select(AuditLog.record_hash).order_by(AuditLog.sequence.desc()).limit(1)).scalar_one_or_none()
    return row or GENESIS_HASH


def write_audit(
    db: Session,
    *,
    tenant_id: str | None,
    actor_type: str,
    actor_id: str,
    request_id: str,
    action: str,
    target_type: str,
    target_id: str | None = None,
    reason: str | None = None,
    policy_decision: str | None = None,
    approval_status: str | None = None,
    before_state: dict | None = None,
    after_state: dict | None = None,
    result: str = "success",
) -> AuditLog:
    sequence = _next_sequence(db)
    previous = _latest_hash(db)
    payload = {
        "sequence": sequence,
        "tenant_id": tenant_id,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "request_id": request_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
        "policy_decision": policy_decision,
        "approval_status": approval_status,
        "before_state": before_state or {},
        "after_state": after_state or {},
        "result": result,
    }
    record = AuditLog(
        id=new_id("aud"),
        previous_hash=previous,
        record_hash=chained_hash(previous, payload),
        timestamp=utcnow(),
        **payload,
    )
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(db: Session) -> tuple[bool, str]:
    rows = db.execute(select(AuditLog).order_by(AuditLog.sequence.asc())).scalars().all()
    previous = GENESIS_HASH
    for row in rows:
        payload = {
            "sequence": row.sequence,
            "tenant_id": row.tenant_id,
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "request_id": row.request_id,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "reason": row.reason,
            "policy_decision": row.policy_decision,
            "approval_status": row.approval_status,
            "before_state": row.before_state or {},
            "after_state": row.after_state or {},
            "result": row.result,
        }
        expected = chained_hash(previous, payload)
        if row.previous_hash != previous or row.record_hash != expected:
            return False, f"audit chain break at sequence {row.sequence}"
        previous = row.record_hash
    return True, "ok"


def list_audit(db: Session, tenant_id: str | None, *, include_platform: bool = False) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.sequence.desc())
    if include_platform:
        return list(db.execute(stmt).scalars().all())
    return list(db.execute(stmt.where(AuditLog.tenant_id == tenant_id)).scalars().all())
