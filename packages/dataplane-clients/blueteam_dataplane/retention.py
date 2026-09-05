"""Retention policies. Enforcement is explicit and tenant-scoped."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from blueteam_common.time import utcnow
from sqlalchemy import delete
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class RetentionPolicy:
    events_days: int = 90
    dead_letter_days: int = 30
    findings_days: int = 365

    def as_dict(self) -> dict[str, int]:
        return {
            "events_days": self.events_days,
            "dead_letter_days": self.dead_letter_days,
            "findings_days": self.findings_days,
        }


def apply_retention(db: Session, tenant_id: str, policy: RetentionPolicy) -> dict[str, int]:
    from app.models.telemetry import DeadLetterEvent, FindingRecord, SecurityEvent

    now = utcnow()
    events = db.execute(
        delete(SecurityEvent).where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.ingested_at < now - timedelta(days=policy.events_days),
        )
    )
    dlq = db.execute(
        delete(DeadLetterEvent).where(
            DeadLetterEvent.tenant_id == tenant_id,
            DeadLetterEvent.created_at < now - timedelta(days=policy.dead_letter_days),
        )
    )
    findings = db.execute(
        delete(FindingRecord).where(
            FindingRecord.tenant_id == tenant_id,
            FindingRecord.created_at < now - timedelta(days=policy.findings_days),
        )
    )
    db.flush()
    return {
        "events_deleted": events.rowcount or 0,
        "dead_letter_deleted": dlq.rowcount or 0,
        "findings_deleted": findings.rowcount or 0,
    }
