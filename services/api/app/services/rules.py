from __future__ import annotations

from blueteam_common.hashing import sha256_hex
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ops import RuleRevision
from app.services.detection import get_registry

ALLOWED_TRANSITIONS = {
    "draft": {"tested", "disabled"},
    "tested": {"promoted", "disabled", "draft"},
    "promoted": {"disabled", "tested"},
    "disabled": {"draft", "tested"},
}


def sync_catalog_revisions(db: Session) -> list[RuleRevision]:
    created: list[RuleRevision] = []
    for rule in get_registry().all_rules():
        existing = db.execute(
            select(RuleRevision).where(
                RuleRevision.rule_id == rule.meta.rule_id,
                RuleRevision.version == rule.meta.version,
            )
        ).scalars().first()
        if existing:
            continue
        checksum = sha256_hex(f"{rule.meta.rule_id}:{rule.meta.version}:{rule.meta.description}")
        row = RuleRevision(
            id=new_id("rlv"),
            rule_id=rule.meta.rule_id,
            version=rule.meta.version,
            status=rule.meta.status if rule.meta.status in ALLOWED_TRANSITIONS else "tested",
            name=rule.meta.name,
            checksum=checksum,
            mitre_techniques=list(rule.meta.mitre_techniques),
            execution=getattr(rule.meta, "execution", "realtime"),
            created_at=utcnow(),
            created_by="catalog",
        )
        db.add(row)
        created.append(row)
    db.flush()
    return created


def list_history(db: Session, rule_id: str) -> list[RuleRevision]:
    return list(
        db.execute(
            select(RuleRevision).where(RuleRevision.rule_id == rule_id).order_by(RuleRevision.created_at.desc())
        ).scalars().all()
    )


def latest_revision(db: Session, rule_id: str) -> RuleRevision | None:
    return db.execute(
        select(RuleRevision).where(RuleRevision.rule_id == rule_id).order_by(RuleRevision.created_at.desc())
    ).scalars().first()


def set_status(db: Session, rule_id: str, status: str, *, actor_id: str) -> RuleRevision:
    if status not in ALLOWED_TRANSITIONS:
        raise ValueError(f"invalid status {status}")
    current = latest_revision(db, rule_id)
    if current is None:
        sync_catalog_revisions(db)
        current = latest_revision(db, rule_id)
    if current is None:
        raise ValueError(f"unknown rule {rule_id}")
    if status not in ALLOWED_TRANSITIONS.get(current.status, set()):
        raise ValueError(f"cannot move {current.status} -> {status}")
    row = RuleRevision(
        id=new_id("rlv"),
        rule_id=current.rule_id,
        version=current.version,
        status=status,
        name=current.name,
        checksum=current.checksum,
        mitre_techniques=current.mitre_techniques,
        execution=current.execution,
        created_at=utcnow(),
        created_by=actor_id,
    )
    db.add(row)
    db.flush()
    return row


def promote(db: Session, rule_id: str, *, actor_id: str, bypass_regression: bool = False) -> RuleRevision:
    if not bypass_regression:
        from app.api.replay import regression_gate
        from blueteam_common.errors import BlueTeamError

        if not regression_gate(rule_id):
            raise BlueTeamError(
                "REGRESSION_GATE",
                f"Promotion blocked: no passing replay job covering {rule_id}",
                409,
            )
    return set_status(db, rule_id, "promoted", actor_id=actor_id)
