from __future__ import annotations

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_vuln import import_scanner_findings
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.vuln import VulnerabilityRecord


def _row(item: VulnerabilityRecord) -> dict:
    return {
        "id": item.id,
        "cve_id": item.cve_id,
        "title": item.title,
        "cvss": item.cvss,
        "exploitability": item.exploitability,
        "asset_id": item.asset_id,
        "asset_criticality": item.asset_criticality,
        "threat_activity": item.threat_activity,
        "priority": item.priority,
        "band": item.band,
        "sla_days": item.sla_days,
        "scanner": item.scanner,
        "status": item.status,
        "formula": item.formula,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
    }


def list_vulns(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(
        select(VulnerabilityRecord)
        .where(VulnerabilityRecord.tenant_id == tenant_id)
        .order_by(VulnerabilityRecord.priority.desc())
    ).scalars().all()
    return [_row(item) for item in rows]


def import_vulns(db: Session, tenant_id: str, rows: list[dict]) -> list[dict]:
    scored = import_scanner_findings(rows)
    now = utcnow()
    created = []
    for item in scored:
        record = VulnerabilityRecord(
            id=new_id("vul"),
            tenant_id=tenant_id,
            cve_id=item["cve_id"],
            title=item["title"],
            cvss=item["cvss"],
            exploitability=item["exploitability"],
            asset_id=item["asset_id"],
            asset_criticality=item["asset_criticality"],
            threat_activity=item["threat_activity"],
            priority=item["priority"],
            band=item["band"],
            sla_days=item["sla_days"],
            scanner=item["scanner"],
            status=item["status"],
            formula=item["formula"],
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        created.append(_row(record))
    db.flush()
    return created
