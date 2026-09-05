from __future__ import annotations

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_correlation.engine import correlate
from blueteam_correlation.rules import incident_fingerprint
from blueteam_schemas.findings import Finding
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ops import IncidentRecord, StorylineRecord
from app.services.detection import list_findings
from app.services.ingestion import load_window


def persist_storylines_and_incidents(db: Session, tenant_id: str) -> dict:
    events = load_window(db, tenant_id)
    findings = [Finding.model_validate(row.payload) for row in list_findings(db, tenant_id)]
    stories = correlate(events, findings)
    created_stories = 0
    created_incidents = 0
    for story in stories:
        fingerprint = incident_fingerprint(story)
        existing_story = db.execute(
            select(StorylineRecord).where(
                StorylineRecord.tenant_id == tenant_id,
                StorylineRecord.fingerprint == fingerprint,
            )
        ).scalar_one_or_none()
        if existing_story:
            incident = db.get(IncidentRecord, existing_story.incident_id) if existing_story.incident_id else None
            if incident:
                continue
        incident = db.execute(
            select(IncidentRecord).where(
                IncidentRecord.tenant_id == tenant_id,
                IncidentRecord.fingerprint == fingerprint,
            )
        ).scalar_one_or_none()
        now = utcnow()
        if incident is None:
            incident = IncidentRecord(
                id=new_id("inc"),
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                title=story.title,
                status="grouped",
                storyline_ids=[],
                finding_rule_ids=sorted({stage.name for stage in story.stages if stage.rule_ids} | set(story.attributes.get("correlation_rule_id", "").split())),
                event_ids=story.event_ids,
                evidence_ids=story.evidence_ids,
                mitre_techniques=story.mitre_techniques,
                payload=story.model_dump(mode="json"),
                created_at=now,
                updated_at=now,
            )
            db.add(incident)
            db.flush()
            created_incidents += 1
        if existing_story is None:
            record = StorylineRecord(
                id=story.storyline_id,
                tenant_id=tenant_id,
                incident_id=incident.id,
                title=story.title,
                fingerprint=fingerprint,
                confidence=story.confidence,
                payload=story.model_dump(mode="json"),
                created_at=story.start,
            )
            db.add(record)
            created_stories += 1
            ids = list(incident.storyline_ids or [])
            if story.storyline_id not in ids:
                ids.append(story.storyline_id)
                incident.storyline_ids = ids
                incident.updated_at = now
    db.flush()
    return {"storylines": created_stories, "incidents": created_incidents, "total_storylines": len(stories)}


def list_incidents(db: Session, tenant_id: str) -> list[IncidentRecord]:
    return list(
        db.execute(
            select(IncidentRecord).where(IncidentRecord.tenant_id == tenant_id).order_by(IncidentRecord.updated_at.desc())
        ).scalars().all()
    )


def list_storylines(db: Session, tenant_id: str) -> list[StorylineRecord]:
    return list(
        db.execute(
            select(StorylineRecord).where(StorylineRecord.tenant_id == tenant_id).order_by(StorylineRecord.created_at.desc())
        ).scalars().all()
    )
