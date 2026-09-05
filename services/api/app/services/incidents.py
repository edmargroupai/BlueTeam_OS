from __future__ import annotations

from blueteam_common.errors import BlueTeamError
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_correlation.engine import correlate
from blueteam_correlation.rules import incident_fingerprint
from blueteam_schemas.findings import Finding
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ops import IncidentRecord, StorylineRecord
from app.models.telemetry import Alert, Evidence
from app.services.detection import list_findings
from app.services.ingestion import load_window

INCIDENT_STATUSES = {
    "grouped",
    "new",
    "triaging",
    "investigating",
    "contained",
    "eradicated",
    "recovered",
    "closed",
}

SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def _timeline_event(
    *,
    kind: str,
    actor_id: str,
    summary: str,
    detail: dict | None = None,
) -> dict:
    return {
        "id": new_id("itl"),
        "at": utcnow().isoformat(),
        "kind": kind,
        "actor_id": actor_id,
        "summary": summary,
        "detail": detail or {},
    }


def serialize_incident(row: IncidentRecord) -> dict:
    return {
        "id": row.id,
        "title": row.title,
        "status": row.status,
        "severity": getattr(row, "severity", None) or "medium",
        "assignee_user_id": getattr(row, "assignee_user_id", None),
        "assignee_email": getattr(row, "assignee_email", None),
        "source_alert_id": getattr(row, "source_alert_id", None),
        "storyline_ids": row.storyline_ids or [],
        "event_ids": row.event_ids or [],
        "evidence_ids": row.evidence_ids or [],
        "related_entity_ids": getattr(row, "related_entity_ids", None) or [],
        "mitre_techniques": row.mitre_techniques or [],
        "notes": getattr(row, "notes", None) or [],
        "tasks": getattr(row, "tasks", None) or [],
        "timeline": getattr(row, "timeline", None) or [],
        "root_cause": getattr(row, "root_cause", None),
        "lessons_learned": getattr(row, "lessons_learned", None),
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


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
                severity="high" if story.confidence >= 0.8 else "medium",
                storyline_ids=[],
                finding_rule_ids=sorted(
                    {stage.name for stage in story.stages if stage.rule_ids}
                    | set(str(story.attributes.get("correlation_rule_id", "")).split())
                ),
                event_ids=story.event_ids,
                evidence_ids=story.evidence_ids,
                related_entity_ids=[],
                mitre_techniques=story.mitre_techniques,
                notes=[],
                tasks=[],
                timeline=[
                    _timeline_event(
                        kind="created",
                        actor_id="correlation",
                        summary="Incident grouped from correlated storyline",
                        detail={"confidence": story.confidence},
                    )
                ],
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


def get_incident(db: Session, tenant_id: str, incident_id: str) -> IncidentRecord:
    row = db.execute(
        select(IncidentRecord).where(IncidentRecord.tenant_id == tenant_id, IncidentRecord.id == incident_id)
    ).scalar_one_or_none()
    if row is None:
        raise BlueTeamError("NOT_FOUND", "Incident not found", 404)
    return row


def create_from_alert(db: Session, tenant_id: str, alert_id: str, *, actor_id: str) -> IncidentRecord:
    alert = db.execute(
        select(Alert).where(Alert.tenant_id == tenant_id, Alert.id == alert_id)
    ).scalar_one_or_none()
    if alert is None:
        raise BlueTeamError("NOT_FOUND", "Alert not found", 404)
    existing = db.execute(
        select(IncidentRecord).where(
            IncidentRecord.tenant_id == tenant_id,
            IncidentRecord.source_alert_id == alert_id,
        )
    ).scalar_one_or_none()
    if existing:
        return existing
    now = utcnow()
    fingerprint = f"alert:{alert_id}"
    incident = IncidentRecord(
        id=new_id("inc"),
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        title=alert.title,
        status="new",
        severity=alert.severity if alert.severity in SEVERITIES else "medium",
        source_alert_id=alert.id,
        storyline_ids=[],
        finding_rule_ids=[alert.finding_id],
        event_ids=[],
        evidence_ids=[],
        related_entity_ids=[],
        mitre_techniques=[],
        notes=[],
        tasks=[],
        timeline=[
            _timeline_event(
                kind="created_from_alert",
                actor_id=actor_id,
                summary=f"Alert {alert_id} converted to incident",
                detail={"alert_id": alert_id, "finding_id": alert.finding_id},
            )
        ],
        payload={"source": "alert", "alert_id": alert_id, "finding_id": alert.finding_id},
        created_at=now,
        updated_at=now,
    )
    alert.status = "promoted"
    db.add(incident)
    db.flush()
    return incident


def set_status(db: Session, incident: IncidentRecord, status: str, *, actor_id: str) -> IncidentRecord:
    if status not in INCIDENT_STATUSES:
        raise BlueTeamError("INVALID_STATUS", f"Unsupported status {status}", 422)
    before = incident.status
    incident.status = status
    incident.updated_at = utcnow()
    timeline = list(incident.timeline or [])
    timeline.append(
        _timeline_event(
            kind="status_change",
            actor_id=actor_id,
            summary=f"Status {before} → {status}",
            detail={"before": before, "after": status},
        )
    )
    incident.timeline = timeline
    db.flush()
    return incident


def assign(
    db: Session,
    incident: IncidentRecord,
    *,
    assignee_user_id: str,
    assignee_email: str,
    actor_id: str,
) -> IncidentRecord:
    incident.assignee_user_id = assignee_user_id
    incident.assignee_email = assignee_email
    incident.updated_at = utcnow()
    if incident.status == "grouped":
        incident.status = "triaging"
    timeline = list(incident.timeline or [])
    timeline.append(
        _timeline_event(
            kind="assignment",
            actor_id=actor_id,
            summary=f"Assigned to {assignee_email}",
            detail={"assignee_user_id": assignee_user_id},
        )
    )
    incident.timeline = timeline
    db.flush()
    return incident


def add_note(db: Session, incident: IncidentRecord, body: str, *, actor_id: str) -> IncidentRecord:
    if not body.strip():
        raise BlueTeamError("INVALID_NOTE", "Note body required", 422)
    note = {
        "id": new_id("nte"),
        "at": utcnow().isoformat(),
        "author_id": actor_id,
        "body": body.strip(),
    }
    notes = list(incident.notes or [])
    notes.append(note)
    incident.notes = notes
    timeline = list(incident.timeline or [])
    timeline.append(
        _timeline_event(kind="note", actor_id=actor_id, summary="Analyst note added", detail={"note_id": note["id"]})
    )
    incident.timeline = timeline
    incident.updated_at = utcnow()
    db.flush()
    return incident


def add_task(
    db: Session,
    incident: IncidentRecord,
    title: str,
    *,
    actor_id: str,
) -> IncidentRecord:
    if not title.strip():
        raise BlueTeamError("INVALID_TASK", "Task title required", 422)
    task = {
        "id": new_id("tsk"),
        "title": title.strip(),
        "status": "open",
        "created_at": utcnow().isoformat(),
        "created_by": actor_id,
    }
    tasks = list(incident.tasks or [])
    tasks.append(task)
    incident.tasks = tasks
    timeline = list(incident.timeline or [])
    timeline.append(
        _timeline_event(kind="task", actor_id=actor_id, summary=f"Task added: {task['title']}", detail={"task_id": task["id"]})
    )
    incident.timeline = timeline
    incident.updated_at = utcnow()
    db.flush()
    return incident


def set_root_cause(db: Session, incident: IncidentRecord, text: str, *, actor_id: str) -> IncidentRecord:
    incident.root_cause = text.strip() or None
    incident.updated_at = utcnow()
    timeline = list(incident.timeline or [])
    timeline.append(_timeline_event(kind="root_cause", actor_id=actor_id, summary="Root cause recorded"))
    incident.timeline = timeline
    db.flush()
    return incident


def set_lessons(db: Session, incident: IncidentRecord, text: str, *, actor_id: str) -> IncidentRecord:
    incident.lessons_learned = text.strip() or None
    incident.updated_at = utcnow()
    timeline = list(incident.timeline or [])
    timeline.append(_timeline_event(kind="lessons", actor_id=actor_id, summary="Lessons learned recorded"))
    incident.timeline = timeline
    db.flush()
    return incident


def link_evidence(
    db: Session,
    incident: IncidentRecord,
    evidence_id: str,
    *,
    actor_id: str,
) -> IncidentRecord:
    evidence = db.execute(
        select(Evidence).where(Evidence.tenant_id == incident.tenant_id, Evidence.id == evidence_id)
    ).scalar_one_or_none()
    if evidence is None:
        raise BlueTeamError("NOT_FOUND", "Evidence not found", 404)
    if not evidence.sealed:
        raise BlueTeamError("EVIDENCE_NOT_SEALED", "Only sealed evidence may be linked", 409)
    if evidence.incident_id and evidence.incident_id != incident.id:
        raise BlueTeamError("EVIDENCE_BOUND", "Evidence already bound to another incident", 409)
    ids = list(incident.evidence_ids or [])
    if evidence_id not in ids:
        ids.append(evidence_id)
        incident.evidence_ids = ids
    evidence.incident_id = incident.id
    history = list(evidence.transformation_history or [])
    history.append(
        {
            "op": "link_incident",
            "at": utcnow().isoformat(),
            "actor_id": actor_id,
            "incident_id": incident.id,
            "integrity_hash": evidence.integrity_hash,
        }
    )
    evidence.transformation_history = history
    timeline = list(incident.timeline or [])
    timeline.append(
        _timeline_event(
            kind="evidence_link",
            actor_id=actor_id,
            summary=f"Linked sealed evidence {evidence_id}",
            detail={"evidence_id": evidence_id, "integrity_hash": evidence.integrity_hash},
        )
    )
    incident.timeline = timeline
    incident.updated_at = utcnow()
    db.flush()
    return incident
