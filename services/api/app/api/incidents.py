from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.incidents import (
    INCIDENT_STATUSES,
    add_note,
    add_task,
    assign,
    create_from_alert,
    get_incident,
    link_evidence,
    list_incidents,
    list_storylines,
    persist_storylines_and_incidents,
    serialize_incident,
    set_lessons,
    set_root_cause,
    set_status,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


class StatusBody(BaseModel):
    status: str


class AssignBody(BaseModel):
    assignee_user_id: str
    assignee_email: str


class NoteBody(BaseModel):
    body: str = Field(min_length=1)


class TaskBody(BaseModel):
    title: str = Field(min_length=1)


class TextBody(BaseModel):
    text: str = Field(min_length=1)


class EvidenceLinkBody(BaseModel):
    evidence_id: str


class ConvertAlertBody(BaseModel):
    alert_id: str


@router.get("")
def get_incidents(
    actor: TenantActor = Depends(Permission("incidents:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_incidents(db, actor.tenant_id)
    return {
        "items": [serialize_incident(row) for row in rows],
        "lifecycle": "ir-v1",
        "allowed_statuses": sorted(INCIDENT_STATUSES),
    }


@router.get("/storylines")
def get_storylines(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = list_storylines(db, actor.tenant_id)
    return {"items": [row.payload for row in rows], "count": len(rows)}


@router.get("/{incident_id}")
def get_one(
    incident_id: str,
    actor: TenantActor = Depends(Permission("incidents:read")),
    db: Session = Depends(get_db),
) -> dict:
    return serialize_incident(get_incident(db, actor.tenant_id, incident_id))


@router.post("/rebuild")
def rebuild(
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
) -> dict:
    return persist_storylines_and_incidents(db, actor.tenant_id)


@router.post("/from-alert")
def from_alert(
    body: ConvertAlertBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    row = create_from_alert(db, actor.tenant_id, body.alert_id, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.from_alert",
        target_type="incident",
        target_id=row.id,
        after_state={"alert_id": body.alert_id, "status": row.status},
    )
    return serialize_incident(row)


@router.post("/{incident_id}/status")
def change_status(
    incident_id: str,
    body: StatusBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    before = incident.status
    row = set_status(db, incident, body.status, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.status",
        target_type="incident",
        target_id=row.id,
        before_state={"status": before},
        after_state={"status": row.status},
    )
    return serialize_incident(row)


@router.post("/{incident_id}/assign")
def assign_incident(
    incident_id: str,
    body: AssignBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = assign(
        db,
        incident,
        assignee_user_id=body.assignee_user_id,
        assignee_email=body.assignee_email,
        actor_id=actor.user_id,
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.assign",
        target_type="incident",
        target_id=row.id,
        after_state={"assignee_user_id": body.assignee_user_id, "assignee_email": body.assignee_email},
    )
    return serialize_incident(row)


@router.post("/{incident_id}/notes")
def note(
    incident_id: str,
    body: NoteBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = add_note(db, incident, body.body, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.note",
        target_type="incident",
        target_id=row.id,
    )
    return serialize_incident(row)


@router.post("/{incident_id}/tasks")
def task(
    incident_id: str,
    body: TaskBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = add_task(db, incident, body.title, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.task",
        target_type="incident",
        target_id=row.id,
    )
    return serialize_incident(row)


@router.post("/{incident_id}/root-cause")
def root_cause(
    incident_id: str,
    body: TextBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = set_root_cause(db, incident, body.text, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.root_cause",
        target_type="incident",
        target_id=row.id,
    )
    return serialize_incident(row)


@router.post("/{incident_id}/lessons")
def lessons(
    incident_id: str,
    body: TextBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = set_lessons(db, incident, body.text, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.lessons",
        target_type="incident",
        target_id=row.id,
    )
    return serialize_incident(row)


@router.post("/{incident_id}/evidence")
def evidence(
    incident_id: str,
    body: EvidenceLinkBody,
    actor: TenantActor = Depends(Permission("incidents:write")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    incident = get_incident(db, actor.tenant_id, incident_id)
    row = link_evidence(db, incident, body.evidence_id, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="incident.evidence_link",
        target_type="incident",
        target_id=row.id,
        after_state={"evidence_id": body.evidence_id},
    )
    return serialize_incident(row)
