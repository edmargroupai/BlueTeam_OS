from __future__ import annotations

from datetime import datetime

from blueteam_common.errors import BlueTeamError
from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_endpoint.process_tree import build_process_tree
from blueteam_network.normalize import sessions_from_events
from blueteam_schemas.events import CanonicalEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.graph import EntityRecord
from app.models.intel import SavedHunt
from app.models.telemetry import SecurityEvent
from app.services.ingestion import load_window
from app.services.intel import as_utc, list_iocs


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(text)


def structured_search(
    db: Session,
    tenant_id: str,
    *,
    start: str | None = None,
    end: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    user: str | None = None,
    host: str | None = None,
    domain: str | None = None,
    process_name: str | None = None,
    source_type: str | None = None,
    category: str | None = None,
    ioc: str | None = None,
    limit: int = 200,
) -> dict:
    events = load_window(db, tenant_id)
    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    limit = max(1, min(limit, 1000))
    matches: list[CanonicalEvent] = []
    for event in events:
        if start_dt and event.timestamp < start_dt:
            continue
        if end_dt and event.timestamp > end_dt:
            continue
        if src_ip and event.src_ip != src_ip:
            continue
        if dst_ip and event.dst_ip != dst_ip:
            continue
        if user:
            uname = (event.user.name if event.user else None) or ""
            if user.lower() not in uname.lower():
                continue
        if host:
            hname = (event.host.name if event.host else None) or event.src_ip or ""
            if host.lower() not in hname.lower():
                continue
        if domain and (event.domain or "").lower() != domain.lower():
            continue
        if process_name:
            pname = (event.process.name if event.process else None) or ""
            if process_name.lower() not in pname.lower():
                continue
        if source_type and event.source_type != source_type:
            continue
        if category and event.category != category:
            continue
        if ioc:
            needle = ioc.lower()
            hay = " ".join(
                filter(
                    None,
                    [
                        event.src_ip,
                        event.dst_ip,
                        event.domain,
                        event.hash,
                        event.url,
                        event.user.email if event.user else None,
                    ],
                )
            ).lower()
            if needle not in hay:
                continue
        matches.append(event)
        if len(matches) >= limit:
            break
    return {
        "count": len(matches),
        "limit": limit,
        "items": [
            {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "source_type": event.source_type,
                "event_type": event.event_type,
                "category": event.category,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "domain": event.domain,
                "user": event.user.name if event.user else None,
                "process": event.process.name if event.process else None,
                "host": event.host.name if event.host else None,
            }
            for event in matches
        ],
        "store": "control_plane_events",
    }


def authentication_history(db: Session, tenant_id: str, *, user: str | None = None, limit: int = 100) -> dict:
    result = structured_search(
        db,
        tenant_id,
        category="authentication",
        user=user,
        limit=limit,
    )
    result["view"] = "authentication_history"
    return result


def network_session_search(
    db: Session,
    tenant_id: str,
    *,
    src_ip: str | None = None,
    dst_ip: str | None = None,
) -> dict:
    events = load_window(db, tenant_id)
    sessions = sessions_from_events(events)
    items = []
    for session in sessions:
        payload = session.model_dump(mode="json") if hasattr(session, "model_dump") else dict(session)
        if src_ip and payload.get("src_ip") != src_ip and payload.get("source_ip") != src_ip:
            continue
        if dst_ip and payload.get("dst_ip") != dst_ip and payload.get("destination_ip") != dst_ip:
            continue
        items.append(payload)
    return {"view": "network_sessions", "count": len(items), "items": items, "manufactured": False}


def process_tree_view(db: Session, tenant_id: str) -> dict:
    events = load_window(db, tenant_id)
    tree = build_process_tree(events)
    tree["view"] = "process_tree"
    return tree


def entity_lookup(db: Session, tenant_id: str, query: str) -> dict:
    q = query.strip().lower()
    if not q:
        raise BlueTeamError("INVALID_QUERY", "entity query required", 422)
    entities = list(
        db.execute(select(EntityRecord).where(EntityRecord.tenant_id == tenant_id)).scalars().all()
    )
    hits = [
        {
            "id": row.id,
            "entity_type": row.entity_type,
            "display_name": row.display_name,
            "risk_score": row.risk_score,
            "criticality": row.criticality,
        }
        for row in entities
        if q in (row.display_name or "").lower() or q in (row.key or "").lower() or q == row.id.lower()
    ]
    return {"query": query, "count": len(hits), "items": hits}


def ioc_lookup(db: Session, tenant_id: str, value: str) -> dict:
    value = value.strip()
    iocs = [
        row
        for row in list_iocs(db, tenant_id, include_expired=True)
        if row.value.lower() == value.lower() or value.lower() in row.value.lower()
    ]
    telemetry = structured_search(db, tenant_id, ioc=value, limit=50)
    return {
        "indicator": value,
        "intel_matches": [
            {
                "id": row.id,
                "type": row.indicator_type,
                "source": row.source,
                "confidence": row.confidence,
                "expired": as_utc(row.expires_at) <= utcnow(),
                "sightings": row.sightings,
                "provenance": row.provenance,
            }
            for row in iocs
        ],
        "telemetry": telemetry,
    }


def save_hunt(
    db: Session,
    tenant_id: str,
    *,
    name: str,
    hunt_type: str,
    query: dict,
    actor_id: str,
    description: str = "",
) -> SavedHunt:
    if hunt_type not in {"blueql", "structured", "sql"}:
        raise BlueTeamError("INVALID_HUNT_TYPE", "hunt_type must be blueql|structured|sql", 422)
    if not name.strip():
        raise BlueTeamError("INVALID_NAME", "name required", 422)
    now = utcnow()
    row = SavedHunt(
        id=new_id("hnt"),
        tenant_id=tenant_id,
        name=name.strip(),
        description=description.strip(),
        hunt_type=hunt_type,
        query=query,
        created_by=actor_id,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def list_saved_hunts(db: Session, tenant_id: str) -> list[SavedHunt]:
    return list(
        db.execute(
            select(SavedHunt).where(SavedHunt.tenant_id == tenant_id).order_by(SavedHunt.updated_at.desc())
        ).scalars().all()
    )


def export_events(items: list[dict], *, fmt: str) -> dict:
    if fmt not in {"json", "csv"}:
        raise BlueTeamError("INVALID_EXPORT", "format must be json|csv", 422)
    if fmt == "json":
        return {"format": "json", "count": len(items), "payload": items}
    headers = sorted({key for item in items for key in item})
    lines = [",".join(headers)]
    for item in items:
        lines.append(",".join(str(item.get(h, "")).replace(",", " ") for h in headers))
    return {"format": "csv", "count": len(items), "payload": "\n".join(lines)}


def event_count(db: Session, tenant_id: str) -> int:
    return len(list(db.execute(select(SecurityEvent.id).where(SecurityEvent.tenant_id == tenant_id)).scalars().all()))
