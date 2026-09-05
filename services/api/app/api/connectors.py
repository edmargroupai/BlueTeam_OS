from __future__ import annotations

import json
from typing import Any

from blueteam_common.errors import BlueTeamError
from blueteam_connectors import EndpointActionRequest, get_connector
from blueteam_correlation.engine import correlate
from blueteam_network.normalize import normalize_suricata, normalize_zeek, sessions_from_events
from blueteam_schemas.findings import Finding
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import Permission, get_request_id
from app.services.audit import write_audit
from app.services.auth import TenantActor
from app.services.detection import list_findings
from app.services.ingestion import ingest_payloads, load_window

router = APIRouter(prefix="/connectors", tags=["connectors"])


class WazuhIngestBody(BaseModel):
    alerts: list[dict[str, Any]] = Field(default_factory=list)


class ActionBody(BaseModel):
    action: str
    agent_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True


class NetworkBatchBody(BaseModel):
    source: str  # zeek|suricata
    events: list[dict[str, Any]] = Field(default_factory=list)
    jsonl: str | None = None


@router.get("")
def list_connectors(_: TenantActor = Depends(Permission("events:read"))) -> dict:
    return {
        "items": [
            {"connector_id": "wazuh", "name": "Wazuh", "kind": "endpoint"},
            {"connector_id": "zeek", "name": "Zeek", "kind": "network"},
            {"connector_id": "suricata", "name": "Suricata", "kind": "network"},
            {"connector_id": "azure_ad", "name": "Azure AD (fixture)", "kind": "cloud"},
        ]
    }


@router.get("/wazuh/health")
def wazuh_health(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    connector = get_connector("wazuh")
    events = load_window(db, actor.tenant_id)
    return connector.health(events).as_dict()


@router.get("/wazuh/inventory")
def wazuh_inventory(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    connector = get_connector("wazuh")
    items = connector.inventory(load_window(db, actor.tenant_id))
    return {"items": items, "count": len(items)}


@router.get("/wazuh/alerts")
def wazuh_alerts(
    actor: TenantActor = Depends(Permission("alerts:read")),
    db: Session = Depends(get_db),
) -> dict:
    connector = get_connector("wazuh")
    items = connector.alerts(load_window(db, actor.tenant_id))
    return {"items": items, "count": len(items)}


@router.post("/wazuh/ingest")
def wazuh_ingest(
    body: WazuhIngestBody,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    payloads = [{**alert, "adapter": "wazuh"} for alert in body.alerts]
    result = ingest_payloads(db, actor.tenant_id, payloads, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="connector.wazuh.ingest",
        target_type="connector",
        target_id="wazuh",
        after_state={"accepted": len(result["accepted"])},
    )
    return result


@router.post("/wazuh/actions")
def wazuh_action(
    body: ActionBody,
    actor: TenantActor = Depends(Permission("response:tier0")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    connector = get_connector("wazuh")
    result = connector.request_action(
        EndpointActionRequest(
            action=body.action,
            agent_id=body.agent_id,
            params=body.params,
            dry_run=body.dry_run,
        )
    )
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="connector.wazuh.action",
        target_type="endpoint_action",
        target_id=result.action_id,
        after_state=result.as_dict(),
        result="denied" if result.status == "denied" else "success",
    )
    return result.as_dict()


@router.post("/network/ingest")
def network_ingest(
    body: NetworkBatchBody,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    source = body.source.lower().strip()
    if source not in {"zeek", "suricata"}:
        raise BlueTeamError("INVALID_SOURCE", "source must be zeek|suricata", 422)
    payloads: list[dict[str, Any]] = []
    if body.jsonl:
        for line in body.jsonl.splitlines():
            if not line.strip():
                continue
            payloads.append({**json.loads(line), "adapter": source})
    for raw in body.events:
        payloads.append({**raw, "adapter": source})
    if not payloads:
        raise BlueTeamError("EMPTY_BATCH", "No network events provided", 422)
    # Fail closed on unparseable rows before persistence.
    for payload in payloads:
        if source == "zeek":
            normalize_zeek(payload, actor.tenant_id)
        else:
            normalize_suricata(payload, actor.tenant_id)
    result = ingest_payloads(db, actor.tenant_id, payloads, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action=f"connector.{source}.ingest",
        target_type="connector",
        target_id=source,
        after_state={"accepted": len(result["accepted"]), "normalized": len(payloads)},
    )
    return {**result, "normalized": len(payloads)}


@router.get("/network/sessions")
def network_sessions(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    events = [item for item in load_window(db, actor.tenant_id) if item.source_type in {"zeek", "suricata", "network"}]
    sessions = sessions_from_events(events)
    return {
        "items": [item.model_dump(mode="json") for item in sessions],
        "count": len(sessions),
        "dns": sum(1 for item in events if item.category == "dns"),
        "http": sum(1 for item in events if item.category == "http"),
        "tls": sum(1 for item in events if item.category == "tls"),
        "ids_alerts": sum(1 for item in events if item.category == "alert"),
    }


@router.get("/network/correlate")
def network_endpoint_correlate(
    actor: TenantActor = Depends(Permission("detections:read")),
    db: Session = Depends(get_db),
) -> dict:
    events = load_window(db, actor.tenant_id)
    findings = [Finding.model_validate(row.payload) for row in list_findings(db, actor.tenant_id)]
    stories = correlate(events, findings)
    event_map = {event.id: event for event in events}
    cross = []
    for story in stories:
        source_types = {event_map[eid].source_type for eid in story.event_ids if eid in event_map}
        sources = {event_map[eid].source for eid in story.event_ids if eid in event_map}
        has_endpoint = "endpoint" in source_types or bool(sources & {"wazuh", "sysmon", "osquery"})
        has_network = bool(source_types & {"zeek", "suricata", "network"})
        if has_endpoint and has_network:
            cross.append(story.model_dump(mode="json"))

    # IP/host join when storyline rules have not yet fired — still evidence-backed only.
    endpoint_events = [
        item
        for item in events
        if item.source_type == "endpoint" or item.source in {"wazuh", "sysmon", "osquery"}
    ]
    network_events = [item for item in events if item.source_type in {"zeek", "suricata", "network"}]
    ip_joins: list[dict[str, Any]] = []
    for endpoint in endpoint_events:
        ips = {endpoint.src_ip, endpoint.dst_ip, endpoint.host.ip if endpoint.host else None} - {None, ""}
        if not ips:
            continue
        matches = [
            net
            for net in network_events
            if net.src_ip in ips or net.dst_ip in ips or (net.host and net.host.ip in ips)
        ]
        if not matches:
            continue
        ip_joins.append(
            {
                "join_key": sorted(ips),
                "endpoint_event_ids": [endpoint.id],
                "network_event_ids": [item.id for item in matches],
                "sources": sorted({endpoint.source, *[item.source for item in matches]}),
            }
        )
    return {
        "storylines": [item.model_dump(mode="json") for item in stories],
        "cross_source": cross,
        "ip_joins": ip_joins,
        "count": len(cross) + len(ip_joins),
        "note": "Cross-source requires endpoint + network evidence (storyline and/or shared IP).",
    }


class CloudIngestBody(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/cloud/azure/ingest")
def azure_ingest(
    body: CloudIngestBody,
    actor: TenantActor = Depends(Permission("events:ingest")),
    db: Session = Depends(get_db),
    request_id: str = Depends(get_request_id),
) -> dict:
    from blueteam_cloud import get_cloud_connector

    connector = get_cloud_connector("azure_ad")
    payloads = []
    for raw in body.events:
        event = connector.normalize_audit(raw, actor.tenant_id)
        payloads.append({**event.model_dump(mode="json")})
    result = ingest_payloads(db, actor.tenant_id, payloads, actor_id=actor.user_id)
    write_audit(
        db,
        tenant_id=actor.tenant_id,
        actor_type="user",
        actor_id=actor.user_id,
        request_id=request_id,
        action="connector.azure_ad.ingest",
        target_type="connector",
        target_id="azure_ad",
        after_state={"accepted": len(result["accepted"])},
    )
    return result


@router.get("/cloud/azure/inventory")
def azure_inventory(
    actor: TenantActor = Depends(Permission("events:read")),
    db: Session = Depends(get_db),
) -> dict:
    from blueteam_cloud import get_cloud_connector

    connector = get_cloud_connector("azure_ad")
    events = [item for item in load_window(db, actor.tenant_id) if item.source == "azure-ad"]
    return connector.inventory(events).as_dict()
