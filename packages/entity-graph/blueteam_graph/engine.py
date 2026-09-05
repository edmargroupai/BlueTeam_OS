"""Build entities and observed relationships from telemetry. Do not invent edges."""

from __future__ import annotations

from blueteam_common.hashing import sha256_hex
from blueteam_schemas.events import CanonicalEvent
from blueteam_schemas.findings import Finding
from blueteam_schemas.graph import (
    EntityGraph,
    GraphEntity,
    GraphRelationship,
    RiskComponent,
)

SEVERITY_POINTS = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 12.0,
    "low": 5.0,
    "informational": 1.0,
}
CRITICALITY_FACTOR = {
    "unknown": 1.0,
    "low": 0.8,
    "medium": 1.0,
    "high": 1.25,
    "crown_jewel": 1.5,
}


def entity_id(tenant_id: str, entity_type: str, key: str) -> str:
    digest = sha256_hex(f"{tenant_id}|{entity_type}|{key.lower()}")
    return f"ent_{digest[:32]}"


def relationship_id(tenant_id: str, src_id: str, relation: str, dst_id: str) -> str:
    digest = sha256_hex(f"{tenant_id}|{src_id}|{relation}|{dst_id}")
    return f"rel_{digest[:32]}"


def build_graph(
    events: list[CanonicalEvent],
    findings: list[Finding] | None = None,
    *,
    criticality: dict[str, str] | None = None,
) -> EntityGraph:
    if not events:
        tenant = findings[0].tenant_id if findings else ""
        return EntityGraph(tenant_id=tenant, entities=[], relationships=[])
    tenant_id = events[0].tenant_id
    entities: dict[str, GraphEntity] = {}
    relationships: dict[str, GraphRelationship] = {}

    def upsert(entity_type: str, key: str, name: str, event: CanonicalEvent, **attrs: str) -> str:
        eid = entity_id(tenant_id, entity_type, key)
        existing = entities.get(eid)
        if existing is None:
            entities[eid] = GraphEntity(
                id=eid,
                tenant_id=tenant_id,
                entity_type=entity_type,  # type: ignore[arg-type]
                key=key.lower(),
                display_name=name,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_ids=[event.id],
                attributes={k: v for k, v in attrs.items() if v},
            )
        else:
            if event.id not in existing.event_ids:
                existing.event_ids.append(event.id)
            if event.timestamp < existing.first_seen:
                existing.first_seen = event.timestamp
            if event.timestamp > existing.last_seen:
                existing.last_seen = event.timestamp
        return eid

    def relate(src: str, relation: str, dst: str, event_id: str) -> None:
        rid = relationship_id(tenant_id, src, relation, dst)
        existing = relationships.get(rid)
        if existing is None:
            relationships[rid] = GraphRelationship(
                id=rid,
                tenant_id=tenant_id,
                src_id=src,
                dst_id=dst,
                relation=relation,  # type: ignore[arg-type]
                event_ids=[event_id],
                manufactured=False,
            )
        elif event_id not in existing.event_ids:
            existing.event_ids.append(event_id)

    for event in events:
        user_id = None
        host_id = None
        proc_id = None
        if event.user and event.user.name:
            user_id = upsert("user", event.user.name, event.user.name, event, user_id=event.user.id or "")
        if event.host and (event.host.id or event.host.name):
            host_key = event.host.id or event.host.name or ""
            host_id = upsert("host", host_key, event.host.name or host_key, event, os=event.host.os or "")
        if event.process and event.process.name:
            proc_key = f"{event.process.name}:{event.process.pid or 'na'}"
            proc_id = upsert(
                "process",
                proc_key,
                event.process.name,
                event,
                path=event.process.path or "",
                command_line=event.process.command_line or "",
            )
        if event.src_ip:
            src_ip = upsert("ip", event.src_ip, event.src_ip, event, role="src")
            if user_id:
                relate(user_id, "used_from", src_ip, event.id)
            if host_id:
                relate(host_id, "connected_to", src_ip, event.id)
        if event.dst_ip:
            dst_ip = upsert("ip", event.dst_ip, event.dst_ip, event, role="dst")
            if host_id:
                relate(host_id, "connected_to", dst_ip, event.id)
            if proc_id:
                relate(proc_id, "connected_to", dst_ip, event.id)
        if event.domain:
            domain_id = upsert("domain", event.domain, event.domain, event)
            if event.src_ip:
                relate(entity_id(tenant_id, "ip", event.src_ip), "queried", domain_id, event.id)
        if event.cloud_resource and (event.cloud_resource.resource_id or event.cloud_resource.account_id):
            cloud_key = event.cloud_resource.resource_id or event.cloud_resource.account_id or ""
            upsert(
                "cloud_resource",
                cloud_key,
                event.cloud_resource.resource_type or cloud_key,
                event,
                provider=event.cloud_resource.provider or "",
                account_id=event.cloud_resource.account_id or "",
            )
        if user_id and host_id:
            relate(user_id, "on_host", host_id, event.id)
        if host_id and proc_id:
            relate(host_id, "ran", proc_id, event.id)
        if proc_id and event.parent_process and event.parent_process.name:
            parent_key = f"{event.parent_process.name}:{event.parent_process.pid or 'na'}"
            parent_id = upsert("process", parent_key, event.parent_process.name, event)
            relate(proc_id, "child_of", parent_id, event.id)

    overrides = criticality or {}
    for entity in entities.values():
        entity.criticality = overrides.get(entity.id, "unknown")  # type: ignore[assignment]
        apply_risk(entity, findings or [])

    return EntityGraph(
        tenant_id=tenant_id,
        entities=sorted(entities.values(), key=lambda item: item.risk_score, reverse=True),
        relationships=list(relationships.values()),
        manufactured_edges=False,
    )


def apply_risk(entity: GraphEntity, findings: list[Finding]) -> GraphEntity:
    components: list[RiskComponent] = []
    finding_ids: list[str] = []
    raw = 0.0
    for finding in findings:
        if finding.tenant_id != entity.tenant_id:
            continue
        if not _finding_touches(entity, finding):
            continue
        finding_ids.append(finding.id)
        points = SEVERITY_POINTS.get(finding.severity, 1.0)
        kind = "intel" if finding.rule_id.startswith("intel.") else "detection"
        raw += points
        components.append(
            RiskComponent(
                source=finding.id,
                kind=kind,  # type: ignore[arg-type]
                points=points,
                explanation=f"{finding.rule_id} ({finding.severity}) contributed {points} points.",
            )
        )
    factor = CRITICALITY_FACTOR.get(entity.criticality, 1.0)
    if factor != 1.0:
        components.append(
            RiskComponent(
                source=f"criticality:{entity.criticality}",
                kind="criticality",
                points=round(raw * (factor - 1.0), 2),
                explanation=f"Asset criticality {entity.criticality} applies factor {factor}.",
            )
        )
    entity.finding_ids = finding_ids
    entity.risk_components = components
    entity.risk_score = min(100.0, round(raw * factor, 2))
    return entity


def _finding_touches(entity: GraphEntity, finding: Finding) -> bool:
    if set(entity.event_ids) & set(finding.event_ids):
        return True
    attrs = finding.attributes or {}
    key = entity.key
    if entity.entity_type == "user" and attrs.get("user", "").lower() == key:
        return True
    if entity.entity_type == "host" and attrs.get("host", "").lower() == key:
        return True
    if entity.entity_type == "ip" and key in {attrs.get("src_ip", "").lower(), attrs.get("dst_ip", "").lower()}:
        return True
    if entity.entity_type == "process" and attrs.get("process", "").lower() and attrs.get("process", "").lower() in key:
        return True
    return False
