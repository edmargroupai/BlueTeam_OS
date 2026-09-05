"""Defensive architecture center — typed graph (zones, controls, sensors, gaps)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow

NodeKind = Literal["zone", "trust_boundary", "asset", "identity", "control", "sensor", "dependency"]


@dataclass
class ArchNode:
    id: str
    kind: NodeKind
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArchEdge:
    source: str
    target: str
    relation: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArchitectureGraph:
    graph_id: str
    tenant_id: str
    version: int
    nodes: list[ArchNode] = field(default_factory=list)
    edges: list[ArchEdge] = field(default_factory=list)
    created_at: str = ""

    def as_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "tenant_id": self.tenant_id,
            "version": self.version,
            "created_at": self.created_at,
            "nodes": [{"id": n.id, "kind": n.kind, "name": n.name, "attributes": n.attributes} for n in self.nodes],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation, "attributes": e.attributes}
                for e in self.edges
            ],
        }


def default_lab_architecture(tenant_id: str) -> ArchitectureGraph:
    nodes = [
        ArchNode("zone_corp", "zone", "Corporate"),
        ArchNode("zone_dmz", "zone", "DMZ"),
        ArchNode("tb_edge", "trust_boundary", "Internet edge"),
        ArchNode("asset_dc", "asset", "dc-01", {"criticality": "critical"}),
        ArchNode("id_alice", "identity", "alice"),
        ArchNode("ctrl_mfa", "control", "MFA", {"coverage": ["T1078"]}),
        ArchNode("sensor_zeek", "sensor", "Zeek", {"telemetry": ["network", "dns"]}),
        ArchNode("sensor_wazuh", "sensor", "Wazuh", {"telemetry": ["endpoint"]}),
        ArchNode("dep_idp", "dependency", "IdP"),
    ]
    edges = [
        ArchEdge("zone_corp", "tb_edge", "bounded_by"),
        ArchEdge("zone_dmz", "tb_edge", "bounded_by"),
        ArchEdge("asset_dc", "zone_corp", "resides_in"),
        ArchEdge("id_alice", "asset_dc", "authenticates_to"),
        ArchEdge("ctrl_mfa", "id_alice", "protects"),
        ArchEdge("sensor_zeek", "zone_dmz", "monitors"),
        ArchEdge("sensor_wazuh", "asset_dc", "monitors"),
        ArchEdge("dep_idp", "id_alice", "provides"),
    ]
    return ArchitectureGraph(
        graph_id=new_id("arch"),
        tenant_id=tenant_id,
        version=1,
        nodes=nodes,
        edges=edges,
        created_at=utcnow().isoformat(),
    )


def detection_gaps(graph: ArchitectureGraph, covered_techniques: list[str]) -> list[dict]:
    covered = {item.upper() for item in covered_techniques}
    gaps = []
    for node in graph.nodes:
        if node.kind != "control":
            continue
        for tech in node.attributes.get("coverage") or []:
            if tech.upper() not in covered:
                gaps.append({"control": node.name, "technique": tech, "gap": "control_without_detection"})
    sensors = [node.name for node in graph.nodes if node.kind == "sensor"]
    if "Zeek" not in sensors:
        gaps.append({"gap": "missing_network_sensor"})
    return gaps


class ArchitectureStore:
    def __init__(self) -> None:
        self._graphs: dict[str, list[ArchitectureGraph]] = {}

    def save(self, graph: ArchitectureGraph) -> ArchitectureGraph:
        versions = self._graphs.setdefault(graph.tenant_id, [])
        graph.version = len(versions) + 1
        versions.append(graph)
        return graph

    def latest(self, tenant_id: str) -> ArchitectureGraph | None:
        versions = self._graphs.get(tenant_id) or []
        return versions[-1] if versions else None

    def history(self, tenant_id: str) -> list[ArchitectureGraph]:
        return list(self._graphs.get(tenant_id) or [])
