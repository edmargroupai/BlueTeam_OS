from __future__ import annotations

from pathlib import Path

import pytest
from blueteam_graph.engine import build_graph
from blueteam_range.loader import load_scenario
from blueteam_range.runner import run_scenario

from detections.python.catalog import build_default_registry

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.polyglot
def test_identity_graph_is_observed_and_explainable() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/identity/password_spray.yaml")
    result = run_scenario(scenario, build_default_registry())
    assert result.passed
    graph = build_graph(scenario.events, result.findings)
    assert graph.manufactured_edges is False
    users = [item for item in graph.entities if item.entity_type == "user"]
    ips = [item for item in graph.entities if item.entity_type == "ip"]
    assert users and ips
    assert all(item.event_ids for item in graph.entities)
    assert graph.relationships
    assert all(rel.event_ids and rel.manufactured is False for rel in graph.relationships)
    risky = [item for item in graph.entities if item.risk_score > 0]
    assert risky
    assert all(item.risk_components and item.finding_ids for item in risky)


@pytest.mark.polyglot
def test_office_graph_includes_process_parent_edge() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/endpoint/office_spawns_powershell.yaml")
    result = run_scenario(scenario, build_default_registry())
    graph = build_graph(scenario.events, result.findings)
    child_edges = [rel for rel in graph.relationships if rel.relation == "child_of"]
    assert child_edges
    assert all(rel.event_ids for rel in child_edges)
