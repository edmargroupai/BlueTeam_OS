from __future__ import annotations

from pathlib import Path

import pytest
from blueteam_broker.broker import ExecutionBroker
from blueteam_correlation.engine import correlate
from blueteam_endpoint.normalize import normalize_sysmon
from blueteam_endpoint.process_tree import build_process_tree
from blueteam_fabric.envelope import envelope
from blueteam_fabric.memory import InMemoryFabric
from blueteam_fabric.pipeline import EventPipeline
from blueteam_fabric.topics import ALL_TOPICS, DEADLETTER, RAW
from blueteam_network.normalize import normalize_suricata, normalize_zeek, sessions_from_events
from blueteam_range.loader import load_scenario
from blueteam_range.runner import run_scenario
from blueteam_rego.engine import active_engine as rego_engine
from blueteam_rego.engine import evaluate
from blueteam_schemas.actions import ActionRequest
from blueteam_sql.engine import execute_hunt, list_hunts
from blueteam_yara.engine import active_engine as yara_engine
from blueteam_yara.engine import scan_bytes

from detections.python.catalog import build_default_registry

ROOT = Path(__file__).resolve().parents[2]
TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _zeek_conn(uid: str, src: str, dst: str, dport: int) -> dict:
    return {
        "_path": "conn",
        "ts": "2026-09-05T10:00:00Z",
        "uid": uid,
        "id": {"orig_h": src, "resp_h": dst, "orig_p": 40000, "resp_p": dport},
        "proto": "tcp",
        "orig_bytes": 120,
        "resp_bytes": 80,
    }


@pytest.mark.polyglot
def test_in_memory_fabric_topics_and_dlq() -> None:
    fabric = InMemoryFabric()
    assert set(fabric.ensure_topics()) == set(ALL_TOPICS)
    fabric.publish(envelope(RAW, TENANT, {"id": "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bad": True}))
    batch = fabric.consume(RAW)
    assert batch[0].tenant_id == TENANT
    assert batch[0].schema_version
    fabric.dead_letter(batch[0], "poison fixture")
    dlq = fabric.consume(DEADLETTER)
    assert dlq and dlq[0].poison is True
    # Idempotent: second consume of same key is empty.
    assert fabric.consume(RAW) == []


@pytest.mark.polyglot
def test_pipeline_normalizes_and_detects_scan() -> None:
    from app.services.normalizer import normalize_generic

    registry = build_default_registry()
    pipeline = EventPipeline(InMemoryFabric(), normalizer=normalize_generic, registry=registry)
    payloads = []
    for idx in range(8):
        event = normalize_zeek(_zeek_conn(f"C{idx}", "10.0.0.44", f"10.0.1.{idx+1}", 22), TENANT)
        payloads.append(event.model_dump(mode="json"))
    result = pipeline.run_once(TENANT, payloads)
    assert result["backend"] == "memory"
    assert result["normalized"] == 8
    assert result["dead_lettered"] == 0
    assert any(item.rule_id == "network.horizontal_scan" for item in pipeline.findings)


@pytest.mark.polyglot
def test_zeek_and_suricata_preserve_raw_reference() -> None:
    zeek = normalize_zeek(_zeek_conn("Craw", "10.0.0.8", "10.0.0.9", 443), TENANT)
    assert zeek.source_type == "zeek"
    assert zeek.raw_hash
    assert zeek.raw_event["uid"] == "Craw"
    eve = normalize_suricata(
        {
            "timestamp": "2026-09-05T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.8",
            "dest_ip": "198.51.100.10",
            "src_port": 4000,
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 99,
            "alert": {"signature": "ET POLICY", "category": "A Network Trojan was detected", "severity": 1},
        },
        TENANT,
    )
    assert eve.category == "alert"
    assert eve.attributes["confirmed_compromise"] == "false"
    assert eve.attributes["signature"] == "ET POLICY"
    sessions = sessions_from_events([zeek, eve])
    assert sessions
    assert sessions[0].zeek_refs or sessions[0].suricata_refs


@pytest.mark.polyglot
def test_process_tree_does_not_invent_missing_parents() -> None:
    child = normalize_sysmon(
        {
            "EventID": 1,
            "UtcTime": "2026-09-05T11:00:00Z",
            "Image": "C:\\Users\\jlee\\payload.exe",
            "ProcessId": 4000,
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentProcessId": 3000,
            "Computer": "ws-jlee",
            "CommandLine": "payload.exe",
        },
        TENANT,
    )
    tree = build_process_tree([child])
    assert tree["manufactured_edges"] is False
    assert len(tree["edges"]) == 1
    parent = next(node for node in tree["nodes"] if node["pid"] == 3000)
    assert parent["inferred_from_child"] is True
    assert parent["event_id"] is None


@pytest.mark.polyglot
def test_registered_hunts_cover_priority_cases() -> None:
    ids = {item["id"] for item in list_hunts()}
    required = {
        "sql.identity.password_spray",
        "sql.identity.brute_force",
        "sql.endpoint.rare_process",
        "sql.network.beaconing",
        "sql.network.horizontal_scan",
        "sql.network.unusual_outbound",
        "sql.network.lateral_movement",
        "sql.identity.privilege_escalation",
        "sql.identity.service_account_misuse",
        "sql.telemetry.sensor_drop",
    }
    assert required <= ids
    scenario = load_scenario(ROOT / "blue_range/scenarios/network/horizontal_scan.yaml")
    result = execute_hunt("sql.network.horizontal_scan", scenario.events, {"min_destinations": 8})
    assert result["backend"] == "sqlite-fixture"
    assert result["rows"] and result["rows"][0]["destinations"] >= 8


@pytest.mark.polyglot
def test_yara_reports_engine_and_creates_evidence_shape() -> None:
    rule = (ROOT / "security-languages/yara/webshells/webshell_eval.yar").read_text(encoding="utf-8")
    bad = (ROOT / "security-languages/yara/corpus/known-malicious/webshell_sample.php.txt").read_bytes()
    match = scan_bytes(bad, rule)
    assert match is not None
    assert match.engine in {"libyara", "blueteam_yara.subset"}
    assert yara_engine() == match.engine or yara_engine() in {"libyara", "blueteam_yara.subset"}


@pytest.mark.polyglot
def test_policy_high_risk_requires_approval() -> None:
    result = evaluate(
        {
            "action": {"type": "isolate.host", "tier": 2, "read_only": False, "dry_run": False},
            "environment": "production",
            "confidence": 0.99,
            "auto_containment": True,
            "domain": "endpoint",
        }
    )
    assert result.decision == "REQUIRE_APPROVAL"
    assert result.engine in {"opa", "blueteam_rego.subset"}
    ai = evaluate({"action": {"type": "ai.contain", "tier": 0, "read_only": False}, "requested_by_ai": True})
    assert ai.decision == "DENY"
    broker = ExecutionBroker()
    isolation = broker.submit(
        ActionRequest.model_validate(
            {
                "action_id": "act_policy",
                "action_type": "isolate.host",
                "tenant_id": TENANT,
                "reason": "policy test",
                "requested_by": "analyst",
                "dry_run": False,
                "permissions": ["response:tier2"],
                "params": {"host_id": "ws-1", "environment": "production"},
            }
        )
    )
    assert isolation.policy_decision == "REQUIRE_APPROVAL"


@pytest.mark.polyglot
def test_office_c2_blue_range_and_storyline() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/endpoint/office_powershell_c2.yaml")
    result = run_scenario(scenario, build_default_registry())
    assert result.passed, result.errors or result.unexpected_rule_ids
    stories = correlate(scenario.events, result.findings)
    assert stories
    assert stories[0].evidence_ids
    assert "T1059.001" in stories[0].mitre_techniques


@pytest.mark.blue_range
def test_network_scan_blue_range() -> None:
    scenario = load_scenario(ROOT / "blue_range/scenarios/network/horizontal_scan.yaml")
    result = run_scenario(scenario, build_default_registry())
    assert result.passed, result.errors or result.unexpected_rule_ids


@pytest.mark.polyglot
def test_rego_engine_label() -> None:
    assert rego_engine() in {"opa", "blueteam_rego.subset"}
