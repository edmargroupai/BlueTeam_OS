from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_attack_coverage_shape(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    catalogue = client.get("/api/v1/attack/catalogue", headers=headers)
    assert catalogue.status_code == 200, catalogue.text
    assert len(catalogue.json()["items"]) >= 10

    coverage = client.get("/api/v1/attack/coverage", headers=headers)
    assert coverage.status_code == 200, coverage.text
    body = coverage.json()
    assert "summary" in body
    assert body["summary"]["technique_count"] >= 10
    tech = body["techniques"][0]
    for key in (
        "technique_id",
        "detections",
        "telemetry_sources",
        "validated",
        "coverage_score",
        "gap_severity",
        "gaps",
    ):
        assert key in tech

    detail = client.get(f"/api/v1/attack/techniques/{tech['technique_id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["technique_id"] == tech["technique_id"]


def test_wazuh_connector_denies_high_impact(client: TestClient, demo_tenant: str) -> None:
    owner = login(client, "owner@demo.blueteam.local")
    headers = auth_headers(owner, demo_tenant)
    ingest = client.post(
        "/api/v1/connectors/wazuh/ingest",
        headers=headers,
        json={
            "alerts": [
                {
                    "agent": {"id": "001", "name": "win-lab-01"},
                    "rule": {"id": "5710", "level": 10, "description": "sshd: attempt to login"},
                    "data": {
                        "event_type": "process_creation",
                        "category": "process",
                        "process_name": "powershell.exe",
                        "command_line": "powershell -enc AA==",
                        "user": "alice",
                    },
                    "timestamp": "2026-09-05T16:00:00Z",
                }
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    assert len(ingest.json()["accepted"]) >= 1

    health = client.get("/api/v1/connectors/wazuh/health", headers=headers)
    assert health.status_code == 200
    assert health.json()["agents_total"] >= 1

    inventory = client.get("/api/v1/connectors/wazuh/inventory", headers=headers)
    assert inventory.status_code == 200
    assert inventory.json()["count"] >= 1

    denied = client.post(
        "/api/v1/connectors/wazuh/actions",
        headers=headers,
        json={"action": "isolate_host", "agent_id": "001", "dry_run": True},
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["status"] == "denied"
    assert denied.json()["policy"] == "REQUIRE_POLICY_ENGINE"

    planned = client.post(
        "/api/v1/connectors/wazuh/actions",
        headers=headers,
        json={"action": "collect_processes", "agent_id": "001", "dry_run": True},
    )
    assert planned.status_code == 200
    assert planned.json()["status"] == "planned"


def test_zeek_suricata_sessions_and_cross_source(client: TestClient, demo_tenant: str) -> None:
    hunter = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(hunter, demo_tenant)

    wazuh = client.post(
        "/api/v1/connectors/wazuh/ingest",
        headers=headers,
        json={
            "alerts": [
                {
                    "agent": {"id": "002", "name": "win-lab-02"},
                    "rule": {"id": "1002", "level": 8, "description": "network"},
                    "data": {
                        "event_type": "network",
                        "category": "network",
                        "process_name": "chrome.exe",
                        "user": "bob",
                    },
                    "timestamp": "2026-09-05T16:05:00Z",
                    "data_src_ip": "10.0.0.50",
                }
            ]
        },
    )
    # Ensure endpoint event carries an IP that network events also use.
    assert wazuh.status_code == 200, wazuh.text

    # Patch: ingest canonical endpoint+network with shared IP via events API for join certainty.
    endpoint = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "id": "evt_0000000000000000000000000000ep01",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T16:05:00Z",
                    "ingested_at": "2026-09-05T16:05:01Z",
                    "source": "wazuh",
                    "source_type": "endpoint",
                    "event_type": "network",
                    "category": "network",
                    "src_ip": "10.0.0.50",
                    "dst_ip": "198.51.100.20",
                    "host": {"name": "win-lab-02", "id": "002", "ip": "10.0.0.50"},
                    "raw_event": {"agent": "002"},
                }
            ]
        },
    )
    assert endpoint.status_code == 200, endpoint.text

    network = client.post(
        "/api/v1/connectors/network/ingest",
        headers=headers,
        json={
            "source": "zeek",
            "events": [
                {
                    "_path": "dns",
                    "ts": "2026-09-05T16:05:02Z",
                    "uid": "Czeekdns001",
                    "id.orig_h": "10.0.0.50",
                    "id.resp_h": "8.8.8.8",
                    "id.orig_p": 5353,
                    "id.resp_p": 53,
                    "proto": "udp",
                    "query": "evil.example",
                },
                {
                    "_path": "http",
                    "ts": "2026-09-05T16:05:03Z",
                    "uid": "Czeekhttp001",
                    "id.orig_h": "10.0.0.50",
                    "id.resp_h": "198.51.100.20",
                    "id.orig_p": 49152,
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "method": "GET",
                    "host": "evil.example",
                    "uri": "/payload",
                },
                {
                    "_path": "ssl",
                    "ts": "2026-09-05T16:05:04Z",
                    "uid": "Czeektls001",
                    "id.orig_h": "10.0.0.50",
                    "id.resp_h": "198.51.100.20",
                    "id.orig_p": 49153,
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "server_name": "evil.example",
                },
            ],
        },
    )
    assert network.status_code == 200, network.text
    assert network.json()["normalized"] == 3

    suricata = client.post(
        "/api/v1/connectors/network/ingest",
        headers=headers,
        json={
            "source": "suricata",
            "events": [
                {
                    "event_type": "alert",
                    "timestamp": "2026-09-05T16:05:05Z",
                    "flow_id": 9001,
                    "src_ip": "10.0.0.50",
                    "dest_ip": "198.51.100.20",
                    "src_port": 49154,
                    "dest_port": 443,
                    "proto": "TCP",
                    "alert": {"signature": "ET MALWARE C2", "signature_id": 2010001, "severity": 1},
                }
            ],
        },
    )
    assert suricata.status_code == 200, suricata.text

    sessions = client.get("/api/v1/connectors/network/sessions", headers=headers)
    assert sessions.status_code == 200, sessions.text
    body = sessions.json()
    assert body["count"] >= 1
    assert body["dns"] >= 1
    assert body["http"] >= 1
    assert body["tls"] >= 1
    assert body["ids_alerts"] >= 1

    corr = client.get("/api/v1/connectors/network/correlate", headers=headers)
    assert corr.status_code == 200, corr.text
    assert corr.json()["count"] >= 1
    assert len(corr.json()["ip_joins"]) >= 1
