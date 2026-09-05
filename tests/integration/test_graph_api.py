from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_ingest_projects_graph_and_isolates_tenants(client: TestClient, demo_tenant: str) -> None:
    detector = login(client, "detector@demo.blueteam.local")
    ingest = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers(detector, demo_tenant),
        json={
            "events": [
                {
                    "id": "evt_graph000000000000000000000000001",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T06:00:01Z",
                    "ingested_at": "2026-09-05T06:00:02Z",
                    "source": "azure-ad",
                    "source_type": "identity",
                    "event_type": "login",
                    "category": "authentication",
                    "src_ip": "203.0.113.44",
                    "outcome": "failure",
                    "user": {"name": "alice"},
                }
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    graph = client.get("/api/v1/graph", headers=auth_headers(detector, demo_tenant))
    assert graph.status_code == 200
    body = graph.json()
    assert body["manufactured_edges"] is False
    assert body["entities"]
    assert any(item["entity_type"] == "user" for item in body["entities"])
    assert any(item["entity_type"] == "ip" for item in body["entities"])
    assert body["relationships"]
    assert all(rel["event_ids"] for rel in body["relationships"])

    platform = login(client, "platform@blueteam.local")
    other = client.get(
        "/api/v1/graph",
        headers=auth_headers(platform, "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    assert other.status_code == 200
    assert other.json()["entities"] == []
    assert other.json()["relationships"] == []
