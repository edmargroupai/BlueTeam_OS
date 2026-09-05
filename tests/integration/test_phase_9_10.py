from __future__ import annotations

from fastapi.testclient import TestClient
from tests.conftest import auth_headers, login


def test_command_overview_includes_phase9_panels(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "analyst@demo.blueteam.local")
    response = client.get("/api/v1/command/overview", headers=auth_headers(token, demo_tenant))
    assert response.status_code == 200, response.text
    body = response.json()
    assert "telemetry_health" in body
    assert "detection_health" in body
    assert "attack_overview" in body
    assert "automation_queue" in body
    assert "top_incidents" in body
    assert body["ai_required"] is False


def test_alert_converts_to_incident_with_timeline(client: TestClient, demo_tenant: str) -> None:
    detector = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(detector, demo_tenant)
    events = []
    for idx, user in enumerate(["a1", "a2", "a3", "a4", "a5", "a6"]):
        events.append(
            {
                "id": f"evt_{idx + 80:032x}",
                "tenant_id": demo_tenant,
                "timestamp": f"2026-09-05T14:0{idx}:00Z",
                "ingested_at": f"2026-09-05T14:0{idx}:01Z",
                "source": "azure-ad",
                "source_type": "identity",
                "event_type": "login",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "203.0.113.44",
                "user": {"name": user},
                "raw_event": {"user": user},
            }
        )
    ingest = client.post("/api/v1/events/ingest", headers=headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text
    alerts = client.get("/api/v1/alerts", headers=headers)
    assert alerts.status_code == 200
    open_alerts = [item for item in alerts.json()["items"] if item["status"] == "open"]
    assert open_alerts, "expected detection to create an open alert"
    alert_id = open_alerts[0]["id"]
    created = client.post("/api/v1/incidents/from-alert", headers=headers, json={"alert_id": alert_id})
    assert created.status_code == 200, created.text
    incident = created.json()
    assert incident["source_alert_id"] == alert_id
    assert incident["status"] == "new"
    assert incident["timeline"]

    assigned = client.post(
        f"/api/v1/incidents/{incident['id']}/assign",
        headers=headers,
        json={"assignee_user_id": "usr_test", "assignee_email": "analyst@demo.blueteam.local"},
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["assignee_email"] == "analyst@demo.blueteam.local"

    noted = client.post(
        f"/api/v1/incidents/{incident['id']}/notes",
        headers=headers,
        json={"body": "Confirmed spray from scanner IP"},
    )
    assert noted.status_code == 200
    assert any(n["body"].startswith("Confirmed") for n in noted.json()["notes"])

    tasked = client.post(
        f"/api/v1/incidents/{incident['id']}/tasks",
        headers=headers,
        json={"title": "Block source IP at edge"},
    )
    assert tasked.status_code == 200
    assert tasked.json()["tasks"]

    status = client.post(
        f"/api/v1/incidents/{incident['id']}/status",
        headers=headers,
        json={"status": "investigating"},
    )
    assert status.status_code == 200
    assert status.json()["status"] == "investigating"
    assert len(status.json()["timeline"]) >= 3

    detail = client.get(f"/api/v1/incidents/{incident['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["id"] == incident["id"]
