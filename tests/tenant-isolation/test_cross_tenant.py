from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


@pytest.mark.tenant_isolation
def test_analyst_cannot_select_foreign_tenant(client: TestClient, platform_tenant: str) -> None:
    token = login(client, "analyst@demo.blueteam.local")
    response = client.get("/api/v1/events", headers=auth_headers(token, platform_tenant))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "PERMISSION_DENIED"


@pytest.mark.tenant_isolation
def test_events_are_not_visible_across_tenants(client: TestClient, demo_tenant: str) -> None:
    detector = login(client, "detector@demo.blueteam.local")
    ingest = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers(detector, demo_tenant),
        json={
            "events": [
                {
                    "id": "evt_cccccccccccccccccccccccccccccccc",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T10:00:00Z",
                    "ingested_at": "2026-09-05T10:00:01Z",
                    "source": "test",
                    "source_type": "fixture",
                    "event_type": "login",
                    "category": "authentication",
                    "outcome": "failure",
                    "src_ip": "198.51.100.10",
                    "user": {"name": "alice"},
                }
            ]
        },
    )
    assert ingest.status_code == 200
    assert ingest.json()["accepted"]

    platform = login(client, "platform@blueteam.local")
    other = client.get(
        "/api/v1/events",
        headers=auth_headers(platform, "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    assert other.status_code == 200
    assert other.json()["items"] == []


@pytest.mark.tenant_isolation
def test_read_only_cannot_ingest(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "auditor@demo.blueteam.local")
    response = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers(token, demo_tenant),
        json={"events": [{"source": "x"}]},
    )
    assert response.status_code == 403
