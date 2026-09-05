from __future__ import annotations

from datetime import timedelta

from blueteam_common.time import utcnow
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_structured_hunt_and_saved_is_audited(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    ingest = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "id": "evt_000000000000000000000000000000a1",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T15:00:00Z",
                    "ingested_at": "2026-09-05T15:00:01Z",
                    "source": "zeek",
                    "source_type": "network",
                    "event_type": "conn",
                    "category": "network",
                    "src_ip": "203.0.113.50",
                    "dst_ip": "198.51.100.10",
                    "raw_event": {"src": "203.0.113.50"},
                }
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    hunt = client.post(
        "/api/v1/hunts/structured",
        headers=headers,
        json={"src_ip": "203.0.113.50", "limit": 20},
    )
    assert hunt.status_code == 200, hunt.text
    assert hunt.json()["count"] >= 1
    saved = client.post(
        "/api/v1/hunts/saved",
        headers=headers,
        json={"name": "spray src", "hunt_type": "structured", "query": {"src_ip": "203.0.113.50"}},
    )
    assert saved.status_code == 200, saved.text
    listed = client.get("/api/v1/hunts/saved", headers=headers)
    assert any(item["name"] == "spray src" for item in listed.json()["items"])
    exported = client.post(
        "/api/v1/hunts/export",
        headers=headers,
        json={"format": "json", "items": hunt.json()["items"]},
    )
    assert exported.status_code == 200
    assert exported.json()["count"] >= 1


def test_ioc_enriches_ingest_and_expires(client: TestClient, demo_tenant: str) -> None:
    hunter = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(hunter, demo_tenant)
    created = client.post(
        "/api/v1/intel/iocs",
        headers=headers,
        json={
            "indicator_type": "ip",
            "value": "198.51.100.44",
            "source": "lab-feed",
            "confidence": 0.95,
            "ttl_hours": 24,
            "actor": "lab-actor",
            "mitre_techniques": ["T1071"],
            "provenance": {"feed": "unit-test"},
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["active"] is True
    assert created.json()["provenance"]["feed"] == "unit-test"

    ingest = client.post(
        "/api/v1/events/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "id": "evt_000000000000000000000000000000a2",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T15:10:00Z",
                    "ingested_at": "2026-09-05T15:10:01Z",
                    "source": "firewall",
                    "source_type": "network",
                    "event_type": "deny",
                    "category": "network",
                    "src_ip": "198.51.100.44",
                    "raw_event": {"src": "198.51.100.44"},
                }
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    from app.core.db import get_session_factory
    from app.models.telemetry import SecurityEvent

    session = get_session_factory()()
    try:
        stored = session.get(SecurityEvent, "evt_000000000000000000000000000000a2")
        assert stored is not None
        assert stored.payload["attributes"]["intel"]["ioc_id"] == created.json()["id"]
    finally:
        session.close()

    iocs = client.get("/api/v1/intel/iocs", headers=headers)
    assert iocs.status_code == 200
    row = next(item for item in iocs.json()["items"] if item["id"] == created.json()["id"])
    assert row["sightings"] >= 1

    from app.models.intel import IndicatorOfCompromise

    session = get_session_factory()()
    try:
        ioc = session.get(IndicatorOfCompromise, created.json()["id"])
        assert ioc is not None
        ioc.expires_at = utcnow() - timedelta(hours=1)
        session.commit()
    finally:
        session.close()

    expired = client.post("/api/v1/intel/expire", headers=headers)
    assert expired.status_code == 200
    assert expired.json()["expired"] >= 1
    after = client.get("/api/v1/intel/iocs?include_expired=true", headers=headers)
    stale = next(item for item in after.json()["items"] if item["id"] == created.json()["id"])
    assert stale["active"] is False or stale["expired"] is True
