from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_password_spray_ingest_creates_finding_and_evidence(
    client: TestClient, demo_tenant: str
) -> None:
    token = login(client, "detector@demo.blueteam.local")
    events = []
    users = ["alice", "bob", "carol", "dave", "erin", "frank"]
    for idx, user in enumerate(users):
        events.append(
            {
                "id": f"evt_{idx:032x}",
                "tenant_id": demo_tenant,
                "timestamp": f"2026-09-05T09:0{idx}:00Z",
                "ingested_at": f"2026-09-05T09:0{idx}:01Z",
                "source": "azure-ad",
                "source_type": "identity",
                "event_type": "login",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "203.0.113.77",
                "action": "login",
                "user": {"name": user},
                "raw_event": {"user": user},
            }
        )
    ingest = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers(token, demo_tenant),
        json={"events": events},
    )
    assert ingest.status_code == 200, ingest.text
    assert ingest.json()["findings_created"] >= 1

    findings = client.get("/api/v1/detections/findings", headers=auth_headers(token, demo_tenant))
    assert findings.status_code == 200
    items = findings.json()["items"]
    assert any(item["rule_id"] == "identity.password_spray" for item in items)
    spray = next(item for item in items if item["rule_id"] == "identity.password_spray")
    assert spray["evidence_ids"]
    assert spray["event_ids"]

    evidence = client.get("/api/v1/evidence", headers=auth_headers(token, demo_tenant))
    assert evidence.status_code == 200
    assert evidence.json()["items"]
    first = evidence.json()["items"][0]
    verify = client.get(
        f"/api/v1/evidence/{first['id']}/verify",
        headers=auth_headers(token, demo_tenant),
    )
    assert verify.status_code == 200
    assert verify.json()["intact"] is True

    quality = client.get("/api/v1/quality/index", headers=auth_headers(token, demo_tenant))
    assert quality.status_code == 200
    body = quality.json()
    assert body["editable"] is False
    assert body["band"] == "prototype"
    assert body["total"] < 925
    assert body["domains"]["identity_security"] >= 50
