from __future__ import annotations

from datetime import timedelta

from blueteam_common.time import utcnow
from blueteam_dataplane.retention import RetentionPolicy, apply_retention
from blueteam_enrich.engine import enrich_event
from blueteam_ingest.syslog import parse_syslog_line
from blueteam_objects.store import open_store
from detections.lint import lint_rules
from fastapi.testclient import TestClient
from tests.conftest import auth_headers, login


def test_rule_lint_blocks_invalid_catalogue() -> None:
    assert lint_rules() == []


def test_health_reports_live_probes(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["data_plane"]["postgres"]["connected"] is True
    assert body["data_plane"]["postgres"]["backend"] in {"sqlite", "postgres"}
    assert isinstance(body["data_plane"]["redis"]["configured"], bool)
    assert "retention" in body
    assert body["retention"]["events_days"] >= 1


def test_syslog_and_webhook_ingest(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    syslog = client.post(
        "/api/v1/events/syslog",
        headers=headers,
        json={
            "lines": [
                "<34>1 2026-09-05T10:00:00Z sshd sshd - - - Failed password for alice from 203.0.113.77"
            ]
        },
    )
    assert syslog.status_code == 200, syslog.text
    assert syslog.json()["accepted"]

    webhook = client.post(
        "/api/v1/events/webhook",
        headers=headers,
        json={
            "source": "okta",
            "events": [
                {
                    "id": "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                    "tenant_id": demo_tenant,
                    "timestamp": "2026-09-05T10:01:00Z",
                    "ingested_at": "2026-09-05T10:01:01Z",
                    "source": "okta",
                    "source_type": "identity",
                    "event_type": "login",
                    "category": "authentication",
                    "outcome": "failure",
                    "src_ip": "203.0.113.77",
                    "user": {"name": "alice"},
                    "raw_event": {"user": "alice"},
                }
            ],
        },
    )
    assert webhook.status_code == 200, webhook.text
    assert webhook.json()["accepted"]

    events = client.get("/api/v1/events", headers=headers)
    assert any(item["source"] == "syslog" for item in events.json()["items"])


def test_enrichment_is_deterministic() -> None:
    event = parse_syslog_line(
        "<34>1 2026-09-05T10:00:00Z sshd sshd - - - Failed password for alice from 203.0.113.77",
        "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    enriched, result = enrich_event(event)
    assert "geoip" in result.applied
    assert result.geo["country"] == "ZZ"
    assert "identity" in result.applied
    assert enriched.identity is not None


def test_object_store_round_trip(tmp_path) -> None:
    store = open_store(root=tmp_path)
    ref = store.put("ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "raw/evt.json", b'{"ok":true}')
    assert store.get(ref.uri) == b'{"ok":true}'
    assert store.ping() is True


def test_suppression_blocks_duplicate_alert(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    suppress = client.post(
        "/api/v1/detections/suppressions",
        headers=headers,
        json={
            "rule_id": "identity.password_spray",
            "entity_key": "src_ip",
            "entity_value": "203.0.113.88",
            "reason": "known scanner exception for test",
        },
    )
    assert suppress.status_code == 200, suppress.text
    events = []
    for idx, user in enumerate(["a1", "a2", "a3", "a4", "a5", "a6"]):
        events.append(
            {
                "id": f"evt_{idx + 20:032x}",
                "tenant_id": demo_tenant,
                "timestamp": f"2026-09-05T11:0{idx}:00Z",
                "ingested_at": f"2026-09-05T11:0{idx}:01Z",
                "source": "azure-ad",
                "source_type": "identity",
                "event_type": "login",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "203.0.113.88",
                "action": "login",
                "user": {"name": user},
                "raw_event": {"user": user},
            }
        )
    ingest = client.post("/api/v1/events/ingest", headers=headers, json={"events": events})
    assert ingest.status_code == 200, ingest.text
    findings = client.get("/api/v1/detections/findings", headers=headers)
    assert not any(item["rule_id"] == "identity.password_spray" and "203.0.113.88" in item["explanation"] for item in findings.json()["items"])


def test_scheduled_rule_and_promotion(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    events = []
    for idx in range(8):
        events.append(
            {
                "id": f"evt_{idx + 40:032x}",
                "tenant_id": demo_tenant,
                "timestamp": f"2026-09-05T12:{idx:02d}:00Z",
                "ingested_at": f"2026-09-05T12:{idx:02d}:01Z",
                "source": "azure-ad",
                "source_type": "identity",
                "event_type": "login",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "198.51.100.20",
                "user": {"name": "alice"},
                "raw_event": {"user": "alice"},
            }
        )
    ingest = client.post("/api/v1/events/ingest", headers=headers, json={"events": events})
    assert ingest.status_code == 200
    scheduled = client.post("/api/v1/detections/scheduled/run", headers=headers)
    assert scheduled.status_code == 200, scheduled.text
    assert scheduled.json()["findings_created"] >= 1
    history = client.get("/api/v1/detections/rules/identity.password_spray/history", headers=headers)
    assert history.status_code == 200
    assert history.json()["items"]
    blocked = client.post("/api/v1/detections/rules/identity.password_spray/promote", headers=headers)
    assert blocked.status_code == 409
    dataset = client.post("/api/v1/replay/datasets", headers=headers, json={"name": "phase6-gate", "relative_path": "."})
    assert dataset.status_code == 200, dataset.text
    job = client.post("/api/v1/replay/jobs", headers=headers, json={"dataset_id": dataset.json()["dataset_id"], "mode": "current"})
    assert job.status_code == 200, job.text
    assert job.json()["passed"] is True
    promoted = client.post("/api/v1/detections/rules/identity.password_spray/promote", headers=headers)
    assert promoted.status_code == 200, promoted.text
    assert promoted.json()["status"] == "promoted"
    history2 = client.get("/api/v1/detections/rules/identity.password_spray/history", headers=headers)
    assert len(history2.json()["items"]) >= 2


def test_incident_grouping_from_storyline(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    users = ["u1", "u2", "u3", "u4", "u5", "u6"]
    events = []
    for idx, user in enumerate(users):
        events.append(
            {
                "id": f"evt_{idx + 60:032x}",
                "tenant_id": demo_tenant,
                "timestamp": f"2026-09-05T13:0{idx}:00Z",
                "ingested_at": f"2026-09-05T13:0{idx}:01Z",
                "source": "azure-ad",
                "source_type": "identity",
                "event_type": "login",
                "category": "authentication",
                "outcome": "failure",
                "src_ip": "203.0.113.91",
                "user": {"name": user},
                "raw_event": {"user": user},
            }
        )
    events.append(
        {
            "id": "evt_00000000000000000000000000000070",
            "schema_version": "1.0.0",
            "tenant_id": demo_tenant,
            "timestamp": "2026-09-05T13:10:00Z",
            "ingested_at": "2026-09-05T13:10:01Z",
            "source": "azure-ad",
            "source_type": "identity",
            "event_type": "role_assignment",
            "category": "identity",
            "outcome": "success",
            "action": "grant_role",
            "user": {"name": "u1"},
            "attributes": {"role": "Global Admin", "member": "u1"},
            "raw_event": {"role": "Global Admin"},
        }
    )
    first = client.post("/api/v1/events/ingest", headers=headers, json={"events": events})
    assert first.status_code == 200, first.text
    second = client.post("/api/v1/incidents/rebuild", headers=headers)
    assert second.status_code == 200
    incidents = client.get("/api/v1/incidents", headers=headers)
    assert incidents.status_code == 200
    items = incidents.json()["items"]
    assert items
    rebuilt = client.post("/api/v1/incidents/rebuild", headers=headers)
    after = client.get("/api/v1/incidents", headers=headers)
    assert len(after.json()["items"]) == len(items)
    assert rebuilt.json()["incidents"] == 0


def test_retention_deletes_expired_events(client: TestClient, demo_tenant: str) -> None:
    from app.core.db import get_session_factory
    from app.models.telemetry import SecurityEvent

    session = get_session_factory()()
    try:
        session.add(
            SecurityEvent(
                id="evt_00000000000000000000000000000099",
                tenant_id=demo_tenant,
                timestamp=utcnow() - timedelta(days=400),
                ingested_at=utcnow() - timedelta(days=400),
                source="retention-test",
                source_type="test",
                event_type="old",
                category="test",
                raw_hash="0" * 64,
                payload={"id": "evt_00000000000000000000000000000099", "tenant_id": demo_tenant},
            )
        )
        session.commit()
        deleted = apply_retention(session, demo_tenant, RetentionPolicy(events_days=90, dead_letter_days=30, findings_days=365))
        session.commit()
        assert deleted["events_deleted"] >= 1
    finally:
        session.close()


def test_cross_tenant_incidents_empty(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    other = "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    response = client.get("/api/v1/incidents", headers=auth_headers(token, other))
    assert response.status_code in {200, 403}
    if response.status_code == 200:
        assert response.json()["items"] == []
