from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_identity_rules_registered(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    catalogue = client.get("/api/v1/detections", headers=headers)
    assert catalogue.status_code == 200
    ids = {item["rule_id"] for item in catalogue.json()["items"]}
    for rule_id in (
        "identity.password_spray",
        "identity.brute_force",
        "identity.privilege_grant",
        "identity.repeated_failures",
        "identity.unusual_success",
        "identity.impossible_travel",
        "identity.mfa_fatigue",
        "identity.dormant_account",
        "identity.service_account_misuse",
    ):
        assert rule_id in ids


def test_azure_cloud_connector(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    ingest = client.post(
        "/api/v1/connectors/cloud/azure/ingest",
        headers=headers,
        json={
            "events": [
                {
                    "id": "evt_azure00000000000000000000000001",
                    "activityDisplayName": "Add member to role",
                    "activityDateTime": "2026-09-05T17:00:00Z",
                    "initiatedBy": {"user": {"userPrincipalName": "alice"}},
                    "ipAddress": "203.0.113.10",
                    "privileged": True,
                    "targetResources": [{"displayName": "Global Administrator", "id": "role-ga"}],
                }
            ]
        },
    )
    assert ingest.status_code == 200, ingest.text
    assert len(ingest.json()["accepted"]) >= 1
    inventory = client.get("/api/v1/connectors/cloud/azure/inventory", headers=headers)
    assert inventory.status_code == 200
    body = inventory.json()
    assert body["risky_configs"]
    assert body["public_exposure"]


def test_vuln_import_priority(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    imported = client.post(
        "/api/v1/vulns/import",
        headers=headers,
        json={
            "findings": [
                {
                    "cve_id": "CVE-2024-9999",
                    "title": "Critical lab CVE",
                    "cvss": 9.8,
                    "exploitability": 90,
                    "asset_id": "dc-01",
                    "asset_criticality": 95,
                    "threat_activity": 80,
                    "scanner": "unit",
                }
            ]
        },
    )
    assert imported.status_code == 200, imported.text
    item = imported.json()["items"][0]
    assert item["priority"] >= 80
    assert item["sla_days"] == 7
    assert "0.40" in item["formula"]
    listed = client.get("/api/v1/vulns", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["count"] >= 1


def test_telemetry_health_warns_on_missing_sources(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "analyst@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    health = client.get("/api/v1/telemetry/health", headers=headers)
    assert health.status_code == 200, health.text
    body = health.json()
    assert body["status"] in {"warn", "degraded", "healthy"}
    assert "warnings" in body
    # Empty tenant should warn about missing expected sources.
    assert any(item["kind"] == "silent_sensor" for item in body["warnings"])


def test_playbook_dag_and_approval_gate(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "owner@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    listed = client.get("/api/v1/playbooks", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["count"] >= 2

    dry = client.post(
        "/api/v1/playbooks/run",
        headers=headers,
        json={"playbook_id": "pb.enrich_only", "dry_run": True, "idempotency_key": "t-enrich"},
    )
    assert dry.status_code == 200, dry.text
    assert dry.json()["status"] == "completed"

    gated = client.post(
        "/api/v1/playbooks/run",
        headers=headers,
        json={"playbook_id": "pb.contain_host_t0", "dry_run": False, "idempotency_key": "t-contain"},
    )
    assert gated.status_code == 200, gated.text
    body = gated.json()
    assert body["status"] == "awaiting_approval"
    assert "isolate" in body["approval_required"]
    assert any(step.get("rollback_hook") == "release.host" for step in body["steps"])
