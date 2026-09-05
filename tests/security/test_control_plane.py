from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


@pytest.mark.security
def test_health_does_not_require_ai(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["ai_required"] is False
    assert body["ai_enabled"] is False


@pytest.mark.security
def test_login_audit_and_me(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "owner@demo.blueteam.local")
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "owner@demo.blueteam.local"
    audit = client.get("/api/v1/audit", headers=auth_headers(token, demo_tenant))
    assert audit.status_code == 200
    actions = {item["action"] for item in audit.json()["items"]}
    assert "auth.login" in actions
    integrity = client.get("/api/v1/audit/integrity", headers=auth_headers(token, demo_tenant))
    assert integrity.status_code == 200
    assert integrity.json()["intact"] is True


@pytest.mark.security
def test_invalid_login_is_denied(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@demo.blueteam.local", "password": "wrong-password"},
    )
    assert response.status_code == 401


@pytest.mark.security
def test_unauthenticated_events_fail(client: TestClient) -> None:
    response = client.get("/api/v1/events")
    assert response.status_code == 401


@pytest.mark.security
def test_invalid_event_goes_to_dead_letter(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    response = client.post(
        "/api/v1/events/ingest",
        headers=auth_headers(token, demo_tenant),
        json={"events": [{"tenant_id": "not-a-tenant", "schema_version": "1.0.0", "id": "x"}]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["rejected"]
    dlq = client.get("/api/v1/events/dead-letter", headers=auth_headers(token, demo_tenant))
    assert dlq.status_code == 200
    assert dlq.json()["items"]


@pytest.mark.security
def test_claim_with_unknown_evidence_is_rejected(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "analyst@demo.blueteam.local")
    response = client.post(
        "/api/v1/evidence/claims/validate",
        headers=auth_headers(token, demo_tenant),
        json={
            "claim_text": "Host is compromised",
            "confidence": 90,
            "supporting_evidence_ids": ["evi_ffffffffffffffffffffffffffffffff"],
            "inference_type": 4,
            "model_or_rule_version": "llm-test",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_EVIDENCE_REF"
