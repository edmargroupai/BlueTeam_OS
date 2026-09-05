from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_replay_gates_promotion(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    blocked = client.post("/api/v1/detections/rules/identity.brute_force/promote", headers=headers)
    assert blocked.status_code == 409
    dataset = client.post(
        "/api/v1/replay/datasets",
        headers=headers,
        json={"name": "full-range", "relative_path": "."},
    )
    assert dataset.status_code == 200, dataset.text
    job = client.post(
        "/api/v1/replay/jobs",
        headers=headers,
        json={"dataset_id": dataset.json()["dataset_id"], "mode": "current"},
    )
    assert job.status_code == 200, job.text
    assert job.json()["passed"] is True
    assert "identity.password_spray" in job.json()["rule_ids"]


def test_improve_and_ai_offline(client: TestClient, demo_tenant: str) -> None:
    detector = login(client, "detector@demo.blueteam.local")
    headers = auth_headers(detector, demo_tenant)
    analytics = client.get("/api/v1/improve/analytics", headers=headers)
    assert analytics.status_code == 200
    created = client.post(
        "/api/v1/improve/candidates",
        headers=headers,
        json={"rule_id": "identity.password_spray", "rationale": "reduce FP", "ai_suggested": True},
    )
    assert created.status_code == 200
    assert created.json()["may_auto_promote"] is False

    analyst = login(client, "analyst@demo.blueteam.local")
    aheaders = auth_headers(analyst, demo_tenant)
    ai = client.post(
        "/api/v1/ai/analyst",
        headers=aheaders,
        json={"task": "incident_summary", "question": "Summarise", "evidence_ids": []},
    )
    assert ai.status_code == 200
    assert ai.json()["decision"] == "deterministic_only"
    assert ai.json()["result"]["fabricated"] is False


def test_dfir_architecture_readiness_observability(client: TestClient, demo_tenant: str) -> None:
    owner = login(client, "owner@demo.blueteam.local")
    headers = auth_headers(owner, demo_tenant)
    seed = client.post("/api/v1/architecture/seed", headers=headers)
    assert seed.status_code == 200
    gaps = client.get("/api/v1/architecture/gaps", headers=headers)
    assert gaps.status_code == 200
    dfir = client.get("/api/v1/dfir/timeline/host", headers=headers)
    assert dfir.status_code == 200
    export = client.post("/api/v1/dfir/export", headers=headers)
    assert export.status_code == 200
    assert "manifest_hash" in export.json()
    metrics = client.get("/api/v1/observability/metrics", headers=headers)
    assert metrics.status_code == 200
    assert "btos_info" in metrics.text
    gate = client.get("/api/v1/readiness/gate", headers=headers)
    assert gate.status_code == 200
    assert "required_checks" in gate.json()


def test_autopilot_playbook(client: TestClient, demo_tenant: str) -> None:
    owner = login(client, "owner@demo.blueteam.local")
    headers = auth_headers(owner, demo_tenant)
    run = client.post(
        "/api/v1/playbooks/run",
        headers=headers,
        json={"playbook_id": "pb.autopilot_investigate", "dry_run": True, "idempotency_key": "auto-1"},
    )
    assert run.status_code == 200, run.text
    assert run.json()["status"] == "completed"
