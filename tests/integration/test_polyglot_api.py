from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login


def test_blueql_and_sql_hunts(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "hunter@demo.blueteam.local")
    headers = auth_headers(token, demo_tenant)
    dry = client.post(
        "/api/v1/hunts/blueql",
        headers=headers,
        json={"query": 'process.name = "powershell.exe"', "dry_run": True},
    )
    assert dry.status_code == 200, dry.text
    assert dry.json()["explain"]["sql_concatenation"] is False
    injected = client.post(
        "/api/v1/hunts/blueql",
        headers=headers,
        json={"query": "process.name = 1; DROP TABLE events"},
    )
    assert injected.status_code == 422
    sql = client.post(
        "/api/v1/hunts/sql",
        headers=headers,
        json={"query_id": "sql.identity.password_spray", "params": {"min_users": 5}},
    )
    assert sql.status_code == 200


def test_broker_forbids_raw_shell(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "owner@demo.blueteam.local")
    response = client.post(
        "/api/v1/broker/actions",
        headers=auth_headers(token, demo_tenant),
        json={"action_type": "powershell.invoke_raw", "reason": "test", "params": {"cmd": "Get-Process"}},
    )
    assert response.status_code == 403


def test_languages_catalogue(client: TestClient, demo_tenant: str) -> None:
    token = login(client, "analyst@demo.blueteam.local")
    response = client.get("/api/v1/languages", headers=auth_headers(token, demo_tenant))
    assert response.status_code == 200
    body = response.json()
    assert body["generic_shell"] is False
    assert body["ai_executes_os_commands"] is False
    assert body["python_orchestrates"] is True
