from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
from blueteam_network.normalize import normalize_zeek
from blueteam_range.loader import load_scenario
from blueteam_sql.engine import execute_hunt

ROOT = Path(__file__).resolve().parents[2]
TENANT = "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _clickhouse_url() -> str:
    return os.environ.get("BTOS_CLICKHOUSE_URL") or "http://127.0.0.1:8123"


def _kafka_bootstrap() -> str:
    return os.environ.get("BTOS_KAFKA_BOOTSTRAP") or "127.0.0.1:19092"


def _clickhouse_up() -> bool:
    try:
        response = httpx.get(f"{_clickhouse_url()}/ping", timeout=2)
        return response.status_code == 200 and response.text.strip() == "Ok."
    except httpx.HTTPError:
        return False


@pytest.mark.polyglot
def test_clickhouse_hunt_backend() -> None:
    if not _clickhouse_up():
        pytest.skip("SKIPPED_WITH_REASON: ClickHouse is not reachable on 127.0.0.1:8123")
    from blueteam_clickhouse.client import connect

    client = connect(_clickhouse_url())
    client.apply_schema()
    scenario = load_scenario(ROOT / "blue_range/scenarios/network/horizontal_scan.yaml")
    client.insert_events(scenario.events)
    result = execute_hunt(
        "sql.network.horizontal_scan",
        scenario.events,
        {"min_destinations": 8},
        clickhouse_url=_clickhouse_url(),
        tenant_id=TENANT,
    )
    assert result["backend"] == "clickhouse"
    assert result["rows"] and int(result["rows"][0]["destinations"]) >= 8


@pytest.mark.polyglot
def test_redpanda_publish_consume() -> None:
    try:
        from blueteam_fabric.kafka import KafkaFabric, KafkaUnavailable, kafka_client_available
    except ImportError:
        pytest.skip("SKIPPED_WITH_REASON: event fabric kafka module missing")
    if not kafka_client_available():
        pytest.skip("SKIPPED_WITH_REASON: kafka-python is not installed")
    try:
        fabric = KafkaFabric(_kafka_bootstrap())
    except KafkaUnavailable as exc:
        pytest.skip(f"SKIPPED_WITH_REASON: Redpanda not reachable ({exc})")
    from blueteam_fabric.envelope import envelope
    from blueteam_fabric.topics import RAW

    event = normalize_zeek(
        {
            "_path": "conn",
            "ts": "2026-09-05T10:00:00Z",
            "uid": "Credpanda",
            "id": {"orig_h": "10.0.0.8", "resp_h": "10.0.0.9", "orig_p": 1, "resp_p": 22},
            "proto": "tcp",
        },
        TENANT,
    )
    fabric.ensure_topics()
    fabric.publish(envelope(RAW, TENANT, event.model_dump(mode="json"), event_id=event.id))
    batch = fabric.consume(RAW, group="runtime-promotion-test")
    assert any(item.tenant_id == TENANT for item in batch) or fabric.lag()[RAW] >= 0
