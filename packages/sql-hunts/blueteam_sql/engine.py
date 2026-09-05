"""Registered, parameterized hunts. Callers cannot supply raw SQL."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import yaml
from blueteam_schemas.events import CanonicalEvent

REPO_ROOT = Path(__file__).resolve().parents[3]
HUNT_ROOT = REPO_ROOT / "security-languages" / "sql"
FORBIDDEN = ("insert ", "update ", "delete ", "drop ", "attach ", "pragma ", "alter ", "truncate ")


def list_hunts() -> list[dict[str, Any]]:
    hunts = []
    for path in sorted(HUNT_ROOT.rglob("*.yaml")):
        hunts.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return hunts


def describe(query_id: str) -> dict[str, Any]:
    for hunt in list_hunts():
        if hunt.get("id") == query_id:
            return hunt
    raise ValueError(f"unknown SQL hunt {query_id}")


def _validate_sql(sql: str) -> str:
    if ";" in sql.strip().rstrip(";"):
        raise ValueError("multiple statements are forbidden")
    lowered = sql.lower()
    if any(token in lowered for token in FORBIDDEN):
        raise ValueError("mutating SQL is forbidden")
    return sql


def _bound_params(hunt: dict[str, Any], params: dict[str, Any] | None) -> dict[str, Any]:
    allowed = set(hunt.get("parameters") or [])
    incoming = params or {}
    extra = set(incoming) - allowed
    if extra:
        raise ValueError(f"undeclared parameters: {sorted(extra)}")
    return {key: incoming.get(key, hunt.get("defaults", {}).get(key)) for key in allowed}


def execute_hunt(
    query_id: str,
    events: list[CanonicalEvent],
    params: dict[str, Any] | None = None,
    *,
    clickhouse_url: str = "",
    tenant_id: str = "",
) -> dict[str, Any]:
    hunt = describe(query_id)
    bound = _bound_params(hunt, params)
    if tenant_id:
        bound = {**bound, "tenant_id": tenant_id}
    elif events:
        bound = {**bound, "tenant_id": events[0].tenant_id}
    if clickhouse_url:
        try:
            rows, backend = _execute_clickhouse(hunt, bound, clickhouse_url)
            return {"query_id": query_id, "backend": backend, "rows": rows}
        except Exception:
            # Fall through to the registered sqlite fixture backend.
            pass
    rows = _execute_sqlite(hunt, events, bound)
    return {"query_id": query_id, "backend": "sqlite-fixture", "rows": rows}


def _execute_clickhouse(hunt: dict[str, Any], bound: dict[str, Any], url: str) -> tuple[list[dict[str, Any]], str]:
    from blueteam_clickhouse.client import connect

    sql = _validate_sql(hunt.get("clickhouse_sql") or hunt["sql"])
    # Named :params are sqlite. ClickHouse hunts must use {name:Type}.
    if ":" in sql and "{" not in sql:
        raise ValueError("ClickHouse hunt requires clickhouse_sql with {param:Type} bindings")
    client = connect(url)
    return client.query(sql, bound), "clickhouse"


def _execute_sqlite(hunt: dict[str, Any], events: list[CanonicalEvent], bound: dict[str, Any]) -> list[dict[str, Any]]:
    sql = _validate_sql(hunt["sql"])
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE events (
            id TEXT, tenant_id TEXT, timestamp TEXT, ingested_at TEXT,
            source TEXT, source_type TEXT, event_type TEXT, category TEXT,
            host_id TEXT, user_id TEXT, src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER, protocol TEXT,
            process_name TEXT, parent_process_name TEXT, command_line TEXT,
            domain TEXT, url TEXT, file_path TEXT, file_hash TEXT,
            action TEXT, outcome TEXT, severity TEXT, confidence REAL,
            schema_version TEXT, user_name TEXT
        )
        """
    )
    for event in events:
        conn.execute(
            """
            INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event.id,
                event.tenant_id,
                event.timestamp.isoformat(),
                event.ingested_at.isoformat(),
                event.source,
                event.source_type,
                event.event_type,
                event.category,
                event.host.id if event.host else None,
                event.user.id if event.user else None,
                event.src_ip,
                event.dst_ip,
                event.src_port,
                event.dst_port,
                event.protocol,
                event.process.name if event.process else None,
                event.parent_process.name if event.parent_process else None,
                event.process.command_line if event.process else None,
                event.domain,
                event.url,
                event.file.path if event.file else None,
                event.hash or (event.file.hash_sha256 if event.file else None),
                event.action,
                event.outcome,
                event.severity,
                event.confidence,
                event.schema_version,
                event.user.name if event.user else None,
            ),
        )
    rows = conn.execute(sql, bound).fetchall()
    return [dict(row) for row in rows]
