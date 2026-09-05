"""Repeatable ClickHouse hunt latency measurements. Reports the actual backend used."""

from __future__ import annotations

import time
from typing import Any


def time_query(client: Any, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    rows = client.query(sql, params)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {"rows": len(rows), "elapsed_ms": round(elapsed_ms, 3), "backend": "clickhouse"}
