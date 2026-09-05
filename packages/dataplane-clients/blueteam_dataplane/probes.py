"""Live connectivity probes. Unconfigured stays unconfigured. Failures are reported, not invented."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _result(name: str, configured: bool, connected: bool, *, backend: str = "", detail: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "configured": configured,
        "connected": connected,
        "backend": backend,
        "detail": detail,
    }


def probe_postgres(url: str) -> dict[str, Any]:
    if not url:
        return _result("postgres", False, False, detail="database url empty")
    backend = "sqlite" if url.startswith("sqlite") else "postgresql"
    try:
        from sqlalchemy import create_engine, text

        kwargs: dict[str, Any] = {"future": True}
        if url.startswith("sqlite"):
            from sqlalchemy.pool import StaticPool

            kwargs["connect_args"] = {"check_same_thread": False}
            if url.endswith(":memory:"):
                kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return _result("postgres", True, True, backend=backend)
    except Exception as exc:
        return _result("postgres", True, False, backend=backend, detail=type(exc).__name__)


def probe_redis(url: str) -> dict[str, Any]:
    if not url:
        return _result("redis", False, False)
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 6379
    try:
        import socket

        sock = socket.create_connection((host, port), timeout=2)
        try:
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            reply = sock.recv(16)
        finally:
            sock.close()
        ok = reply.startswith(b"+PONG") or b"PONG" in reply
        return _result("redis", True, ok, backend="redis", detail="" if ok else "no pong")
    except Exception as exc:
        return _result("redis", True, False, backend="redis", detail=type(exc).__name__)


def probe_clickhouse(url: str) -> dict[str, Any]:
    if not url:
        return _result("clickhouse", False, False)
    try:
        import httpx

        ping = url.rstrip("/") + "/ping"
        response = httpx.get(ping, timeout=3.0)
        return _result("clickhouse", True, response.status_code == 200, backend="clickhouse")
    except Exception as exc:
        return _result("clickhouse", True, False, backend="clickhouse", detail=type(exc).__name__)


def probe_opensearch(url: str) -> dict[str, Any]:
    if not url:
        return _result("opensearch", False, False)
    try:
        import httpx

        response = httpx.get(url.rstrip("/"), timeout=3.0)
        return _result("opensearch", True, response.status_code < 500, backend="opensearch")
    except Exception as exc:
        return _result("opensearch", True, False, backend="opensearch", detail=type(exc).__name__)


def probe_kafka(bootstrap: str) -> dict[str, Any]:
    if not bootstrap:
        return _result("kafka", False, False)
    host, _, port_text = bootstrap.partition(":")
    port = int(port_text or "9092")
    try:
        import socket

        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return _result("kafka", True, True, backend="redpanda")
    except Exception as exc:
        return _result("kafka", True, False, backend="redpanda", detail=type(exc).__name__)


def probe_object_store(endpoint: str, local_root: str) -> dict[str, Any]:
    try:
        from blueteam_objects.store import open_store

        store = open_store(root=local_root, endpoint=endpoint)
        ok = store.ping()
        return _result("object_storage", True, ok, backend=store.backend)
    except Exception as exc:
        configured = bool(endpoint or local_root)
        return _result("object_storage", configured, False, detail=type(exc).__name__)


def probe_all(settings: Any) -> dict[str, Any]:
    local_root = getattr(settings, "object_store_root", "./data/objects")
    probes = {
        "postgres": probe_postgres(settings.database_url),
        "redis": probe_redis(settings.redis_url),
        "clickhouse": probe_clickhouse(settings.clickhouse_url),
        "opensearch": probe_opensearch(settings.opensearch_url),
        "kafka": probe_kafka(settings.kafka_bootstrap),
        "object_storage": probe_object_store(settings.s3_endpoint, local_root),
    }
    connected = [name for name, item in probes.items() if item["connected"]]
    configured = [name for name, item in probes.items() if item["configured"]]
    return {
        "probes": probes,
        "connected": connected,
        "configured": configured,
        "all_configured_connected": all(item["connected"] for item in probes.values() if item["configured"]),
    }
