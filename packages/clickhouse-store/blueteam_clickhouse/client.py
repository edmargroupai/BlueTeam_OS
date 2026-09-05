"""HTTP ClickHouse client. Empty URL means unconfigured — never invent a healthy store."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from blueteam_schemas.events import CanonicalEvent

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "schema.sql"


class ClickHouseUnavailable(RuntimeError):
    pass


class ClickHouseClient:
    backend = "clickhouse"

    def __init__(self, url: str, *, timeout: float = 8.0) -> None:
        if not url:
            raise ClickHouseUnavailable("BTOS_CLICKHOUSE_URL is empty")
        self.url = url.rstrip("/")
        self.timeout = timeout
        user, password = self._credentials(url)
        self._auth = httpx.BasicAuth(user, password)

    def _headers(self) -> dict[str, str]:
        return {}

    @staticmethod
    def _credentials(url: str) -> tuple[str, str]:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.username or "blueteam", parsed.password or "dev_only_ch"

    def ping(self) -> bool:
        try:
            response = httpx.get(f"{self.url}/ping", timeout=self.timeout)
            return response.status_code == 200 and response.text.strip() == "Ok."
        except httpx.HTTPError:
            return False

    def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        if ";" in sql.strip().rstrip(";"):
            raise ValueError("multiple statements are forbidden")
        forbidden = ("insert ", "update ", "delete ", "drop ", "alter ", "attach ", "truncate ")
        if any(token in sql.lower() for token in forbidden):
            raise ValueError("mutating SQL is forbidden on the hunt path")
        query_params: dict[str, Any] = {"query": sql.rstrip().rstrip(";") + " FORMAT JSON"}
        for key, value in (params or {}).items():
            query_params[f"param_{key}"] = value
        response = httpx.get(
            self.url,
            params=query_params,
            timeout=self.timeout,
            auth=self._auth,
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise ClickHouseUnavailable(response.text[:500])
        payload = response.json()
        return list(payload.get("data") or [])

    def command(self, sql: str) -> str:
        response = httpx.post(
            self.url, content=sql.encode("utf-8"), timeout=self.timeout, auth=self._auth, headers=self._headers()
        )
        if response.status_code >= 400:
            raise ClickHouseUnavailable(response.text[:500])
        return response.text

    def apply_schema(self) -> None:
        sql = SCHEMA_PATH.read_text(encoding="utf-8")
        for statement in [part.strip() for part in sql.split(";") if part.strip()]:
            self.command(statement)

    def insert_events(self, events: list[CanonicalEvent]) -> int:
        if not events:
            return 0
        rows = [self._row(event) for event in events]
        body = "\n".join(json.dumps(row, default=str) for row in rows)
        qs = urlencode({"query": "INSERT INTO blueteam.events FORMAT JSONEachRow"})
        response = httpx.post(
            f"{self.url}/?{qs}",
            content=body.encode("utf-8"),
            timeout=self.timeout,
            auth=self._auth,
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise ClickHouseUnavailable(response.text[:500])
        return len(rows)

    def _row(self, event: CanonicalEvent) -> dict[str, Any]:
        return {
            "event_id": event.id,
            "tenant_id": event.tenant_id,
            "timestamp": _ch_time(event.timestamp),
            "ingested_at": _ch_time(event.ingested_at),
            "source": event.source,
            "source_type": event.source_type,
            "event_type": event.event_type,
            "category": event.category,
            "host_id": event.host.id if event.host and event.host.id else (event.host.name if event.host else ""),
            "user_id": event.user.name if event.user and event.user.name else "",
            "src_ip": event.src_ip or "",
            "dst_ip": event.dst_ip or "",
            "src_port": event.src_port or 0,
            "dst_port": event.dst_port or 0,
            "protocol": event.protocol or "",
            "process_name": event.process.name if event.process else "",
            "parent_process_name": event.parent_process.name if event.parent_process else "",
            "command_line": event.process.command_line if event.process else "",
            "domain": event.domain or "",
            "url": event.url or "",
            "file_path": event.file.path if event.file else "",
            "file_hash": event.hash or (event.file.hash_sha256 if event.file else ""),
            "action": event.action or "",
            "outcome": event.outcome or "",
            "severity": event.severity,
            "confidence": event.confidence,
            "schema_version": event.schema_version,
            "attributes": json.dumps(event.attributes),
            "raw_reference": event.raw_hash or event.id,
        }


def _ch_time(value: datetime) -> str:
    return value.replace(tzinfo=None).isoformat(sep=" ", timespec="milliseconds")


def connect(url: str) -> ClickHouseClient:
    client = ClickHouseClient(url)
    if not client.ping():
        raise ClickHouseUnavailable(f"ClickHouse ping failed at {url}")
    return client
