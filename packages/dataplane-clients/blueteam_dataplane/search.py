"""OpenSearch write/query when a cluster is actually reachable."""

from __future__ import annotations

from typing import Any

import httpx


class OpenSearchStore:
    def __init__(self, url: str) -> None:
        if not url:
            raise ValueError("opensearch url empty")
        self.url = url.rstrip("/")

    def ping(self) -> bool:
        response = httpx.get(self.url, timeout=3.0)
        return response.status_code < 500

    def index_event(self, tenant_id: str, event_id: str, document: dict[str, Any]) -> str:
        index = f"btos-events-{tenant_id[-8:]}"
        response = httpx.put(
            f"{self.url}/{index}/_doc/{event_id}",
            json=document,
            timeout=6.0,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"opensearch index failed: {response.status_code}")
        return index

    def search(self, tenant_id: str, query: str, *, size: int = 10) -> list[dict[str, Any]]:
        index = f"btos-events-{tenant_id[-8:]}"
        response = httpx.post(
            f"{self.url}/{index}/_search",
            json={"size": size, "query": {"query_string": {"query": query}}},
            timeout=6.0,
        )
        if response.status_code >= 400:
            return []
        hits = response.json().get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]
