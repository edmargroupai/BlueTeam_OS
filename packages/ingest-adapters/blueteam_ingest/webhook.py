"""Generic webhook adapter. Payload must still become a CanonicalEvent."""

from __future__ import annotations

from typing import Any

def normalize_webhook(payload: dict[str, Any], tenant_id: str, *, source: str = "webhook") -> list[dict[str, Any]]:
    if "events" in payload and isinstance(payload["events"], list):
        events = []
        for item in payload["events"]:
            if not isinstance(item, dict):
                raise ValueError("webhook events must be objects")
            events.append(_stamp(item, source, payload.get("adapter")))
        return events
    if payload.get("schema_version") or payload.get("event_type") or payload.get("type"):
        return [_stamp(payload, source, payload.get("adapter"))]
    raise ValueError("webhook payload must include events[] or a single event object")


def _stamp(item: dict[str, Any], source: str, adapter: Any) -> dict[str, Any]:
    stamped = dict(item)
    stamped.setdefault("source", source)
    stamped.setdefault("source_type", source)
    if adapter:
        stamped.setdefault("adapter", adapter)
    return stamped
