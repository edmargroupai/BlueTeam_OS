from __future__ import annotations

from datetime import datetime
from typing import Any

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from blueteam_schemas.events import CanonicalEvent, CanonicalUser


def _first(payload: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if "." in key:
            current: Any = payload
            ok = True
            for part in key.split("."):
                if not isinstance(current, dict) or part not in current:
                    ok = False
                    break
                current = current[part]
            if ok and current not in (None, ""):
                return current
        elif key in payload and payload[key] not in (None, ""):
            return payload[key]
    return None


def normalize_generic(payload: dict[str, Any], tenant_id: str) -> CanonicalEvent:
    if payload.get("schema_version") and payload.get("id") and payload.get("tenant_id"):
        event = CanonicalEvent.model_validate(payload)
        if event.tenant_id != tenant_id:
            raise ValueError("event tenant_id does not match request tenant")
        return event

    timestamp = _first(payload, ["timestamp", "time", "@timestamp", "event_time"])
    if isinstance(timestamp, str):
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    elif isinstance(timestamp, datetime):
        parsed = timestamp
    else:
        parsed = utcnow()

    user_name = _first(payload, ["user", "username", "user.name", "account"])
    user = CanonicalUser(name=str(user_name)) if user_name else None
    return CanonicalEvent(
        id=str(_first(payload, ["id", "event_id"]) or new_id("evt")),
        tenant_id=tenant_id,
        timestamp=parsed,
        ingested_at=utcnow(),
        source=str(_first(payload, ["source", "vendor"]) or "generic-json"),
        source_type=str(_first(payload, ["source_type", "product"]) or "unknown"),
        event_type=str(_first(payload, ["event_type", "type"]) or "unknown"),
        category=str(_first(payload, ["category"]) or "unknown"),
        user=user,
        src_ip=_first(payload, ["src_ip", "source_ip", "client_ip", "source.ip"]),
        dst_ip=_first(payload, ["dst_ip", "destination_ip", "destination.ip"]),
        action=_first(payload, ["action"]),
        outcome=_first(payload, ["outcome", "result"]),
        raw_event=payload,
        attributes={k: str(v) for k, v in payload.items() if k in {"group", "role", "member"}},
    )
