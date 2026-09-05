"""Durable event envelope. tenant_id and schema_version are mandatory."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from blueteam_common.ids import new_id
from blueteam_common.time import utcnow
from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0.0"


class FabricEnvelope(BaseModel):
    event_id: str
    tenant_id: str
    schema_version: str = SCHEMA_VERSION
    topic: str
    produced_at: datetime
    idempotency_key: str
    payload: dict[str, Any] = Field(default_factory=dict)
    attempt: int = 0
    poison: bool = False
    partition_key: str = ""

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        if not value or not value.startswith("ten_"):
            raise ValueError("tenant_id is mandatory and must use the ten_ prefix")
        return value

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if not value:
            raise ValueError("schema_version is mandatory")
        return value


def envelope(
    topic: str,
    tenant_id: str,
    payload: dict[str, Any],
    *,
    event_id: str | None = None,
    idempotency_key: str | None = None,
) -> FabricEnvelope:
    eid = event_id or payload.get("id") or new_id("evt")
    return FabricEnvelope(
        event_id=str(eid),
        tenant_id=tenant_id,
        topic=topic,
        produced_at=utcnow(),
        idempotency_key=idempotency_key or f"{topic}:{eid}",
        payload=payload,
        partition_key=tenant_id,
    )
