from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuditRecord(BaseModel):
    id: str
    tenant_id: str | None
    actor_type: Literal["user", "api_key", "system", "playbook", "ai_gateway"]
    actor_id: str
    request_id: str
    action: str
    target_type: str
    target_id: str | None = None
    reason: str | None = None
    policy_decision: str | None = None
    approval_status: str | None = None
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    result: Literal["success", "denied", "error"]
    timestamp: datetime
    previous_hash: str
    record_hash: str
