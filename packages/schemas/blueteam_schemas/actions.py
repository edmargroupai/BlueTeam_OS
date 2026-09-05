"""Versioned action contract. Languages must not invent private action payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

PolicyDecision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
ActionStatus = Literal["planned", "denied", "awaiting_approval", "executed", "skipped", "failed", "verified"]


class ActionRequest(BaseModel):
    action_id: str
    action_type: str
    tenant_id: str
    target: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str
    requested_by: str
    dry_run: bool = True
    actor_roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class ActionResult(BaseModel):
    action_id: str
    action_type: str
    tenant_id: str
    policy_decision: PolicyDecision
    approval_status: str | None = None
    executor: str
    rollback_available: bool = False
    status: ActionStatus
    dry_run: bool
    outputs: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    skip_reason: str | None = None
    error: str | None = None
    completed_at: datetime | None = None
