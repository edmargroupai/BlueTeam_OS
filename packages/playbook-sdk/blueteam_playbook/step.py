from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass
class PlaybookContext:
    tenant_id: str
    run_id: str
    actor_id: str
    request_id: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepResult:
    status: Literal["success", "denied", "failed", "awaiting_approval"]
    outputs: dict[str, Any] = field(default_factory=dict)
    audit_action: str = "playbook.step"
    compensation_needed: bool = False


class PlaybookStep(Protocol):
    name: str

    async def execute(self, ctx: PlaybookContext) -> StepResult: ...
