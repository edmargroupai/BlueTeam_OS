from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Decision = Literal["deterministic_only", "deny_policy", "deny_budget", "local", "frontier"]


@dataclass(frozen=True)
class AIRequest:
    tenant_id: str
    feature: str
    task_type: str
    context_refs: list[str]
    requested_capability: str
    max_cost: float
    max_tokens: int
    sensitivity: str
    structured_output_schema: dict[str, Any]


@dataclass(frozen=True)
class AIDecision:
    decision: Decision
    reason: str
    provider: str | None = None
    model: str | None = None


def route(request: AIRequest, *, ai_enabled: bool = False) -> AIDecision:
    """Default is deterministic-only. Provider outages cannot break detections."""
    if request.task_type in {"detect", "correlate", "score", "ingest", "contain"}:
        return AIDecision("deterministic_only", "Security-critical path must not call a model")
    if not ai_enabled:
        return AIDecision("deterministic_only", "AI gateway disabled — operate offline")
    if request.sensitivity in {"secret", "restricted"}:
        return AIDecision("deny_policy", "Sensitivity class is not eligible for model dispatch")
    return AIDecision("deny_policy", "No approved provider configured")
