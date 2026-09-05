"""AI Gateway — sole model dispatch path. Features must not import provider SDKs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

Decision = Literal["deterministic_only", "deny_policy", "deny_budget", "local", "frontier", "cached"]

SECRET_PATTERNS = (
    re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
)


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
    prompt: str = ""


@dataclass(frozen=True)
class AIDecision:
    decision: Decision
    reason: str
    provider: str | None = None
    model: str | None = None
    redacted_prompt: str | None = None
    cost_estimate: float = 0.0
    cached: bool = False


@dataclass
class GatewayLedger:
    calls: int = 0
    denials: int = 0
    deterministic: int = 0
    spend: float = 0.0
    cache_hits: int = 0
    audit: list[dict[str, Any]] = field(default_factory=list)


_LEDGER = GatewayLedger()
_CACHE: dict[str, AIDecision] = {}
_BUDGET = 5.0


def redact(text: str) -> str:
    cleaned = text
    for pattern in SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned


def validate_structured(payload: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    required = schema.get("required") or []
    missing = [key for key in required if key not in payload]
    return [f"missing:{key}" for key in missing]


def route(request: AIRequest, *, ai_enabled: bool = False, budget: float | None = None) -> AIDecision:
    """Default is deterministic-only. Provider outages cannot break detections."""
    global _BUDGET
    if budget is not None:
        _BUDGET = budget
    _LEDGER.calls += 1
    redacted = redact(request.prompt)
    cache_key = hashlib.sha256(
        f"{request.tenant_id}:{request.feature}:{request.task_type}:{redacted}".encode()
    ).hexdigest()
    if cache_key in _CACHE:
        _LEDGER.cache_hits += 1
        cached = _CACHE[cache_key]
        decision = AIDecision(
            cached.decision,
            cached.reason,
            provider=cached.provider,
            model=cached.model,
            redacted_prompt=redacted,
            cost_estimate=0.0,
            cached=True,
        )
        _audit(request, decision)
        return decision

    if request.task_type in {"detect", "correlate", "score", "ingest", "contain"}:
        decision = AIDecision("deterministic_only", "Security-critical path must not call a model", redacted_prompt=redacted)
        _LEDGER.deterministic += 1
        _CACHE[cache_key] = decision
        _audit(request, decision)
        return decision
    if not ai_enabled:
        decision = AIDecision("deterministic_only", "AI gateway disabled — operate offline", redacted_prompt=redacted)
        _LEDGER.deterministic += 1
        _CACHE[cache_key] = decision
        _audit(request, decision)
        return decision
    if request.sensitivity in {"secret", "restricted"}:
        decision = AIDecision("deny_policy", "Sensitivity class is not eligible for model dispatch", redacted_prompt=redacted)
        _LEDGER.denials += 1
        _audit(request, decision)
        return decision
    if request.max_cost > _BUDGET or _LEDGER.spend + request.max_cost > _BUDGET:
        decision = AIDecision("deny_budget", "Token/cost budget exceeded", redacted_prompt=redacted)
        _LEDGER.denials += 1
        _audit(request, decision)
        return decision
    decision = AIDecision("deny_policy", "No approved provider configured", redacted_prompt=redacted)
    _LEDGER.denials += 1
    _audit(request, decision)
    return decision


def ledger() -> dict[str, Any]:
    return {
        "calls": _LEDGER.calls,
        "denials": _LEDGER.denials,
        "deterministic": _LEDGER.deterministic,
        "spend": _LEDGER.spend,
        "cache_hits": _LEDGER.cache_hits,
        "budget": _BUDGET,
        "audit_tail": _LEDGER.audit[-20:],
    }


def _audit(request: AIRequest, decision: AIDecision) -> None:
    _LEDGER.audit.append(
        {
            "tenant_id": request.tenant_id,
            "feature": request.feature,
            "task_type": request.task_type,
            "decision": decision.decision,
            "reason": decision.reason,
            "context_refs": list(request.context_refs),
            "schema": json.dumps(request.structured_output_schema, sort_keys=True)[:200],
        }
    )


# Back-compat for tests importing from services.ai-gateway path via sys.path hacks.
__all__ = ["AIDecision", "AIRequest", "ledger", "redact", "route", "validate_structured"]
