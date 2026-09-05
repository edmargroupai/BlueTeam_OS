"""Policy evaluation. Production prefers OPA; subset remains a labeled fallback."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from blueteam_rego.opa import evaluate_opa, opa_available

Decision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    policy: str = "blueteam.response.v1"
    engine: str = "blueteam_rego.subset"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "policy": self.policy,
            "engine": self.engine,
        }


def _subset_evaluate(input_doc: dict[str, Any]) -> PolicyResult:
    action = input_doc.get("action") or {}
    action_type = str(action.get("type", ""))
    tier = int(action.get("tier", 2))
    read_only = bool(action.get("read_only", False))
    dry_run = bool(action.get("dry_run", True))
    environment = str(input_doc.get("environment", "unknown"))
    confidence = float(input_doc.get("confidence", 0))
    auto = bool(input_doc.get("auto_containment", False))
    requested_by_ai = bool(input_doc.get("requested_by_ai", False))
    domain = str(input_doc.get("domain", ""))

    if action_type in {"delete_evidence", "alter_platform_policy"}:
        return PolicyResult("DENY", "Destructive or policy-altering actions are denied")
    if action_type.startswith("ai.") or action_type.startswith("llm.") or requested_by_ai:
        return PolicyResult("DENY", "AI cannot request execution authority")
    if dry_run and read_only:
        return PolicyResult("ALLOW", "Read-only dry-run is permitted")
    if tier >= 2:
        return PolicyResult("REQUIRE_APPROVAL", "Tier-2 actions always require a human")
    if not read_only and environment.lower() == "production":
        return PolicyResult("REQUIRE_APPROVAL", "Production impact requires approval even at high confidence")
    if domain in {"identity", "endpoint", "network", "cloud", "tenant"} and not read_only:
        return PolicyResult("REQUIRE_APPROVAL", f"{domain} mutation requires approval")
    if not read_only and (not auto or confidence < 0.95):
        return PolicyResult("REQUIRE_APPROVAL", "Containment requires auto_containment and confidence >= 0.95")
    if read_only and tier == 0:
        return PolicyResult("ALLOW", "Tier-0 read-only collection is permitted")
    return PolicyResult("DENY", "Default deny")


def evaluate(input_doc: dict[str, Any], *, prefer_opa: bool = True) -> PolicyResult:
    if prefer_opa and opa_available():
        try:
            raw = evaluate_opa(input_doc)
            decision = raw.get("decision", "DENY")
            if decision not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
                decision = "DENY"
            return PolicyResult(
                decision=decision,  # type: ignore[arg-type]
                reason=str(raw.get("reason", "OPA decision")),
                policy=str(raw.get("policy", "blueteam.policy.v1")),
                engine="opa",
            )
        except Exception as exc:
            fallback = _subset_evaluate(input_doc)
            return PolicyResult(
                fallback.decision,
                f"{fallback.reason} (OPA failed: {exc})",
                fallback.policy,
                engine="blueteam_rego.subset",
            )
    return _subset_evaluate(input_doc)


def active_engine() -> str:
    return "opa" if opa_available() else "blueteam_rego.subset"
