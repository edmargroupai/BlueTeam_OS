from __future__ import annotations

from enum import IntEnum
from typing import Literal

PolicyDecision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


class ActionTier(IntEnum):
    T0 = 0
    T1 = 1
    T2 = 2


TIER2_ACTIONS = {
    "isolate_host",
    "isolate.host",
    "disable_user",
    "revoke_privileged_access",
    "modify_firewall",
    "push_production_detection",
    "alter_platform_policy",
    "delete_evidence",
}

TIER1_ACTIONS = {
    "contain_session",
    "disable_stale_token",
    "quarantine_mailbox_rule",
}


def evaluate_action(action_type: str, tier: ActionTier | None = None) -> PolicyDecision:
    if action_type in TIER2_ACTIONS or tier == ActionTier.T2:
        return "REQUIRE_APPROVAL"
    if action_type in TIER1_ACTIONS or tier == ActionTier.T1:
        return "REQUIRE_APPROVAL"
    return "ALLOW"
