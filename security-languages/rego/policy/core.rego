package blueteam.policy

# Python remains the orchestrator. This package returns a decision only.
# Default deny.

default result := {"decision": "DENY", "reason": "Default deny", "policy": "blueteam.policy.v1"}

result := {"decision": "DENY", "reason": "Destructive or policy-altering actions are denied", "policy": "blueteam.policy.v1"} {
    input.action.type == "delete_evidence"
}

result := {"decision": "DENY", "reason": "Destructive or policy-altering actions are denied", "policy": "blueteam.policy.v1"} {
    input.action.type == "alter_platform_policy"
}

result := {"decision": "DENY", "reason": "AI cannot request execution authority", "policy": "blueteam.policy.v1"} {
    startswith(input.action.type, "ai.")
}

result := {"decision": "DENY", "reason": "AI cannot request execution authority", "policy": "blueteam.policy.v1"} {
    startswith(input.action.type, "llm.")
}

result := {"decision": "DENY", "reason": "AI-requested actions are denied", "policy": "blueteam.policy.v1"} {
    input.requested_by_ai == true
}

result := {"decision": "ALLOW", "reason": "Read-only dry-run is permitted", "policy": "blueteam.policy.v1"} {
    input.action.dry_run == true
    input.action.read_only == true
}

result := {"decision": "ALLOW", "reason": "Tier-0 read-only collection is permitted", "policy": "blueteam.policy.v1"} {
    input.action.read_only == true
    input.action.tier == 0
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Tier-2 actions always require a human", "policy": "blueteam.policy.v1"} {
    input.action.tier >= 2
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Production impact requires approval", "policy": "blueteam.policy.v1"} {
    input.environment == "production"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Identity disablement requires approval", "policy": "blueteam.policy.v1"} {
    input.domain == "identity"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Endpoint containment requires approval", "policy": "blueteam.policy.v1"} {
    input.domain == "endpoint"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Network containment requires approval", "policy": "blueteam.policy.v1"} {
    input.domain == "network"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Cloud mutation requires approval", "policy": "blueteam.policy.v1"} {
    input.domain == "cloud"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Tenant policy override requires approval", "policy": "blueteam.policy.v1"} {
    input.domain == "tenant"
    input.action.read_only == false
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Containment requires auto_containment and confidence >= 0.95", "policy": "blueteam.policy.v1"} {
    input.action.read_only == false
    input.auto_containment != true
}

result := {"decision": "REQUIRE_APPROVAL", "reason": "Containment requires auto_containment and confidence >= 0.95", "policy": "blueteam.policy.v1"} {
    input.action.read_only == false
    input.confidence < 0.95
}
