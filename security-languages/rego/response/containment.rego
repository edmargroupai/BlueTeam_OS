package blueteam.response

# Source of truth for response authority. The Python evaluator implements this subset.
# AI cannot override these decisions.

default decision := "DENY"

decision := "ALLOW" {
    input.action.read_only == true
    input.action.tier == 0
}

decision := "ALLOW" {
    input.action.dry_run == true
    input.action.read_only == true
}

decision := "REQUIRE_APPROVAL" {
    input.action.tier >= 2
}

decision := "REQUIRE_APPROVAL" {
    input.environment == "production"
    input.action.read_only == false
}

decision := "DENY" {
    input.action.type == "delete_evidence"
}

decision := "DENY" {
    startswith(input.action.type, "ai.")
}
