# Detection SDK

`DetectionRule.evaluate(event, context) -> list[Finding]`

Rules must not perform network calls. Window queries go through `DetectionContext`. Findings must include explanation, ATT&CK techniques, event IDs, and evidence slots. Default catalogue: `identity.password_spray`, `identity.brute_force`, `identity.privilege_grant`.
