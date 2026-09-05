# Security hardening checklist (Phase 27)

## Threat model (summary)
- Assets: tenant telemetry, evidence, detections, credentials, audit chain
- Actors: external attacker, malicious tenant user, compromised connector, AI provider outage
- Controls: RBAC, tenant middleware, hash-chained audit, Rego action policy, AI gateway deny-by-default

## Required scans (CI / local)
- SAST: `ruff check`
- Secrets: gitleaks pre-commit / CI
- Dependencies: `pip-audit` / npm audit (when packaging)
- Containers: Trivy on `infra/docker/Dockerfile.api`
- Tenant isolation: `pytest -m tenant_isolation`
- Auth/RBAC: `tests/security`
- Audit integrity: quality check + `verify_audit_chain`

## Formal acceptances
High/critical findings must be resolved or recorded here before production claim.
