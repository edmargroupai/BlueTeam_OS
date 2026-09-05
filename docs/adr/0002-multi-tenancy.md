# ADR 0002 — Tenant isolation at the application boundary

Status: accepted

Every tenant-owned row has `tenant_id`. Repositories and APIs bind tenant from authenticated context (`X-Tenant-ID` + membership), never from an untrusted body field for authorization. Cross-tenant tests are mandatory in CI.
