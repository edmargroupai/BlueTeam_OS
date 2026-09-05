# Multi-tenancy

- Header `X-Tenant-ID` selects the active tenant
- Membership or platform-admin break-glass is required
- Event IDs colliding across tenants are dead-lettered
- List endpoints always filter by bound `tenant_id`
- Isolation tests live in `tests/tenant-isolation`
