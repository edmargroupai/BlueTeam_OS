# Go

Why: concurrent cloud/Kubernetes/SaaS collectors.

Allowed: collect, validate tenant_id, basic normalise, publish, health, retry.

Prohibited: Python detection/correlation clones.

Contract: `Normalize()` rejects missing `ten_` prefixes and sets `schema_version=1.0.0`.
