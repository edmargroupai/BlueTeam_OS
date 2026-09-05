# Security model

Roles are defined in `app/domain/permissions.py`. Least privilege is enforced per request. Audit covers login, ingest, and Blue Range execution. Response actions are classified T0/T1/T2; T2 always requires approval. AI is disabled by default.
